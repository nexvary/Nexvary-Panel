from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-domains-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_domains as routes_domains

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "domains-csrf"
    web_calls: list[dict] = []
    ops_calls: list[dict] = []

    def fake_webtools(payload, timeout=0):
        web_calls.append(dict(payload))
        return {"ok": True, "meta": {"aliases": len(payload.get("aliases", []))}}

    def fake_ops(payload, timeout=0):
        ops_calls.append(dict(payload))
        action = payload.get("action")
        if action == "ssl-status":
            return {"ok": True, "installed": False, "domain": payload.get("domain")}
        if action in {"ssl-issue", "ssl-renew"}:
            return {"ok": True, "installed": True, "detail": "provider-ok"}
        return {"ok": False, "error": "unexpected-action"}

    routes_domains.webtools_call = fake_webtools
    routes_domains.ops_call = fake_ops

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        conn.execute("UPDATE hosting_packages SET max_subdomains=1 WHERE id=?", (int(core["id"]),))
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
                     ("client01", "operator", "11" * 16, "22" * 32, now))
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)",
                     ("client01", int(core["id"]), now))
        conn.execute("INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",
                     ("example.com", "static", "", None, "client01", now))
        conn.execute("INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",
                     ("other.example.net", "static", "", None, "other", now))

    with client.session_transaction() as sess:
        sess.update(auth=True, user="client01", role="operator", csrf=csrf)

    r = client.get("/api/domains/aliases?domain=example.com")
    assert r.status_code == 200, r.data
    assert r.get_json()["quota"]["limit"] == 1

    # Writes require Step-Up.
    r = client.post("/api/domains/aliases", json={"domain":"example.com","alias":"app.example.com"}, headers={"X-CSRF-Token":csrf})
    assert r.status_code == 428, r.data

    with client.session_transaction() as sess:
        sess["step_up_user"] = "client01"
        sess["step_up_until"] = now + 300

    r = client.post("/api/domains/aliases", json={"domain":"example.com","alias":"app.example.com"}, headers={"X-CSRF-Token":csrf})
    assert r.status_code == 201, r.data
    assert web_calls[-1]["action"] == "domain-alias-sync"
    assert web_calls[-1]["aliases"] == ["app.example.com"]

    # Unified lifecycle exposes DNS suggestions and SSL posture without provider secrets.
    r = client.get("/api/domains/lifecycle?domain=example.com")
    assert r.status_code == 200, r.data
    lifecycle = r.get_json()
    assert lifecycle["aliases"][0]["alias"] == "app.example.com"
    assert lifecycle["dns_suggestions"] == [{"record_name":"app.example.com","record_type":"CNAME","record_value":"example.com","ttl":300}]
    assert lifecycle["dns_binding"] is None
    assert lifecycle["ssl"]["installed"] is False
    assert lifecycle["ssl_policy"]["auto_renew"] == 0
    assert ops_calls[-1] == {"action":"ssl-status","domain":"example.com"}

    # Persistent AutoSSL policy is Step-Up protected and bounded.
    r = client.put("/api/domains/ssl-policy", json={"domain":"example.com","contact_email":"ops@example.com","auto_renew":True,"renew_before_days":21}, headers={"X-CSRF-Token":csrf})
    assert r.status_code == 200, r.data
    with db() as conn:
        policy = conn.execute("SELECT contact_email,auto_renew,renew_before_days FROM ssl_policies WHERE domain='example.com'").fetchone()
        assert policy["contact_email"] == "ops@example.com" and int(policy["auto_renew"]) == 1 and int(policy["renew_before_days"]) == 21

    # Manual issue/renew are fixed provider actions; no arbitrary command surface exists.
    r = client.post("/api/domains/ssl/issue", json={"domain":"example.com","contact_email":"ops@example.com"}, headers={"X-CSRF-Token":csrf})
    assert r.status_code == 200, r.data
    assert ops_calls[-1] == {"action":"ssl-issue","domain":"example.com","email":"ops@example.com"}
    r = client.post("/api/domains/ssl/renew", json={"domain":"example.com"}, headers={"X-CSRF-Token":csrf})
    assert r.status_code == 200, r.data
    assert ops_calls[-1] == {"action":"ssl-renew","domain":"example.com"}

    # Package subdomain/alias quota is enforced before provider execution.
    before = len(web_calls)
    r = client.post("/api/domains/aliases", json={"domain":"example.com","alias":"shop.example.com"}, headers={"X-CSRF-Token":csrf})
    assert r.status_code == 409, r.data
    assert len(web_calls) == before

    # A user cannot attach aliases to another owner's site.
    r = client.get("/api/domains/aliases?domain=other.example.net")
    assert r.status_code == 403, r.data

    # Existing managed domains cannot be reused as aliases.
    with db() as conn:
        conn.execute("UPDATE hosting_packages SET max_subdomains=5 WHERE id=?", (int(core["id"]),))
    r = client.post("/api/domains/aliases", json={"domain":"example.com","alias":"other.example.net"}, headers={"X-CSRF-Token":csrf})
    assert r.status_code == 409, r.data

    # Disabling SSL in the package blocks manual SSL actions before the provider.
    with db() as conn:
        conn.execute("INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,0,?) ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=0,updated_at=excluded.updated_at",
                     (int(core["id"]), "security.ssl_tls", now))
    before_ops = len(ops_calls)
    r = client.post("/api/domains/ssl/renew", json={"domain":"example.com"}, headers={"X-CSRF-Token":csrf})
    assert r.status_code == 403, r.data
    assert len(ops_calls) == before_ops

    with db() as conn:
        row = conn.execute("SELECT id FROM domain_aliases WHERE alias='app.example.com'").fetchone()
        alias_id = int(row["id"])
    r = client.delete(f"/api/domains/aliases/{alias_id}", headers={"X-CSRF-Token":csrf})
    assert r.status_code == 200, r.data
    assert web_calls[-1]["aliases"] == []

print("Nexvary Panel Domain Lifecycle, AutoSSL policy, quota and ownership gate: PASS")
