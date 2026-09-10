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
    calls: list[dict] = []

    def fake_webtools(payload, timeout=0):
        calls.append(dict(payload))
        return {"ok": True, "meta": {"aliases": len(payload.get("aliases", []))}}

    routes_domains.webtools_call = fake_webtools

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
    assert calls[-1]["action"] == "domain-alias-sync"
    assert calls[-1]["aliases"] == ["app.example.com"]

    # Package subdomain/alias quota is enforced before provider execution.
    before = len(calls)
    r = client.post("/api/domains/aliases", json={"domain":"example.com","alias":"shop.example.com"}, headers={"X-CSRF-Token":csrf})
    assert r.status_code == 409, r.data
    assert len(calls) == before

    # A user cannot attach aliases to another owner's site.
    r = client.get("/api/domains/aliases?domain=other.example.net")
    assert r.status_code == 403, r.data

    # Existing managed domains cannot be reused as aliases.
    with db() as conn:
        conn.execute("UPDATE hosting_packages SET max_subdomains=5 WHERE id=?", (int(core["id"]),))
    r = client.post("/api/domains/aliases", json={"domain":"example.com","alias":"other.example.net"}, headers={"X-CSRF-Token":csrf})
    assert r.status_code == 409, r.data

    with db() as conn:
        row = conn.execute("SELECT id FROM domain_aliases WHERE alias='app.example.com'").fetchone()
        alias_id = int(row["id"])
    r = client.delete(f"/api/domains/aliases/{alias_id}", headers={"X-CSRF-Token":csrf})
    assert r.status_code == 200, r.data
    assert calls[-1]["aliases"] == []

print("Nexvary Panel Domain Lifecycle policy, quota and ownership gate: PASS")
