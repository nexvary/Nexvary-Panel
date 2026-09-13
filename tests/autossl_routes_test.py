from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-autossl-routes-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_OPS_SOCK"] = str(pathlib.Path(tmp) / "missing-ops.sock")

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_autossl as routes_autossl

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "autossl-csrf"

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        pid = int(core["id"])
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("sslclient", "operator", "55" * 16, "66" * 32, now),
        )
        conn.execute(
            "INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)",
            ("sslclient", pid, now),
        )
        conn.execute(
            "INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",
            ("ssl.example.test", "php", "", None, "sslclient", now),
        )
        conn.execute(
            "INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",
            ("admin.example.test", "php", "", None, "admin", now),
        )

    with client.session_transaction() as session:
        session.update(auth=True, user="sslclient", role="operator", csrf=csrf)

    response = client.get("/api/autossl?domain=ssl.example.test")
    assert response.status_code == 200, response.data
    body = response.get_json()
    policy = body["policy"]
    assert body["names"] == ["ssl.example.test"]
    assert policy["configured"] is False
    assert policy["feature_enabled"] is True

    response = client.put(
        "/api/autossl/ssl.example.test",
        json={"auto_renew": True, "contact_email": "ops@example.test", "renew_before_days": 21},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 428, response.data

    with client.session_transaction() as session:
        session["step_up_user"] = "sslclient"
        session["step_up_until"] = now + 300

    response = client.put(
        "/api/autossl/ssl.example.test",
        json={"auto_renew": True, "contact_email": "ops@example.test", "renew_before_days": 21},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200, response.data
    policy = response.get_json()["policy"]
    assert policy["auto_renew"] is True and policy["renew_before_days"] == 21
    assert policy["last_status"] == "pending"

    with db() as conn:
        row = conn.execute("SELECT * FROM ssl_policies WHERE domain='ssl.example.test'").fetchone()
        assert row and row["owner"] == "sslclient" and int(row["auto_renew"]) == 1
        audit_text = " ".join(str(r[0]) for r in conn.execute("SELECT detail FROM audit").fetchall())
        assert "ops@example.test" not in audit_text
        conn.execute(
            "INSERT INTO domain_aliases(domain,alias,owner,created_at,updated_at) VALUES(?,?,?,?,?)",
            ("ssl.example.test", "www2.ssl.example.test", "sslclient", now, now),
        )

    seen = []
    def fake_ops(payload, timeout=35):
        seen.append(dict(payload))
        return {
            "ok": True,
            "ready": True,
            "domain": payload["domain"],
            "domains": payload["domains"],
            "checks": [{"domain": name, "ready": True, "dns": ["203.0.113.1"], "http_status": 200, "reason": ""} for name in payload["domains"]],
        }
    routes_autossl.ops_call = fake_ops
    response = client.get("/api/autossl/preflight?domain=ssl.example.test")
    assert response.status_code == 200, response.data
    preflight = response.get_json()
    assert preflight["names"] == ["ssl.example.test", "www2.ssl.example.test"]
    assert preflight["preflight"]["ready"] is True
    assert seen and seen[-1]["action"] == "ssl-preflight"
    assert seen[-1]["domains"] == preflight["names"]

    response = client.put(
        "/api/autossl/ssl.example.test",
        json={"auto_renew": True, "contact_email": "", "renew_before_days": 21},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 400, response.data

    response = client.put(
        "/api/autossl/admin.example.test",
        json={"auto_renew": False, "contact_email": "", "renew_before_days": 30},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 403, response.data

    with db() as conn:
        conn.execute(
            "INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,0,?) "
            "ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=0,updated_at=excluded.updated_at",
            (pid, "security.ssl_tls", now),
        )
    response = client.get("/api/autossl?domain=ssl.example.test")
    assert response.status_code == 200, response.data
    assert response.get_json()["policy"]["feature_enabled"] is False
    response = client.get("/api/autossl/preflight?domain=ssl.example.test")
    assert response.status_code == 403, response.data
    response = client.put(
        "/api/autossl/ssl.example.test",
        json={"auto_renew": False, "contact_email": "", "renew_before_days": 30},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 403, response.data

print("Nexvary Panel AutoSSL routes gate: PASS")
