from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-wordpress-lifecycle-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_WORDPRESS_SOCK"] = str(pathlib.Path(tmp) / "missing-wordpress.sock")

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_wordpress_lifecycle as routes

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "wordpress-csrf"
    calls: list[dict] = []

    def fake_wordpress(payload, timeout=45):
        calls.append(dict(payload))
        action = payload.get("action")
        if action == "inventory":
            return {
                "ok": True,
                "domain": payload["domain"],
                "version": "6.8.2",
                "maintenance": False,
                "config_present": True,
                "plugin_count": 1,
                "theme_count": 1,
                "plugins": [{"slug": "hello-tool", "version": "2.4.1"}],
                "themes": [{"slug": "royal-theme", "version": "1.7.0"}],
            }
        if action == "integrity":
            return {"ok": True, "domain": payload["domain"], "version": "6.8.2", "checked": 1900, "missing": [], "mismatched": [], "integrity_ok": True, "source": "api.wordpress.org/core/checksums"}
        if action == "maintenance":
            return {"ok": True, "domain": payload["domain"], "maintenance": bool(payload["enabled"])}
        return {"ok": False, "error": "unexpected-test-action"}

    routes.wordpress_call = fake_wordpress

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        pid = int(core["id"])
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)", ("wpclient", "operator", "aa" * 16, "bb" * 32, now))
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)", ("wpclient", pid, now))
        conn.execute("INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)", ("wp.example.test", "php", "", None, "wpclient", now))
        conn.execute("INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)", ("adminwp.example.test", "php", "", None, "admin", now))
        conn.execute("INSERT INTO wordpress_instances(domain,db_name,db_user,status,version,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", ("wp.example.test", "wpdb", "wpuser", "prepared", "6.8.1", "wpclient", now, now))

    with client.session_transaction() as session:
        session.update(auth=True, user="wpclient", role="operator", csrf=csrf)

    response = client.get("/api/wordpress/lifecycle?domain=wp.example.test")
    assert response.status_code == 200, response.data
    body = response.get_json()
    assert body["version"] == "6.8.2" and body["plugin_count"] == 1 and body["theme_count"] == 1
    with db() as conn:
        saved = conn.execute("SELECT status,version FROM wordpress_instances WHERE domain='wp.example.test'").fetchone()
        assert saved["status"] == "active" and saved["version"] == "6.8.2"

    response = client.post("/api/wordpress/integrity", json={"domain": "wp.example.test"}, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200, response.data
    assert response.get_json()["integrity_ok"] is True

    response = client.put("/api/wordpress/maintenance", json={"domain": "wp.example.test", "enabled": True}, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 428, response.data
    with client.session_transaction() as session:
        session["step_up_user"] = "wpclient"
        session["step_up_until"] = now + 300
    response = client.put("/api/wordpress/maintenance", json={"domain": "wp.example.test", "enabled": True}, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200, response.data
    assert calls[-1] == {"action": "maintenance", "domain": "wp.example.test", "enabled": True}
    with db() as conn:
        assert conn.execute("SELECT status FROM wordpress_instances WHERE domain='wp.example.test'").fetchone()["status"] == "maintenance"

    response = client.get("/api/wordpress/lifecycle?domain=adminwp.example.test")
    assert response.status_code == 403, response.data

    # Disabling WordPress for the package must stop both read and write lifecycle operations before provider calls.
    before = len(calls)
    with db() as conn:
        conn.execute(
            "INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,0,?) "
            "ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=0,updated_at=excluded.updated_at",
            (pid, "software.wordpress", now),
        )
    response = client.get("/api/wordpress/lifecycle?domain=wp.example.test")
    assert response.status_code == 403, response.data
    response = client.post("/api/wordpress/integrity", json={"domain": "wp.example.test"}, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 403, response.data
    assert len(calls) == before

print("Nexvary Panel WordPress lifecycle route gate: PASS")
