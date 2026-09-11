from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-wp-updates-routes-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_WORDPRESS_SOCK"] = str(pathlib.Path(tmp) / "missing-wordpress.sock")

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_wordpress_updates as routes

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "wp-updates-csrf"

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        pid = int(core["id"])
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("wpclient", "operator", "aa" * 16, "bb" * 32, now),
        )
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("otherclient", "operator", "cc" * 16, "dd" * 32, now),
        )
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)", ("wpclient", pid, now))
        conn.execute(
            "INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",
            ("wp.example.test", "php", "", None, "wpclient", now),
        )
        conn.execute(
            "INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",
            ("other.example.test", "php", "", None, "otherclient", now),
        )

    calls: list[dict] = []
    def fake_call(payload: dict, timeout: int = 0):
        calls.append(dict(payload))
        action = payload.get("action")
        if action == "component-check":
            return {"ok": True, "domain": payload["domain"], "kind": payload["kind"], "slug": payload["slug"], "installed_version": "1.0.0", "latest_version": "2.0.0", "update_available": True, "source": "downloads.wordpress.org"}
        if action == "component-update":
            return {"ok": True, "domain": payload["domain"], "kind": payload["kind"], "slug": payload["slug"], "installed_version": "1.0.0", "latest_version": "2.0.0", "updated": True, "snapshot_id": "1750000000-deadbeef"}
        if action == "component-rollback":
            return {"ok": True, "domain": payload["domain"], "kind": "plugin", "slug": "hello-tool", "snapshot_id": payload["snapshot_id"], "restored_version": "1.0.0"}
        return {"ok": False, "error": "unexpected-action"}
    routes.wordpress_call = fake_call

    with client.session_transaction() as session:
        session.update(auth=True, user="wpclient", role="operator", csrf=csrf)

    response = client.get("/api/wordpress/components/check?domain=wp.example.test&kind=plugin&slug=hello-tool")
    assert response.status_code == 200, response.data
    body = response.get_json()
    assert body["update_available"] is True and body["source"] == "downloads.wordpress.org"
    assert calls[-1]["action"] == "component-check"

    response = client.post(
        "/api/wordpress/components/update",
        json={"domain": "wp.example.test", "kind": "plugin", "slug": "hello-tool"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 428, response.data

    with client.session_transaction() as session:
        session["step_up_user"] = "wpclient"
        session["step_up_until"] = now + 300

    response = client.post(
        "/api/wordpress/components/update",
        json={"domain": "wp.example.test", "kind": "plugin", "slug": "hello-tool"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200, response.data
    assert response.get_json()["snapshot_id"] == "1750000000-deadbeef"
    assert calls[-1]["action"] == "component-update"

    response = client.post(
        "/api/wordpress/components/rollback",
        json={"domain": "wp.example.test", "snapshot_id": "1750000000-deadbeef"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200, response.data
    assert calls[-1]["action"] == "component-rollback"

    response = client.get("/api/wordpress/components/check?domain=other.example.test&kind=plugin&slug=hello-tool")
    assert response.status_code == 403, response.data
    response = client.get("/api/wordpress/components/check?domain=wp.example.test&kind=plugin&slug=../../bad")
    assert response.status_code == 400, response.data
    response = client.post(
        "/api/wordpress/components/rollback",
        json={"domain": "wp.example.test", "snapshot_id": "../../etc"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 400, response.data

    with db() as conn:
        audit = " ".join(str(row[0]) for row in conn.execute("SELECT detail FROM audit").fetchall())
        assert "downloads.wordpress.org" not in audit
        conn.execute(
            """INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at)
               VALUES(?,?,0,?) ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=0,updated_at=excluded.updated_at""",
            (pid, "software.wordpress", now),
        )

    response = client.get("/api/wordpress/components/check?domain=wp.example.test&kind=plugin&slug=hello-tool")
    assert response.status_code == 403, response.data

print("Nexvary Panel WordPress component routes gate: PASS")
