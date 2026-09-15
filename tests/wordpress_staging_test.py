from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-wordpress-staging-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_WORDPRESS_SOCK"] = str(pathlib.Path(tmp) / "missing-wordpress.sock")

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_wordpress_staging as routes

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "wp-staging-csrf"
    snapshot = "1760000000-cafebabe"
    calls: list[dict] = []

    def fake_wordpress(payload, timeout=45):
        calls.append(dict(payload))
        action = payload.get("action")
        if action == "staging-clone":
            return {
                "ok": True,
                "source_domain": payload["source_domain"],
                "target_domain": payload["target_domain"],
                "source_db": "wpdb",
                "target_db": payload["target_db"],
                "db_user": "wpuser",
                "version": "6.8.2",
                "rewrite_scope": "home-siteurl",
            }
        if action == "staging-preview":
            return {
                "ok": True,
                "source_domain": payload["source_domain"],
                "target_domain": payload["target_domain"],
                "source_version": "6.8.2",
                "target_version": "6.8.2",
                "source_db": "wpdb",
                "target_db": "wpstage",
                "source_files": 4200,
                "target_files": 4210,
                "safety": "snapshot-before-publish",
            }
        if action == "staging-publish":
            return {
                "ok": True,
                "live_domain": payload["source_domain"],
                "staging_domain": payload["target_domain"],
                "snapshot_id": snapshot,
                "version": "6.8.2",
                "safety": "rollback-ready",
            }
        if action == "staging-publish-rollback":
            return {
                "ok": True,
                "live_domain": payload["source_domain"],
                "snapshot_id": payload["snapshot_id"],
                "version": "6.8.1",
                "rolled_back": True,
            }
        return {"ok": False, "error": "unexpected-test-action"}

    routes.wordpress_call = fake_wordpress

    with db() as conn:
        package = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        pid = int(package["id"])
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)", ("wpclient", "operator", "aa" * 16, "bb" * 32, now))
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)", ("wpclient", pid, now))
        for domain, owner in [
            ("live.example.test", "wpclient"),
            ("stage.example.test", "wpclient"),
            ("otherstage.example.test", "wpclient"),
            ("adminstage.example.test", "admin"),
        ]:
            conn.execute("INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)", (domain, "php", "", None, owner, now))
        conn.execute("INSERT INTO databases(db_name,db_user,engine,site_domain,owner,created_at) VALUES(?,?,?,?,?,?)", ("wpdb", "wpuser", "mariadb", "live.example.test", "wpclient", now))
        conn.execute("INSERT INTO wordpress_instances(domain,db_name,db_user,status,version,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", ("live.example.test", "wpdb", "wpuser", "active", "6.8.2", "wpclient", now, now))

    with client.session_transaction() as sess:
        sess.update(auth=True, user="wpclient", role="operator", csrf=csrf)

    state = client.get("/api/wordpress/staging?domain=live.example.test")
    assert state.status_code == 200, state.data
    body = state.get_json()
    assert body["mapping"] is None
    targets = {row["domain"] for row in body["targets"]}
    assert "stage.example.test" in targets and "otherstage.example.test" in targets
    assert "adminstage.example.test" not in targets

    # Cross-account target is rejected before any provider call.
    before = len(calls)
    denied = client.post("/api/wordpress/staging/clone", json={"source_domain":"live.example.test","target_domain":"adminstage.example.test","target_db":"wpstage"}, headers={"X-CSRF-Token":csrf})
    assert denied.status_code == 428  # Step-Up is checked before route scope.
    assert len(calls) == before

    with client.session_transaction() as sess:
        sess["step_up_user"] = "wpclient"
        sess["step_up_until"] = now + 600

    denied = client.post("/api/wordpress/staging/clone", json={"source_domain":"live.example.test","target_domain":"adminstage.example.test","target_db":"wpstage"}, headers={"X-CSRF-Token":csrf})
    assert denied.status_code == 403, denied.data
    assert len(calls) == before

    # Database quota is enforced before clone.
    with db() as conn:
        conn.execute("UPDATE hosting_packages SET max_databases=1 WHERE id=?", (pid,))
    quota = client.post("/api/wordpress/staging/clone", json={"source_domain":"live.example.test","target_domain":"stage.example.test","target_db":"wpstage"}, headers={"X-CSRF-Token":csrf})
    assert quota.status_code == 409, quota.data
    assert len(calls) == before
    with db() as conn:
        conn.execute("UPDATE hosting_packages SET max_databases=10 WHERE id=?", (pid,))

    created = client.post("/api/wordpress/staging/clone", json={"source_domain":"live.example.test","target_domain":"stage.example.test","target_db":"wpstage"}, headers={"X-CSRF-Token":csrf})
    assert created.status_code == 200, created.data
    assert created.get_json()["refreshed"] is False
    assert calls[-1]["action"] == "staging-clone" and calls[-1]["replace"] is False
    with db() as conn:
        assert conn.execute("SELECT owner FROM databases WHERE db_name='wpstage'").fetchone()["owner"] == "wpclient"
        assert conn.execute("SELECT status FROM wordpress_instances WHERE domain='stage.example.test'").fetchone()["status"] == "staging"
        mapping = conn.execute("SELECT * FROM wordpress_staging WHERE source_domain='live.example.test'").fetchone()
        assert mapping and mapping["target_domain"] == "stage.example.test" and mapping["target_db"] == "wpstage"

    state = client.get("/api/wordpress/staging?domain=live.example.test").get_json()
    assert state["mapping"]["target_domain"] == "stage.example.test"

    refreshed = client.post("/api/wordpress/staging/clone", json={"source_domain":"live.example.test","target_domain":"stage.example.test","target_db":"wpstage"}, headers={"X-CSRF-Token":csrf})
    assert refreshed.status_code == 200 and refreshed.get_json()["refreshed"] is True
    assert calls[-1]["replace"] is True

    changed_target = client.post("/api/wordpress/staging/clone", json={"source_domain":"live.example.test","target_domain":"otherstage.example.test","target_db":"wpstage2"}, headers={"X-CSRF-Token":csrf})
    assert changed_target.status_code == 409

    preview = client.post("/api/wordpress/staging/publish-preview", json={"source_domain":"live.example.test"}, headers={"X-CSRF-Token":csrf})
    assert preview.status_code == 200 and preview.get_json()["safety"] == "snapshot-before-publish"
    assert calls[-1] == {"action":"staging-preview","source_domain":"live.example.test","target_domain":"stage.example.test"}

    # Publish is Step-Up protected even after mapping exists.
    with client.session_transaction() as sess:
        sess.pop("step_up_user", None); sess.pop("step_up_until", None)
    no_step = client.post("/api/wordpress/staging/publish", json={"source_domain":"live.example.test"}, headers={"X-CSRF-Token":csrf})
    assert no_step.status_code == 428
    with client.session_transaction() as sess:
        sess["step_up_user"] = "wpclient"; sess["step_up_until"] = now + 600

    published = client.post("/api/wordpress/staging/publish", json={"source_domain":"live.example.test"}, headers={"X-CSRF-Token":csrf})
    assert published.status_code == 200, published.data
    assert published.get_json()["snapshot_id"] == snapshot
    with db() as conn:
        row = conn.execute("SELECT status,last_publish_snapshot FROM wordpress_staging WHERE source_domain='live.example.test'").fetchone()
        assert row["status"] == "published" and row["last_publish_snapshot"] == snapshot

    wrong = client.post("/api/wordpress/staging/publish-rollback", json={"source_domain":"live.example.test","snapshot_id":"1760000001-deadbeef"}, headers={"X-CSRF-Token":csrf})
    assert wrong.status_code == 409
    before = len(calls)
    rolled = client.post("/api/wordpress/staging/publish-rollback", json={"source_domain":"live.example.test","snapshot_id":snapshot}, headers={"X-CSRF-Token":csrf})
    assert rolled.status_code == 200 and rolled.get_json()["rolled_back"] is True
    assert len(calls) == before + 1 and calls[-1]["action"] == "staging-publish-rollback"

    # Package policy blocks access before provider calls.
    with db() as conn:
        conn.execute("INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,0,?) ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=0,updated_at=excluded.updated_at", (pid, "software.wordpress", now))
    before = len(calls)
    assert client.get("/api/wordpress/staging?domain=live.example.test").status_code == 403
    assert client.post("/api/wordpress/staging/publish", json={"source_domain":"live.example.test"}, headers={"X-CSRF-Token":csrf}).status_code == 403
    assert len(calls) == before

    with db() as conn:
        audit_text = "\n".join(str(row[0] or "") for row in conn.execute("SELECT detail FROM audit WHERE action LIKE 'wordpress-staging%'").fetchall())
        assert "password" not in audit_text.lower()

print("Nexvary Panel WordPress staging route gate: PASS")
