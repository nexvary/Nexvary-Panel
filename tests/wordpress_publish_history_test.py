from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-wp-publish-history-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_WORDPRESS_SOCK"] = str(pathlib.Path(tmp) / "missing-wordpress.sock")

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_wordpress_publish as routes

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "wp-publish-csrf"
    selective_snapshot = "1760000100-deadc0de"
    calls: list[dict] = []

    def fake_wordpress(payload, timeout=45):
        calls.append(dict(payload))
        if payload.get("action") == "staging-publish-selective":
            return {
                "ok": True,
                "snapshot_id": selective_snapshot,
                "version": "6.8.2",
                "scope": "plugins_themes",
                "published": {"plugins": 11, "themes": 4},
                "database_changed": False,
                "uploads_changed": False,
            }
        if payload.get("action") == "staging-publish-rollback":
            return {"ok": True, "snapshot_id": payload["snapshot_id"], "version": "6.8.2", "rolled_back": True}
        return {"ok": False, "error": "unexpected-test-action"}

    routes.wordpress_call = fake_wordpress

    with db() as conn:
        package = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        pid = int(package["id"])
        conn.execute("UPDATE hosting_packages SET max_databases=10 WHERE id=?", (pid,))
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)", ("wpclient", "operator", "aa" * 16, "bb" * 32, now))
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)", ("wpclient", pid, now))
        for domain in ("live.example.test", "stage.example.test"):
            conn.execute("INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)", (domain, "php", "", None, "wpclient", now))
        conn.execute("INSERT INTO databases(db_name,db_user,engine,site_domain,owner,created_at) VALUES(?,?,?,?,?,?)", ("wpdb", "wpuser", "mariadb", "live.example.test", "wpclient", now))
        conn.execute("INSERT INTO databases(db_name,db_user,engine,site_domain,owner,created_at) VALUES(?,?,?,?,?,?)", ("wpstage", "wpuser", "mariadb", "stage.example.test", "wpclient", now))
        conn.execute("INSERT INTO wordpress_instances(domain,db_name,db_user,status,version,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", ("live.example.test", "wpdb", "wpuser", "active", "6.8.2", "wpclient", now, now))
        conn.execute("INSERT INTO wordpress_instances(domain,db_name,db_user,status,version,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", ("stage.example.test", "wpstage", "wpuser", "staging", "6.8.2", "wpclient", now, now))
        conn.execute("INSERT INTO wordpress_staging(source_domain,target_domain,source_db,target_db,db_user,owner,status,last_publish_snapshot,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)", ("live.example.test", "stage.example.test", "wpdb", "wpstage", "wpuser", "wpclient", "ready", "", now, now))

    with client.session_transaction() as sess:
        sess.update(auth=True, user="wpclient", role="operator", csrf=csrf, step_up_user="wpclient", step_up_until=now + 600)

    # Existing full publish route is tracked automatically by the schema trigger.
    full_snapshot = "1760000000-cafebabe"
    with db() as conn:
        conn.execute("UPDATE wordpress_staging SET status='published',last_publish_snapshot=?,updated_at=? WHERE source_domain=?", (full_snapshot, now + 1, "live.example.test"))
        full = conn.execute("SELECT scope,status FROM wordpress_publish_history WHERE snapshot_id=?", (full_snapshot,)).fetchone()
        assert full and full["scope"] == "full" and full["status"] == "published"

    bad_scope = client.post("/api/wordpress/staging/publish-selective", json={"source_domain":"live.example.test","scope":"database"}, headers={"X-CSRF-Token":csrf})
    assert bad_scope.status_code == 400
    assert not calls

    selective = client.post("/api/wordpress/staging/publish-selective", json={"source_domain":"live.example.test","scope":"plugins_themes"}, headers={"X-CSRF-Token":csrf})
    assert selective.status_code == 200, selective.data
    body = selective.get_json()
    assert body["snapshot_id"] == selective_snapshot
    assert body["database_changed"] is False and body["uploads_changed"] is False
    assert calls[-1]["action"] == "staging-publish-selective"

    history = client.get("/api/wordpress/staging/history?domain=live.example.test")
    assert history.status_code == 200
    rows = history.get_json()["history"]
    assert rows[0]["snapshot_id"] == selective_snapshot and rows[0]["scope"] == "plugins_themes" and rows[0]["can_rollback"] is True
    assert any(row["snapshot_id"] == full_snapshot and row["scope"] == "full" for row in rows)

    older = client.post(f"/api/wordpress/staging/history/{full_snapshot}/rollback", json={"source_domain":"live.example.test"}, headers={"X-CSRF-Token":csrf})
    assert older.status_code == 409

    rolled = client.post(f"/api/wordpress/staging/history/{selective_snapshot}/rollback", json={"source_domain":"live.example.test"}, headers={"X-CSRF-Token":csrf})
    assert rolled.status_code == 200 and rolled.get_json()["rolled_back"] is True
    assert calls[-1]["action"] == "staging-publish-rollback"
    with db() as conn:
        row = conn.execute("SELECT status,rolled_back_at FROM wordpress_publish_history WHERE snapshot_id=?", (selective_snapshot,)).fetchone()
        assert row["status"] == "rolled-back" and int(row["rolled_back_at"]) > 0

    with db() as conn:
        conn.execute("INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,0,?) ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=0,updated_at=excluded.updated_at", (pid, "software.wordpress", now))
    before = len(calls)
    assert client.get("/api/wordpress/staging/history?domain=live.example.test").status_code == 403
    assert client.post("/api/wordpress/staging/publish-selective", json={"source_domain":"live.example.test","scope":"plugins_themes"}, headers={"X-CSRF-Token":csrf}).status_code == 403
    assert len(calls) == before

print("Nexvary Panel WordPress publish history route gate: PASS")
