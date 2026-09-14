from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-wp-smart-guard-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_WORDPRESS_SOCK"] = str(pathlib.Path(tmp) / "missing-wordpress.sock")

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_wordpress_smart_guard as routes

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "smart-guard-csrf"
    stage_snapshot = "1760000100-cafebabe"
    production_snapshot = "1760000200-deadbeef"
    component_updated = False
    production_integrity_ok = True
    calls: list[dict] = []

    def fake_wordpress(payload, timeout=45):
        nonlocal_holder = None
        calls.append(dict(payload))
        action = payload.get("action")
        domain = payload.get("domain")
        if action == "component-check":
            updated = component_updated
            return {"ok": True, "domain": domain, "kind": payload["kind"], "slug": payload["slug"], "installed_version": "2.0.0" if updated else "1.0.0", "latest_version": "2.0.0", "update_available": not updated}
        if action == "component-update":
            globals_dict["component_updated"] = True
            return {"ok": True, "updated": True, "installed_version": "1.0.0", "latest_version": "2.0.0", "snapshot_id": stage_snapshot}
        if action == "component-rollback":
            globals_dict["component_updated"] = False
            return {"ok": True, "snapshot_id": payload["snapshot_id"], "restored_version": "1.0.0"}
        if action == "integrity":
            ok = production_integrity_ok if domain == "live.example.test" else True
            return {"ok": True, "domain": domain, "integrity_ok": ok, "missing_count": 0 if ok else 1, "mismatched_count": 0}
        if action == "staging-publish-selective":
            return {"ok": True, "live_domain": payload["source_domain"], "staging_domain": payload["target_domain"], "snapshot_id": production_snapshot, "scope": "plugins_themes", "version": "6.8.2", "published": {"plugins": 3, "themes": 2}, "database_changed": False, "uploads_changed": False}
        if action == "inventory":
            return {"ok": True, "domain": domain, "version": "6.8.2", "plugin_count": 3, "theme_count": 2}
        if action == "staging-publish-rollback":
            return {"ok": True, "live_domain": payload["source_domain"], "snapshot_id": payload["snapshot_id"], "version": "6.8.2", "rolled_back": True}
        return {"ok": False, "error": f"unexpected-test-action:{action}"}

    # Mutable closure state without exposing any credential material.
    globals_dict = {"component_updated": False}
    def wrapped_wordpress(payload, timeout=45):
        nonlocal_component = globals_dict["component_updated"]
        calls.append(dict(payload))
        action = payload.get("action")
        domain = payload.get("domain")
        if action == "component-check":
            return {"ok": True, "domain": domain, "kind": payload["kind"], "slug": payload["slug"], "installed_version": "2.0.0" if nonlocal_component else "1.0.0", "latest_version": "2.0.0", "update_available": not nonlocal_component}
        if action == "component-update":
            globals_dict["component_updated"] = True
            return {"ok": True, "updated": True, "installed_version": "1.0.0", "latest_version": "2.0.0", "snapshot_id": stage_snapshot}
        if action == "component-rollback":
            globals_dict["component_updated"] = False
            return {"ok": True, "snapshot_id": payload["snapshot_id"], "restored_version": "1.0.0"}
        if action == "integrity":
            ok = globals_dict.get("production_integrity_ok", True) if domain == "live.example.test" else True
            return {"ok": True, "domain": domain, "integrity_ok": ok, "missing_count": 0 if ok else 1, "mismatched_count": 0}
        if action == "staging-publish-selective":
            return {"ok": True, "live_domain": payload["source_domain"], "staging_domain": payload["target_domain"], "snapshot_id": production_snapshot, "scope": "plugins_themes", "version": "6.8.2", "published": {"plugins": 3, "themes": 2}, "database_changed": False, "uploads_changed": False}
        if action == "inventory":
            return {"ok": True, "domain": domain, "version": "6.8.2", "plugin_count": 3, "theme_count": 2}
        if action == "staging-publish-rollback":
            return {"ok": True, "live_domain": payload["source_domain"], "snapshot_id": payload["snapshot_id"], "version": "6.8.2", "rolled_back": True}
        return {"ok": False, "error": f"unexpected-test-action:{action}"}

    routes.wordpress_call = wrapped_wordpress

    with db() as conn:
        package = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        pid = int(package["id"])
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)", ("wpguard", "operator", "aa" * 16, "bb" * 32, now))
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)", ("wpguard", pid, now))
        for domain in ("live.example.test", "stage.example.test"):
            conn.execute("INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)", (domain, "php", "", None, "wpguard", now))
        conn.execute("INSERT INTO databases(db_name,db_user,engine,site_domain,owner,created_at) VALUES(?,?,?,?,?,?)", ("wpdb", "wpuser", "mariadb", "live.example.test", "wpguard", now))
        conn.execute("INSERT INTO databases(db_name,db_user,engine,site_domain,owner,created_at) VALUES(?,?,?,?,?,?)", ("wpstage", "wpuser", "mariadb", "stage.example.test", "wpguard", now))
        conn.execute("INSERT INTO wordpress_instances(domain,db_name,db_user,status,version,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", ("live.example.test", "wpdb", "wpuser", "active", "6.8.2", "wpguard", now, now))
        conn.execute("INSERT INTO wordpress_instances(domain,db_name,db_user,status,version,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", ("stage.example.test", "wpstage", "wpuser", "staging", "6.8.2", "wpguard", now, now))
        conn.execute("INSERT INTO wordpress_staging(source_domain,target_domain,source_db,target_db,db_user,owner,status,last_publish_snapshot,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'',?,?)", ("live.example.test", "stage.example.test", "wpdb", "wpstage", "wpuser", "wpguard", "ready", now, now))

    with client.session_transaction() as sess:
        sess.update(auth=True, user="wpguard", role="operator", csrf=csrf)

    preview = client.post("/api/wordpress/smart-guard/preview", json={"source_domain":"live.example.test","kind":"plugin","slug":"hello-tool"}, headers={"X-CSRF-Token":csrf})
    assert preview.status_code == 201, preview.data
    candidate = preview.get_json()["candidate"]
    candidate_id = int(candidate["id"])
    assert candidate["status"] == "preview" and candidate["target_version"] == "2.0.0"
    assert calls[-1]["action"] == "component-check" and calls[-1]["domain"] == "stage.example.test"

    no_step = client.post(f"/api/wordpress/smart-guard/{candidate_id}/verify", json={}, headers={"X-CSRF-Token":csrf})
    assert no_step.status_code == 428, no_step.data
    with client.session_transaction() as sess:
        sess["step_up_user"] = "wpguard"; sess["step_up_until"] = now + 600

    verified = client.post(f"/api/wordpress/smart-guard/{candidate_id}/verify", json={}, headers={"X-CSRF-Token":csrf})
    assert verified.status_code == 200, verified.data
    body = verified.get_json()
    assert body["publish_ready"] is True and body["candidate"]["status"] == "verified"
    assert body["candidate"]["staging_snapshot"] == stage_snapshot
    assert [call["action"] for call in calls[-3:]] == ["component-update", "integrity", "component-check"]

    with client.session_transaction() as sess:
        sess.pop("step_up_user", None); sess.pop("step_up_until", None)
    no_step = client.post(f"/api/wordpress/smart-guard/{candidate_id}/publish", json={}, headers={"X-CSRF-Token":csrf})
    assert no_step.status_code == 428
    with client.session_transaction() as sess:
        sess["step_up_user"] = "wpguard"; sess["step_up_until"] = now + 600

    published = client.post(f"/api/wordpress/smart-guard/{candidate_id}/publish", json={}, headers={"X-CSRF-Token":csrf})
    assert published.status_code == 200, published.data
    result = published.get_json()
    assert result["safety"] == "postchecked-rollback-ready"
    assert result["snapshot_id"] == production_snapshot
    assert candidate_id in result["cohort_ids"]
    with db() as conn:
        row = conn.execute("SELECT status,production_snapshot FROM wordpress_update_guard WHERE id=?", (candidate_id,)).fetchone()
        assert row["status"] == "published" and row["production_snapshot"] == production_snapshot
        history = conn.execute("SELECT status,detail FROM wordpress_publish_history WHERE source_domain=? ORDER BY id DESC LIMIT 1", ("live.example.test",)).fetchone()
        assert history and history["status"] == "published" and "smart-guard" in history["detail"]

    state = client.get("/api/wordpress/smart-guard?domain=live.example.test")
    assert state.status_code == 200
    policy = state.get_json()["policy"]
    assert policy["staging_required"] and policy["verify_before_guarded_publish"] and policy["automatic_rollback_on_failed_postcheck"]

    # A second candidate proves production post-check failure triggers automatic rollback.
    globals_dict["component_updated"] = False
    preview2 = client.post("/api/wordpress/smart-guard/preview", json={"source_domain":"live.example.test","kind":"theme","slug":"royal-theme"}, headers={"X-CSRF-Token":csrf})
    candidate2 = int(preview2.get_json()["candidate"]["id"])
    assert client.post(f"/api/wordpress/smart-guard/{candidate2}/verify", json={}, headers={"X-CSRF-Token":csrf}).status_code == 200
    globals_dict["production_integrity_ok"] = False
    failed = client.post(f"/api/wordpress/smart-guard/{candidate2}/publish", json={}, headers={"X-CSRF-Token":csrf})
    assert failed.status_code == 409, failed.data
    assert failed.get_json()["rolled_back"] is True
    assert calls[-1]["action"] == "staging-publish-rollback"
    with db() as conn:
        row = conn.execute("SELECT status FROM wordpress_update_guard WHERE id=?", (candidate2,)).fetchone()
        assert row["status"] == "publish-failed-rolled-back"

print("NEXVARY WordPress Smart Update Guard gate: PASS")
