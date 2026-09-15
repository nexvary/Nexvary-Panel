from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-db-life-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_DATABASE_SOCK"] = str(pathlib.Path(tmp) / "missing-db.sock")
    os.environ["NVP_POSTGRES_SOCK"] = str(pathlib.Path(tmp) / "missing-pg.sock")

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_database_lifecycle as routes

    app = create_app(); app.testing = True; client = app.test_client()
    now = int(time.time()); csrf = "database-lifecycle-csrf"
    maria_calls: list[dict] = []; pg_calls: list[dict] = []

    def fake_maria(payload, timeout=180):
        maria_calls.append(dict(payload))
        action = payload.get("action")
        if action == "snapshot-create":
            return {"ok": True, "archive": "client_db-20260914T100000Z-a1b2c3d4.sql", "size_bytes": 12345, "sha256": "a" * 64}
        if action == "snapshot-restore":
            return {"ok": True, "restored": True, "rollback_archive": "client_db-20260914T100100Z-b1c2d3e4.sql", "rollback_size_bytes": 12000, "rollback_sha256": "b" * 64}
        return {"ok": True, "deleted": True}

    def fake_pg(payload, timeout=180):
        pg_calls.append(dict(payload))
        action = payload.get("action")
        if action == "snapshot-create":
            return {"ok": True, "archive": "client_pg-20260914T100000Z-c1d2e3f4.dump", "size_bytes": 22000, "sha256": "c" * 64}
        if action == "snapshot-restore":
            return {"ok": True, "restored": True, "rollback_archive": "client_pg-20260914T100100Z-d1e2f3a4.dump", "rollback_size_bytes": 21000, "rollback_sha256": "d" * 64}
        return {"ok": True, "deleted": True}

    routes.database_call = fake_maria
    routes.postgres_call = fake_pg

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone(); pid = int(core["id"])
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)", ("dbclient", "operator", "55"*16, "55"*32, now))
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)", ("dbclient", pid, now))
        conn.execute("INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,1,?) ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=1", (pid, "databases.postgresql", now))
        conn.execute("INSERT INTO databases(db_name,db_user,site_domain,engine,owner,created_at) VALUES(?,?,?,?,?,?)", ("client_db", "client_user", "", "mariadb", "dbclient", now))
        conn.execute("INSERT INTO databases(db_name,db_user,site_domain,engine,owner,created_at) VALUES(?,?,?,?,?,?)", ("admin_db", "admin_user", "", "mariadb", "admin", now))
        conn.execute("INSERT INTO postgres_resources(db_name,db_user,site_domain,owner,created_at) VALUES(?,?,?,?,?)", ("client_pg", "client_pg_owner", "", "dbclient", now))

    with client.session_transaction() as sess:
        sess.update(auth=True, user="dbclient", role="operator", csrf=csrf)

    catalog = client.get("/api/database-lifecycle")
    assert catalog.status_code == 200, catalog.data
    cat = catalog.get_json()
    assert {x["db_name"] for x in cat["databases"]} == {"client_db", "client_pg"}
    assert cat["policy"] == {"server_managed_only": True, "arbitrary_paths": False, "restore_safety_snapshot": True}

    no_step = client.post("/api/database-lifecycle/snapshots", json={"engine":"mariadb","db_name":"client_db"}, headers={"X-CSRF-Token":csrf})
    assert no_step.status_code == 428 and maria_calls == []

    with client.session_transaction() as sess:
        sess["step_up_user"] = "dbclient"; sess["step_up_until"] = now + 600

    cross = client.post("/api/database-lifecycle/snapshots", json={"engine":"mariadb","db_name":"admin_db"}, headers={"X-CSRF-Token":csrf})
    assert cross.status_code == 403 and maria_calls == []

    created = client.post("/api/database-lifecycle/snapshots", json={"engine":"mariadb","db_name":"client_db","archive":"/tmp/attacker.sql"}, headers={"X-CSRF-Token":csrf})
    assert created.status_code == 201, created.data
    assert maria_calls[-1] == {"action":"snapshot-create","db_name":"client_db"}
    sid = int(created.get_json()["id"])

    pg_created = client.post("/api/database-lifecycle/snapshots", json={"engine":"postgresql","db_name":"client_pg","path":"../../escape"}, headers={"X-CSRF-Token":csrf})
    assert pg_created.status_code == 201, pg_created.data
    assert pg_calls[-1] == {"action":"snapshot-create","db_name":"client_pg"}

    restored = client.post(f"/api/database-lifecycle/snapshots/{sid}/restore", headers={"X-CSRF-Token":csrf})
    assert restored.status_code == 200, restored.data
    assert maria_calls[-1]["action"] == "snapshot-restore"
    assert maria_calls[-1]["archive"].endswith(".sql") and "/" not in maria_calls[-1]["archive"]
    rollback_id = restored.get_json()["rollback_snapshot_id"]
    assert rollback_id

    with db() as conn:
        rollback = conn.execute("SELECT kind,archive,owner FROM database_snapshots WHERE id=?", (rollback_id,)).fetchone()
        assert rollback and rollback["kind"] == "pre-restore" and rollback["owner"] == "dbclient"
        assert conn.execute("SELECT restored_at FROM database_snapshots WHERE id=?", (sid,)).fetchone()[0] > 0
        conn.execute("UPDATE hosting_package_features SET enabled=0,updated_at=? WHERE package_id=? AND feature_id='databases.postgresql'", (now, pid))

    pg_blocked = client.post("/api/database-lifecycle/snapshots", json={"engine":"postgresql","db_name":"client_pg"}, headers={"X-CSRF-Token":csrf})
    assert pg_blocked.status_code == 403

    deleted = client.delete(f"/api/database-lifecycle/snapshots/{sid}", headers={"X-CSRF-Token":csrf})
    assert deleted.status_code == 200 and maria_calls[-1]["action"] == "snapshot-delete"

    with db() as conn:
        actions = {str(row[0]) for row in conn.execute("SELECT action FROM audit WHERE action LIKE 'database-snapshot-%'").fetchall()}
        assert {"database-snapshot-create", "database-snapshot-restore", "database-snapshot-delete"}.issubset(actions)

print("Nexvary Panel managed database lifecycle policy gate: PASS")
