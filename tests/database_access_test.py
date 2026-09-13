from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-db-access-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_DATABASE_SOCK"] = str(pathlib.Path(tmp) / "missing-database.sock")

    from panel import create_app
    from panel.database_access_schema import ensure_database_access_schema
    from panel.db_layer import db
    import panel.routes_database_access as routes

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "database-access-csrf"
    password = "StrongDbPass-2026!"
    rotated_password = "RotatedDbPass-2026!"
    calls: list[dict] = []

    def fake_database(payload, timeout=30):
        calls.append(payload)
        if payload.get("action") == "status":
            return {"ok": True, "engine": "mariadb", "version": "11-test"}
        return {"ok": True}

    routes.database_call = fake_database

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        pid = int(core["id"])
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)", ("dbclient", "operator", "33"*16, "33"*32, now))
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)", ("dbclient", pid, now))
        conn.execute("INSERT INTO databases(db_name,db_user,engine,site_domain,owner,created_at) VALUES(?,?,?,?,?,?)", ("client_db", "legacy_user", "mariadb", "", "dbclient", now))
        conn.execute("INSERT INTO databases(db_name,db_user,engine,site_domain,owner,created_at) VALUES(?,?,?,?,?,?)", ("admin_db", "admin_db_user", "mariadb", "", "admin", now))
    ensure_database_access_schema()

    with db() as conn:
        assert conn.execute("SELECT 1 FROM database_access_users WHERE username='legacy_user' AND owner='dbclient'").fetchone()
        legacy = conn.execute("SELECT privileges FROM database_access_grants WHERE db_name='client_db' AND db_user='legacy_user'").fetchone()
        assert legacy and "SELECT" in legacy["privileges"] and "ALTER" in legacy["privileges"]

    with client.session_transaction() as sess:
        sess.update(auth=True, user="dbclient", role="operator", csrf=csrf)

    no_step = client.post(
        "/api/database-access/users",
        json={"username": "report_user", "password": password},
        headers={"X-CSRF-Token": csrf},
    )
    assert no_step.status_code == 428 and calls == []

    with client.session_transaction() as sess:
        sess["step_up_user"] = "dbclient"
        sess["step_up_until"] = now + 600

    created = client.post(
        "/api/database-access/users",
        json={"username": "report_user", "password": password},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201, created.data
    assert created.get_json()["username"] == "report_user"
    assert calls[-1]["action"] == "user-create"
    assert calls[-1]["data"]["password"] == password

    catalog = client.get("/api/database-access")
    assert catalog.status_code == 200
    body = catalog.get_json()
    assert body["provider"]["online"] is True
    assert all(row["owner"] == "dbclient" for row in body["databases"])
    assert {row["username"] for row in body["users"]} >= {"legacy_user", "report_user"}
    assert "TRIGGER" in body["privilege_catalog"]

    cross = client.put(
        "/api/database-access/grants",
        json={"db_name": "admin_db", "username": "report_user", "privileges": ["SELECT"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert cross.status_code == 409

    granted = client.put(
        "/api/database-access/grants",
        json={"db_name": "client_db", "username": "report_user", "privileges": ["SELECT", "UPDATE"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert granted.status_code == 200, granted.data
    assert granted.get_json()["privileges"] == ["SELECT", "UPDATE"]
    assert calls[-1]["action"] == "grant-replace"

    rotated = client.put(
        "/api/database-access/users/report_user/password",
        json={"password": rotated_password},
        headers={"X-CSRF-Token": csrf},
    )
    assert rotated.status_code == 200
    assert "password" not in rotated.get_json()

    blocked_delete = client.delete("/api/database-access/users/report_user", headers={"X-CSRF-Token": csrf})
    assert blocked_delete.status_code == 409

    revoked = client.put(
        "/api/database-access/grants",
        json={"db_name": "client_db", "username": "report_user", "privileges": []},
        headers={"X-CSRF-Token": csrf},
    )
    assert revoked.status_code == 200
    removed = client.delete("/api/database-access/users/report_user", headers={"X-CSRF-Token": csrf})
    assert removed.status_code == 200

    with db() as conn:
        details = "\n".join(str(row[0] or "") for row in conn.execute("SELECT detail FROM audit WHERE action LIKE 'database-%'").fetchall())
        assert password not in details and rotated_password not in details
        assert conn.execute("SELECT 1 FROM database_access_users WHERE username='report_user'").fetchone() is None
        conn.execute(
            "INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,0,?) ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=0,updated_at=excluded.updated_at",
            (pid, "databases.mariadb", now),
        )

    blocked = client.get("/api/database-access")
    assert blocked.status_code == 403

print("Nexvary Panel Database Access Manager policy gate: PASS")
