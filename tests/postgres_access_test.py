from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-pg-access-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_POSTGRES_SOCK"] = str(pathlib.Path(tmp) / "missing-postgres.sock")

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_database_access as routes

    app = create_app(); app.testing = True; client = app.test_client()
    now = int(time.time()); csrf = "postgres-access-csrf"
    password = "StrongPgPass-2026!"; rotated = "RotatedPgPass-2026!"
    calls: list[dict] = []

    def fake_postgres(payload, timeout=45):
        calls.append(dict(payload))
        if payload.get("action") == "status":
            return {"ok": True, "available": True, "engine": "postgresql", "grant_profiles": ["developer", "readonly", "readwrite"]}
        return {"ok": True, "username": payload.get("username", ""), "profile": payload.get("profile", "")}

    routes.postgres_call = fake_postgres

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone(); pid = int(core["id"])
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)", ("pgclient", "operator", "44"*16, "44"*32, now))
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)", ("pgclient", pid, now))
        conn.execute("INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,1,?)", (pid, "databases.postgresql", now))
        conn.execute("INSERT INTO postgres_resources(db_name,db_user,site_domain,owner,created_at) VALUES(?,?,?,?,?)", ("client_pg", "owner_role", "", "pgclient", now))
        conn.execute("INSERT INTO postgres_resources(db_name,db_user,site_domain,owner,created_at) VALUES(?,?,?,?,?)", ("admin_pg", "admin_owner", "", "admin", now))
        owner = conn.execute("SELECT managed_owner_role FROM postgres_access_roles WHERE username='owner_role'").fetchone()
        assert owner and int(owner[0]) == 1

    with client.session_transaction() as sess:
        sess.update(auth=True, user="pgclient", role="operator", csrf=csrf)

    no_step = client.post("/api/database-access/postgresql/roles", json={"username":"analyst_role","password":password}, headers={"X-CSRF-Token":csrf})
    assert no_step.status_code == 428 and calls == []

    with client.session_transaction() as sess:
        sess["step_up_user"] = "pgclient"; sess["step_up_until"] = now + 600

    created = client.post("/api/database-access/postgresql/roles", json={"username":"analyst_role","password":password}, headers={"X-CSRF-Token":csrf})
    assert created.status_code == 201, created.data
    assert calls[-1]["action"] == "role-create" and calls[-1]["password"] == password

    catalog = client.get("/api/database-access/postgresql")
    assert catalog.status_code == 200, catalog.data
    body = catalog.get_json()
    assert body["provider"]["online"] is True
    assert all(row["owner"] == "pgclient" for row in body["databases"])
    roles = {row["username"]: row for row in body["roles"]}
    assert roles["owner_role"]["managed_owner_role"] is True
    assert roles["analyst_role"]["managed_owner_role"] is False
    assert set(body["profiles"]) == {"readonly", "readwrite", "developer"}

    owner_denied = client.put("/api/database-access/postgresql/grants", json={"db_name":"client_pg","username":"owner_role","profile":"readonly"}, headers={"X-CSRF-Token":csrf})
    assert owner_denied.status_code == 409

    cross = client.put("/api/database-access/postgresql/grants", json={"db_name":"admin_pg","username":"analyst_role","profile":"readonly"}, headers={"X-CSRF-Token":csrf})
    assert cross.status_code == 409

    invalid = client.put("/api/database-access/postgresql/grants", json={"db_name":"client_pg","username":"analyst_role","profile":"superuser"}, headers={"X-CSRF-Token":csrf})
    assert invalid.status_code == 400

    granted = client.put("/api/database-access/postgresql/grants", json={"db_name":"client_pg","username":"analyst_role","profile":"readwrite"}, headers={"X-CSRF-Token":csrf})
    assert granted.status_code == 200, granted.data
    assert calls[-1] == {"action":"grant-profile","db_name":"client_pg","username":"analyst_role","profile":"readwrite"}

    rotated_resp = client.put("/api/database-access/postgresql/roles/analyst_role/password", json={"password":rotated}, headers={"X-CSRF-Token":csrf})
    assert rotated_resp.status_code == 200 and "password" not in rotated_resp.get_json()

    blocked_delete = client.delete("/api/database-access/postgresql/roles/analyst_role", headers={"X-CSRF-Token":csrf})
    assert blocked_delete.status_code == 409
    revoked = client.put("/api/database-access/postgresql/grants", json={"db_name":"client_pg","username":"analyst_role","profile":"none"}, headers={"X-CSRF-Token":csrf})
    assert revoked.status_code == 200
    removed = client.delete("/api/database-access/postgresql/roles/analyst_role", headers={"X-CSRF-Token":csrf})
    assert removed.status_code == 200

    with db() as conn:
        details = "\n".join(str(row[0] or "") for row in conn.execute("SELECT detail FROM audit WHERE action LIKE 'postgres-%'").fetchall())
        assert password not in details and rotated not in details
        assert conn.execute("SELECT 1 FROM postgres_access_roles WHERE username='analyst_role'").fetchone() is None
        conn.execute("UPDATE hosting_package_features SET enabled=0,updated_at=? WHERE package_id=? AND feature_id='databases.postgresql'", (now, pid))

    blocked = client.get("/api/database-access/postgresql")
    assert blocked.status_code == 403

print("Nexvary Panel PostgreSQL Access Manager policy gate: PASS")
