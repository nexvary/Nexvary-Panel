from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-extensions-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "extensions-csrf"

    with db() as conn:
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("viewer01", "viewer", "00" * 16, "00" * 32, now),
        )

    with client.session_transaction() as session:
        session.update(auth=True, user="admin", role="admin", csrf=csrf, step_up_user="admin", step_up_until=now + 600)

    catalog = client.get("/api/extensions")
    assert catalog.status_code == 200, catalog.data
    body = catalog.get_json()
    assert body["execution_model"] == "curated-manifests-no-arbitrary-code"
    by_id = {item["extension_id"]: item for item in body["extensions"]}
    for extension_id in ("dnssec", "autossl", "mail-queue", "deliverability", "fleet", "migration-center", "wordpress-staging"):
        assert extension_id in by_id and by_id[extension_id]["state"]["enabled"] is True
    assert by_id["fleet"]["maturity"] == "provider"
    assert by_id["migration-center"]["maturity"] == "provider"
    assert "/api/migration-center" in by_id["migration-center"]["api_prefixes"]
    assert all(prefix.startswith("/api/") for item in body["extensions"] for prefix in item["api_prefixes"])

    disable = client.put(
        "/api/extensions/fleet",
        json={"enabled": False},
        headers={"X-CSRF-Token": csrf},
    )
    assert disable.status_code == 200 and disable.get_json()["enabled"] is False
    blocked = client.get("/api/fleet")
    assert blocked.status_code == 503
    assert blocked.get_json()["error"] == "extension disabled: fleet"

    enable = client.put(
        "/api/extensions/fleet",
        json={"enabled": True},
        headers={"X-CSRF-Token": csrf},
    )
    assert enable.status_code == 200 and enable.get_json()["enabled"] is True
    restored = client.get("/api/fleet")
    assert restored.status_code == 200, restored.data

    disable_migration = client.put(
        "/api/extensions/migration-center",
        json={"enabled": False},
        headers={"X-CSRF-Token": csrf},
    )
    assert disable_migration.status_code == 200 and disable_migration.get_json()["enabled"] is False
    blocked_migration = client.get("/api/migration-center/uploads")
    assert blocked_migration.status_code == 503
    assert blocked_migration.get_json()["error"] == "extension disabled: migration-center"
    enable_migration = client.put(
        "/api/extensions/migration-center",
        json={"enabled": True},
        headers={"X-CSRF-Token": csrf},
    )
    assert enable_migration.status_code == 200 and enable_migration.get_json()["enabled"] is True
    restored_migration = client.get("/api/migration-center/uploads")
    assert restored_migration.status_code == 200, restored_migration.data

    invalid = client.put(
        "/api/extensions/not-real",
        json={"enabled": False},
        headers={"X-CSRF-Token": csrf},
    )
    assert invalid.status_code == 404

    with client.session_transaction() as session:
        session.clear()
        session.update(auth=True, user="admin", role="admin", csrf=csrf)
    no_step = client.put(
        "/api/extensions/dnssec",
        json={"enabled": False},
        headers={"X-CSRF-Token": csrf},
    )
    assert no_step.status_code == 428

    with client.session_transaction() as session:
        session.clear()
        session.update(auth=True, user="viewer01", role="viewer", csrf=csrf)
    viewer = client.get("/api/extensions")
    assert viewer.status_code == 403

    with db() as conn:
        fleet = conn.execute("SELECT enabled,updated_by FROM extension_states WHERE extension_id='fleet'").fetchone()
        migration = conn.execute("SELECT enabled,updated_by FROM extension_states WHERE extension_id='migration-center'").fetchone()
        assert fleet and int(fleet["enabled"]) == 1 and fleet["updated_by"] == "admin"
        assert migration and int(migration["enabled"]) == 1 and migration["updated_by"] == "admin"
        rows = conn.execute("SELECT action,detail FROM audit WHERE action='extension-state' ORDER BY id").fetchall()
        assert len(rows) == 4
        details = [str(row["detail"]) for row in rows]
        assert sum("extension=fleet" in detail for detail in details) == 2
        assert sum("extension=migration-center" in detail for detail in details) == 2

print("Nexvary Panel curated Extension Hub / kill-switch gate: PASS")
