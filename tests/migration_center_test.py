from __future__ import annotations

import io
import os
import pathlib
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-migration-center-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db

    app = create_app()
    app.testing = True
    client = app.test_client()
    csrf = "migration-csrf"
    now = int(time.time())

    def admin(step_up: bool = True):
        with client.session_transaction() as sess:
            sess.clear()
            sess.update(auth=True, user="admin", role="admin", csrf=csrf)
            if step_up:
                sess.update(step_up_user="admin", step_up_until=now + 600)

    admin()
    upload = client.post(
        "/api/migration-center/uploads",
        data={"archive": (io.BytesIO(b"not-a-real-archive-but-streamed"), "cpmove-demo.tar.gz")},
        headers={"X-CSRF-Token": csrf},
        content_type="multipart/form-data",
    )
    assert upload.status_code == 201, upload.data
    uploaded = upload.get_json()
    filename = uploaded["filename"]
    assert filename.endswith(".tar.gz")
    inbox_file = pathlib.Path(tmp) / "migration-inbox" / filename
    assert inbox_file.is_file()
    assert inbox_file.read_bytes() == b"not-a-real-archive-but-streamed"
    assert inbox_file.stat().st_mode & 0o077 == 0

    listing = client.get("/api/migration-center/uploads")
    assert listing.status_code == 200
    body = listing.get_json()
    assert body["uploads"][0]["filename"] == filename
    assert body["supported_panels"] == ["cpanel", "directadmin", "plesk"]

    with patch(
        "panel.routes_migration_center.ops_call",
        return_value={
            "ok": True,
            "panel": "cpanel",
            "filename": filename,
            "capabilities": {"website": True, "mariadb_sql": True, "mail_import": False, "dns_apply": False},
            "warnings": ["mail data detected"],
        },
    ) as inspect_call:
        inspected = client.post(
            "/api/migration-center/inspect",
            json={"filename": filename},
            headers={"X-CSRF-Token": csrf},
        )
    assert inspected.status_code == 200
    assert inspected.get_json()["panel"] == "cpanel"
    assert inspect_call.call_args.args[0]["action"] == "migration-import-inspect"

    normalized_archive = "/var/backups/nexvary-panel/migrations/example.com-import-cpanel-test.tar.gz"
    with patch(
        "panel.routes_migration_center.ops_call",
        return_value={
            "ok": True,
            "panel": "cpanel",
            "archive": normalized_archive,
            "size_bytes": 12345,
            "sha256": "a" * 64,
            "website_files": 42,
            "database_included": True,
            "warnings": ["DNS data detected"],
        },
    ) as normalize_call:
        normalized = client.post(
            "/api/migration-center/normalize",
            json={
                "filename": filename,
                "target_domain": "example.com",
                "source_db": "old_db",
                "target_db": "new_db",
            },
            headers={"X-CSRF-Token": csrf},
        )
    assert normalized.status_code == 201, normalized.data
    payload = normalized.get_json()
    assert payload["source_panel"] == "cpanel"
    assert payload["website_files"] == 42
    assert payload["database_included"] is True
    assert payload["restore_endpoint"].endswith("/restore")
    bundle_id = int(payload["bundle_id"])
    assert normalize_call.call_args.args[0]["action"] == "migration-import-normalize"

    with db() as conn:
        row = conn.execute("SELECT domain,archive,size_bytes,sha256,status,owner FROM migration_bundles WHERE id=?", (bundle_id,)).fetchone()
    assert row is not None
    assert row["domain"] == "example.com" and row["archive"] == normalized_archive
    assert int(row["size_bytes"]) == 12345 and row["sha256"] == "a" * 64
    assert row["status"] == "ready" and row["owner"] == "admin"

    bad_extension = client.post(
        "/api/migration-center/uploads",
        data={"archive": (io.BytesIO(b"x"), "payload.php")},
        headers={"X-CSRF-Token": csrf},
        content_type="multipart/form-data",
    )
    assert bad_extension.status_code == 400

    traversal = client.post(
        "/api/migration-center/inspect",
        json={"filename": "../escape.tar.gz"},
        headers={"X-CSRF-Token": csrf},
    )
    assert traversal.status_code == 400

    deleted = client.delete(f"/api/migration-center/uploads/{filename}", headers={"X-CSRF-Token": csrf})
    assert deleted.status_code == 200
    assert not inbox_file.exists()

    admin(step_up=False)
    blocked = client.post(
        "/api/migration-center/normalize",
        json={"filename": "anything.tar.gz", "target_domain": "example.com"},
        headers={"X-CSRF-Token": csrf},
    )
    assert blocked.status_code == 428

print("Nexvary Panel Migration Center control-plane gate: PASS")
