from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-mail-import-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_mail_import as routes_mail_import

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "mail-import-csrf"
    provider_calls: list[dict] = []
    fail_forwarder = False

    def fake_mail(payload, timeout=0):
        provider_calls.append(dict(payload))
        if fail_forwarder and payload.get("action") == "forwarder-upsert":
            return {"ok": False, "error": "synthetic-provider-failure"}
        return {"ok": True}

    routes_mail_import.mail_call = fake_mail

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        assert core, "NEXVARY Core package missing"
        core_id = int(core["id"])
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("client01", "operator", "11" * 16, "22" * 32, now),
        )
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)", ("client01", core_id, now))
        conn.execute(
            "INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",
            ("example.com", "static", "", None, "client01", now),
        )
        for feature_id in ("email.accounts", "email.forwarders", "email.address_importer"):
            conn.execute("DELETE FROM hosting_package_features WHERE package_id=? AND feature_id=?", (core_id, feature_id))
            conn.execute(
                "INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,1,?)",
                (core_id, feature_id, now),
            )

    with client.session_transaction() as sess:
        sess.update(auth=True, user="client01", role="operator", csrf=csrf, step_up_user="client01", step_up_until=now + 300)

    payload = {
        "domain": "example.com",
        "entries": [
            {"kind": "mailbox", "localpart": "alice", "password": "Nexvary-Test-Password-2026!", "quota_mb": 1024},
            {"kind": "forwarder", "localpart": "sales", "destination": "sales@external.example"},
        ],
    }
    r = client.post("/api/mail/import", json=payload, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 201, r.data
    body = r.get_json()
    assert body["ok"] is True and body["imported"] == 2 and body["mailboxes"] == 1 and body["forwarders"] == 1
    assert [call["action"] for call in provider_calls[-2:]] == ["mailbox-upsert", "forwarder-upsert"]
    with db() as conn:
        box = conn.execute("SELECT quota_mb,owner FROM mailboxes WHERE domain='example.com' AND localpart='alice'").fetchone()
        fwd = conn.execute("SELECT destination,owner FROM mail_forwarders WHERE domain='example.com' AND localpart='sales'").fetchone()
        assert box and int(box["quota_mb"]) == 1024 and box["owner"] == "client01"
        assert fwd and fwd["destination"] == "sales@external.example" and fwd["owner"] == "client01"
        audit_rows = conn.execute("SELECT detail FROM audit WHERE action='mail-address-import'").fetchall()
        details = "\n".join(str(row[0] or "") for row in audit_rows)
        assert "Nexvary-Test-Password-2026!" not in details
        assert "sales@external.example" not in details
        assert "domain=example.com" in details and "entries=2" in details

    before = len(provider_calls)
    r = client.post(
        "/api/mail/import",
        json={
            "domain": "example.com",
            "entries": [
                {"kind": "forwarder", "localpart": "dup", "destination": "one@external.example"},
                {"kind": "forwarder", "localpart": "dup", "destination": "two@external.example"},
            ],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 400, r.data
    assert len(provider_calls) == before, "duplicate payload reached provider"

    with db() as conn:
        conn.execute(
            "UPDATE hosting_package_features SET enabled=0,updated_at=? WHERE package_id=? AND feature_id='email.address_importer'",
            (now, core_id),
        )
    r = client.post(
        "/api/mail/import",
        json={"domain": "example.com", "entries": [{"kind": "forwarder", "localpart": "blocked", "destination": "ok@external.example"}]},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 403, r.data

    with db() as conn:
        conn.execute(
            "UPDATE hosting_package_features SET enabled=1,updated_at=? WHERE package_id=? AND feature_id='email.address_importer'",
            (now, core_id),
        )
    with client.session_transaction() as sess:
        sess["step_up_until"] = 0
    r = client.post(
        "/api/mail/import",
        json={"domain": "example.com", "entries": [{"kind": "forwarder", "localpart": "needsstepup", "destination": "ok@external.example"}]},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 428, r.data

    with client.session_transaction() as sess:
        sess["step_up_until"] = now + 300
    provider_calls.clear()
    fail_forwarder = True
    r = client.post(
        "/api/mail/import",
        json={
            "domain": "example.com",
            "entries": [
                {"kind": "mailbox", "localpart": "rollbackbox", "password": "Nexvary-Rollback-Password-2026!", "quota_mb": 512},
                {"kind": "forwarder", "localpart": "rollbackfwd", "destination": "target@external.example"},
            ],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 502, r.data
    body = r.get_json()
    assert body["rolled_back"] is True and body["failed_source"] == "rollbackfwd@example.com"
    actions = [call["action"] for call in provider_calls]
    assert actions == ["mailbox-upsert", "forwarder-upsert", "mailbox-delete"], actions
    with db() as conn:
        assert conn.execute("SELECT 1 FROM mailboxes WHERE domain='example.com' AND localpart='rollbackbox'").fetchone() is None
        assert conn.execute("SELECT 1 FROM mail_forwarders WHERE domain='example.com' AND localpart='rollbackfwd'").fetchone() is None

print("Nexvary Panel address importer policy/Step-Up/rollback/audit tests: PASS")
