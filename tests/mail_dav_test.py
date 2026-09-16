from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

with tempfile.TemporaryDirectory(prefix="nvp-mail-dav-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_DAV_SOCK"] = str(Path(tmp) / "missing-dav.sock")

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_mail as routes_mail
    import panel.routes_mail_dav as routes_mail_dav

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "mail-dav-csrf"
    provider_calls: list[dict] = []
    mail_calls: list[dict] = []

    def fake_dav(payload, timeout=0):
        call = dict(payload)
        provider_calls.append(call)
        if call.get("action") == "status":
            return {"ok": True, "online": True, "engine": "radicale-caldav-carddav", "account_count": 0}
        return {"ok": True, "username": call.get("username", ""), "engine": "radicale-caldav-carddav"}

    def fake_mail(payload, timeout=0):
        mail_calls.append(dict(payload))
        return {"ok": True, "engine": "postfix-dovecot"}

    routes_mail_dav.dav_call = fake_dav
    routes_mail.dav_call = fake_dav
    routes_mail.mail_call = fake_mail

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
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
        conn.execute(
            "INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,1,?)",
            (core_id, "email.calendars_contacts", now),
        )
        cur = conn.execute(
            "INSERT INTO mailboxes(domain,localpart,quota_mb,enabled,owner,created_at,updated_at) VALUES(?,?,1024,1,?,?,?)",
            ("example.com", "calendar", "client01", now, now),
        )
        mailbox_id = int(cur.lastrowid)

    with client.session_transaction() as sess:
        sess.update(auth=True, user="client01", role="operator", csrf=csrf, step_up_user="client01", step_up_until=now + 300)

    r = client.get("/api/mail/dav")
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["provider"]["online"] is True
    assert body["endpoint"] == "/dav/"
    assert body["mailboxes"][0]["address"] == "calendar@example.com"
    assert body["mailboxes"][0]["feature_allowed"] is True

    secret1 = "DavCredential!2026"
    r = client.post(
        "/api/mail/dav/accounts",
        json={"mailbox_id": mailbox_id, "password": secret1},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 201, r.data
    account = r.get_json()["account"]
    account_id = int(account["id"])
    assert account["username"] == "calendar@example.com"
    assert "password" not in account
    assert provider_calls[-1]["action"] == "credential-sync"
    assert provider_calls[-1]["expected_present"] is False
    assert provider_calls[-1]["password"] == secret1

    r = client.post(
        "/api/mail/dav/accounts",
        json={"mailbox_id": mailbox_id, "password": "AnotherCredential!2026"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 409, r.data

    secret2 = "RotatedCredential!2026"
    r = client.put(
        f"/api/mail/dav/accounts/{account_id}",
        json={"password": secret2},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.data
    assert provider_calls[-1]["action"] == "credential-sync"
    assert provider_calls[-1]["expected_present"] is True
    assert provider_calls[-1]["password"] == secret2

    with db() as conn:
        conn.execute(
            "UPDATE hosting_package_features SET enabled=0,updated_at=? WHERE package_id=? AND feature_id='email.calendars_contacts'",
            (now, core_id),
        )
    r = client.put(
        f"/api/mail/dav/accounts/{account_id}",
        json={"password": "BlockedCredential!2026"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 403, r.data
    with db() as conn:
        conn.execute(
            "UPDATE hosting_package_features SET enabled=1,updated_at=? WHERE package_id=? AND feature_id='email.calendars_contacts'",
            (now, core_id),
        )

    with client.session_transaction() as sess:
        sess["step_up_until"] = 0
    r = client.delete(f"/api/mail/dav/accounts/{account_id}", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 428, r.data

    with client.session_transaction() as sess:
        sess["step_up_until"] = now + 300
    r = client.delete(f"/api/mail/dav/accounts/{account_id}", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.data
    assert provider_calls[-1] == {"action": "credential-delete", "username": "calendar@example.com"}

    # Mailbox deletion must revoke a linked DAV credential before the mailbox metadata
    # cascades, otherwise Radicale would retain an orphan login.
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO mailboxes(domain,localpart,quota_mb,enabled,owner,created_at,updated_at) VALUES(?,?,1024,1,?,?,?)",
            ("example.com", "delete-me", "client01", now, now),
        )
        delete_mailbox_id = int(cur.lastrowid)
    r = client.post(
        "/api/mail/dav/accounts",
        json={"mailbox_id": delete_mailbox_id, "password": "DeleteCredential!2026"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 201, r.data
    delete_account_id = int(r.get_json()["account"]["id"])
    provider_calls.clear()
    mail_calls.clear()
    r = client.delete(f"/api/mail/mailboxes/{delete_mailbox_id}", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.data
    assert provider_calls and provider_calls[0] == {"action": "credential-delete", "username": "delete-me@example.com"}
    assert mail_calls and mail_calls[0]["action"] == "mailbox-delete"
    with db() as conn:
        assert conn.execute("SELECT 1 FROM mailboxes WHERE id=?", (delete_mailbox_id,)).fetchone() is None
        assert conn.execute("SELECT 1 FROM mail_dav_accounts WHERE id=?", (delete_account_id,)).fetchone() is None
        details = "\n".join(str(row[0] or "") for row in conn.execute("SELECT detail FROM audit WHERE action LIKE 'dav-account-%'").fetchall())
        assert "calendar@example.com" in details
        assert "delete-me@example.com" in details
        assert secret1 not in details
        assert secret2 not in details
        assert "DeleteCredential!2026" not in details

print("Nexvary Panel Calendars & Contacts control-plane tests: PASS")
