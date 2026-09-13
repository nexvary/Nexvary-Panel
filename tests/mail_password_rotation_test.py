from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-mail-password-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_MAIL_SOCK"] = str(pathlib.Path(tmp) / "missing-mail.sock")

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_mail_security as routes

    app = create_app()
    app.testing = True
    client = app.test_client()
    csrf = "mail-password-csrf"
    now = int(time.time())
    secret = "RotatedMailPass-2026!"
    calls: list[dict] = []

    def fake_mail(payload, timeout=35):
        calls.append(dict(payload))
        return {"ok": True, "address": payload.get("address", "")}

    routes.mail_call = fake_mail

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        pid = int(core["id"])
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)", ("mailclient", "operator", "22"*16, "22"*32, now))
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)", ("mailclient", pid, now))
        conn.execute("INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)", ("mailclient.example.com", "php", "", None, "mailclient", now))
        conn.execute("INSERT INTO mail_domains(domain,owner,enabled,created_at,updated_at) VALUES(?,?,1,?,?)", ("mailclient.example.com", "mailclient", now, now))
        conn.execute("INSERT INTO mailboxes(domain,localpart,quota_mb,enabled,owner,created_at,updated_at) VALUES(?,?,512,1,?,?,?)", ("mailclient.example.com", "info", "mailclient", now, now))
        own_id = int(conn.execute("SELECT id FROM mailboxes WHERE owner='mailclient'").fetchone()[0])
        conn.execute("INSERT INTO mail_domains(domain,owner,enabled,created_at,updated_at) VALUES(?,?,1,?,?)", ("adminmail.example.com", "admin", now, now))
        conn.execute("INSERT INTO mailboxes(domain,localpart,quota_mb,enabled,owner,created_at,updated_at) VALUES(?,?,512,1,?,?,?)", ("adminmail.example.com", "adminbox", "admin", now, now))
        other_id = int(conn.execute("SELECT id FROM mailboxes WHERE owner='admin'").fetchone()[0])

    with client.session_transaction() as sess:
        sess.update(auth=True, user="mailclient", role="operator", csrf=csrf)

    no_step = client.put(f"/api/mail/mailboxes/{own_id}/password", json={"password": secret}, headers={"X-CSRF-Token": csrf})
    assert no_step.status_code == 428
    assert calls == []

    with client.session_transaction() as sess:
        sess["step_up_user"] = "mailclient"
        sess["step_up_until"] = now + 600

    weak = client.put(f"/api/mail/mailboxes/{own_id}/password", json={"password":"short"}, headers={"X-CSRF-Token": csrf})
    assert weak.status_code == 400 and calls == []

    denied = client.put(f"/api/mail/mailboxes/{other_id}/password", json={"password": secret}, headers={"X-CSRF-Token": csrf})
    assert denied.status_code == 403 and calls == []

    rotated = client.put(f"/api/mail/mailboxes/{own_id}/password", json={"password": secret}, headers={"X-CSRF-Token": csrf})
    assert rotated.status_code == 200, rotated.data
    body = rotated.get_json()
    assert body["rotated"] is True and body["address"] == "info@mailclient.example.com"
    assert "password" not in body
    assert calls[-1] == {"action":"mailbox-upsert","address":"info@mailclient.example.com","password":secret}
    with db() as conn:
        updated = int(conn.execute("SELECT updated_at FROM mailboxes WHERE id=?", (own_id,)).fetchone()[0])
        assert updated >= now
        details = "\n".join(str(r[0] or "") for r in conn.execute("SELECT detail FROM audit WHERE action='mailbox-password-rotate'").fetchall())
        assert secret not in details and "RotatedMailPass" not in details

    with db() as conn:
        conn.execute("INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,0,?) ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=0,updated_at=excluded.updated_at", (pid, "email.accounts", now))
    before = len(calls)
    blocked = client.put(f"/api/mail/mailboxes/{own_id}/password", json={"password": secret}, headers={"X-CSRF-Token": csrf})
    assert blocked.status_code == 403 and len(calls) == before

print("Nexvary Panel mailbox password rotation gate: PASS")
