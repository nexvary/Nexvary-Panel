from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-mail-auto-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_MAIL_SOCK"] = str(pathlib.Path(tmp) / "missing-mail.sock")

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_mail_automation as routes

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "mail-auto-csrf"

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        pid = int(core["id"])
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("mailclient", "operator", "11" * 16, "22" * 32, now),
        )
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)", ("mailclient", pid, now))
        for feature in ("email.autoresponders", "email.filters", "email.spam_filters"):
            conn.execute(
                "INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,1,?)",
                (pid, feature, now),
            )
        conn.execute(
            "INSERT INTO mail_domains(domain,owner,enabled,created_at,updated_at) VALUES(?,?,1,?,?)",
            ("example.test", "mailclient", now, now),
        )
        cur = conn.execute(
            "INSERT INTO mailboxes(domain,localpart,quota_mb,enabled,owner,created_at,updated_at) VALUES(?,?,1024,1,?,?,?)",
            ("example.test", "info", "mailclient", now, now),
        )
        mailbox_id = int(cur.lastrowid)
        cur = conn.execute(
            "INSERT INTO mailboxes(domain,localpart,quota_mb,enabled,owner,created_at,updated_at) VALUES(?,?,1024,1,?,?,?)",
            ("example.test", "adminbox", "admin", now, now),
        )
        admin_box = int(cur.lastrowid)

    calls = []
    def fake_mail(payload, timeout=35):
        calls.append(payload)
        return {"ok": True}
    routes.mail_call = fake_mail

    with client.session_transaction() as sess:
        sess.update(auth=True, user="mailclient", role="operator", csrf=csrf)

    r = client.get(f"/api/mail/automation/{mailbox_id}")
    assert r.status_code == 200, r.data
    features = r.get_json()["features"]
    assert features == {"autoresponders": True, "filters": True, "spam_filters": True, "global_filters": False}

    r = client.post(
        f"/api/mail/automation/{mailbox_id}/filters",
        json={"field": "subject", "match_type": "contains", "pattern": "invoice", "action": "fileinto", "destination": "Billing", "priority": 100},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 428, r.data

    with client.session_transaction() as sess:
        sess["step_up_user"] = "mailclient"
        sess["step_up_until"] = now + 600

    r = client.post(
        f"/api/mail/automation/{mailbox_id}/filters",
        json={"field": "subject", "match_type": "contains", "pattern": "invoice", "action": "fileinto", "destination": "Billing", "priority": 100},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 201, r.data
    filter_id = int(r.get_json()["filter_id"])
    assert calls[-1]["action"] == "sieve-sync"
    assert calls[-1]["address"] == "info@example.test"
    assert calls[-1]["global_filters"] == []
    assert "password" not in str(calls[-1]).lower()

    r = client.put(
        f"/api/mail/automation/{mailbox_id}/autoresponder",
        json={"enabled": True, "subject": "Out of office", "body": "We will reply soon.", "interval_days": 2},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.data
    assert r.get_json()["autoresponder"]["enabled"] == 1

    r = client.put(
        f"/api/mail/automation/{mailbox_id}/spam",
        json={"enabled": True, "action": "junk"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.data

    r = client.post(
        f"/api/mail/automation/{mailbox_id}/filters",
        json={"field": "from", "match_type": "contains", "pattern": "bad", "action": "redirect", "destination": "not-an-email"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 400, r.data

    r = client.get(f"/api/mail/automation/{admin_box}")
    assert r.status_code == 404, r.data

    r = client.delete(f"/api/mail/automation/filters/{filter_id}", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.data

    with db() as conn:
        conn.execute(
            "UPDATE hosting_package_features SET enabled=0,updated_at=? WHERE package_id=? AND feature_id='email.filters'",
            (now + 1, pid),
        )
    r = client.post(
        f"/api/mail/automation/{mailbox_id}/filters",
        json={"field": "subject", "match_type": "is", "pattern": "blocked", "action": "discard"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 403, r.data

    with db() as conn:
        details = " ".join(str(row[0]) for row in conn.execute("SELECT detail FROM audit").fetchall())
        assert "We will reply soon" not in details
        assert "Out of office" not in details

print("Nexvary Panel mail automation policy gate: PASS")
