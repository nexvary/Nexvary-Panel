import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-mail-policy-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_MAIL_SOCK"] = str(pathlib.Path(tmp) / "missing-mail.sock")

    from panel import create_app
    from panel.db_layer import db

    app = create_app()
    app.testing = True
    client = app.test_client()
    csrf = "mail-policy-csrf"
    now = int(time.time())

    with db() as conn:
        core = conn.execute("SELECT id,max_mailboxes FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        assert core and int(core["max_mailboxes"]) > 0
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
                     ("mailclient", "operator", "22" * 16, "22" * 32, now))
        conn.execute("INSERT INTO hosting_accounts(username,reseller_owner,primary_domain,package_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                     ("mailclient", "admin", "mailclient.example.com", int(core["id"]), "active", now, now))
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)",
                     ("mailclient", int(core["id"]), now))

    with client.session_transaction() as sess:
        sess.update(auth=True, user="mailclient", role="operator", csrf=csrf)

    r = client.get("/api/mail")
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["provider"]["online"] is False
    assert any(d["domain"] == "mailclient.example.com" and d["email_accounts"] for d in body["available_domains"])
    assert body["mailboxes"] == [] and body["forwarders"] == []

    r = client.post("/api/mail/mailboxes", json={
        "domain": "mailclient.example.com", "localpart": "info",
        "password": "StrongMailPass-2026!", "quota_mb": 512,
    }, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 428, r.data

    with client.session_transaction() as sess:
        sess["step_up_user"] = "mailclient"
        sess["step_up_until"] = now + 300
    r = client.post("/api/mail/mailboxes", json={
        "domain": "outside.example.com", "localpart": "info",
        "password": "StrongMailPass-2026!", "quota_mb": 512,
    }, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 403, r.data

    # Disable email.accounts for the client's package and verify policy reaches the domain catalog and mutations.
    with db() as conn:
        conn.execute("INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,0,?) "
                     "ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=0,updated_at=excluded.updated_at",
                     (int(core["id"]), "email.accounts", now))
    r = client.get("/api/mail")
    body = r.get_json()
    assert any(d["domain"] == "mailclient.example.com" and not d["email_accounts"] for d in body["available_domains"])
    r = client.post("/api/mail/mailboxes", json={
        "domain": "mailclient.example.com", "localpart": "info",
        "password": "StrongMailPass-2026!", "quota_mb": 512,
    }, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 403, r.data

print("Nexvary Panel Email Center scope, package-policy and Step-Up tests: PASS")
