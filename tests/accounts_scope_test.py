import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-account-scope-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db

    app = create_app()
    app.testing = True
    client = app.test_client()
    csrf = "account-scope-csrf"
    now = int(time.time())

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        unlimited = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Unlimited'").fetchone()
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
                     ("partner01", "reseller", "00" * 16, "00" * 32, now))
        conn.execute("INSERT INTO reseller_profiles(username,max_accounts,enabled,created_at,updated_at) VALUES(?,?,1,?,?)",
                     ("partner01", 1, now, now))
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
                     ("client01", "operator", "11" * 16, "11" * 32, now))
        conn.execute("INSERT INTO hosting_accounts(username,reseller_owner,primary_domain,package_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                     ("client01", "partner01", "client01.example.com", int(core["id"]), "active", now, now))
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)",
                     ("client01", int(core["id"]), now))

    with client.session_transaction() as sess:
        sess.update(auth=True, user="partner01", role="reseller", csrf=csrf,
                    step_up_user="partner01", step_up_until=now + 300)

    r = client.get("/api/accounts")
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["account_limit"] == 1
    assert len(body["accounts"]) == 1 and body["accounts"][0]["username"] == "client01"
    assert all(p["name"] != "NEXVARY Unlimited" for p in body["packages"])

    r = client.put("/api/accounts/client01/package", json={"package_id": int(unlimited["id"])}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 403, r.data

    with client.session_transaction() as sess:
        sess["step_up_until"] = 0
    r = client.put("/api/accounts/client01/status", json={"status": "suspended"}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 428, r.data

    with client.session_transaction() as sess:
        sess["step_up_until"] = now + 300
    r = client.put("/api/accounts/client01/status", json={"status": "suspended"}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.data
    assert r.get_json()["scope"] == "control-plane"

    with db() as conn:
        user = conn.execute("SELECT enabled FROM users WHERE username='client01'").fetchone()
        account = conn.execute("SELECT status FROM hosting_accounts WHERE username='client01'").fetchone()
    assert int(user["enabled"]) == 0
    assert account["status"] == "suspended"

print("Nexvary Panel Account/Reseller scope, Step-Up and anti-escalation tests: PASS")
