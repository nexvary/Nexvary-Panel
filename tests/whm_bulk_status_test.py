from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-whm-bulk-status-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_whm_bulk as routes

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "bulk-status-csrf"
    calls: list[tuple[tuple[str, ...], str]] = []
    fail_domain = ""

    def fake_toggle(domains: list[str], desired: str):
        calls.append((tuple(domains), desired))
        if desired == "disable" and fail_domain and fail_domain in domains:
            return False, "injected provider failure"
        return True, ""

    routes._toggle_sites = fake_toggle

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        package_id = int(core["id"])
        for username, domain in (("lifeone", "one.example.test"), ("lifetwo", "two.example.test")):
            conn.execute(
                "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
                (username, "operator", "11" * 16, "22" * 32, now),
            )
            conn.execute(
                "INSERT INTO hosting_accounts(username,reseller_owner,primary_domain,package_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                (username, "admin", domain, package_id, "active", now, now),
            )
            conn.execute(
                "INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)",
                (username, package_id, now),
            )
            conn.execute(
                "INSERT INTO sites(domain,kind,target,enabled,owner,created_at) VALUES(?,?,?,?,?,?)",
                (domain, "php", "", 1, username, now),
            )

    with client.session_transaction() as session:
        session.update(auth=True, user="admin", role="admin", csrf=csrf)

    payload = {"usernames": ["lifeone", "lifetwo"], "status": "suspended"}
    preview = client.post("/api/whm/bulk/status-preview", json=payload, headers={"X-CSRF-Token": csrf})
    assert preview.status_code == 200, preview.data
    p = preview.get_json()["preview"]
    assert p["safe_to_apply"] is True and p["affected_sites"] == 2 and len(p["transitions"]) == 2

    no_step = client.post("/api/whm/bulk/status-apply", json=payload, headers={"X-CSRF-Token": csrf})
    assert no_step.status_code == 428
    with client.session_transaction() as session:
        session["step_up_user"] = "admin"
        session["step_up_until"] = now + 600

    suspended = client.post("/api/whm/bulk/status-apply", json=payload, headers={"X-CSRF-Token": csrf})
    assert suspended.status_code == 200, suspended.data
    body = suspended.get_json()
    assert body["applied"] == 2 and body["affected_sites"] == 2 and body["status"] == "suspended"
    with db() as conn:
        assert {str(row[0]) for row in conn.execute("SELECT status FROM hosting_accounts WHERE username IN ('lifeone','lifetwo')")} == {"suspended"}
        assert {int(row[0]) for row in conn.execute("SELECT enabled FROM users WHERE username IN ('lifeone','lifetwo')")} == {0}
        assert {int(row[0]) for row in conn.execute("SELECT enabled FROM sites WHERE owner IN ('lifeone','lifetwo')")} == {0}
        assert int(conn.execute("SELECT COUNT(*) FROM account_suspension_sites WHERE username IN ('lifeone','lifetwo')").fetchone()[0]) == 2

    activated = client.post(
        "/api/whm/bulk/status-apply",
        json={"usernames": ["lifeone", "lifetwo"], "status": "active"},
        headers={"X-CSRF-Token": csrf},
    )
    assert activated.status_code == 200, activated.data
    with db() as conn:
        assert {str(row[0]) for row in conn.execute("SELECT status FROM hosting_accounts WHERE username IN ('lifeone','lifetwo')")} == {"active"}
        assert {int(row[0]) for row in conn.execute("SELECT enabled FROM users WHERE username IN ('lifeone','lifetwo')")} == {1}
        assert {int(row[0]) for row in conn.execute("SELECT enabled FROM sites WHERE owner IN ('lifeone','lifetwo')")} == {1}
        assert int(conn.execute("SELECT COUNT(*) FROM account_suspension_sites WHERE username IN ('lifeone','lifetwo')").fetchone()[0]) == 0

    # A no-op batch is safe and performs no provider mutation.
    calls_before = len(calls)
    noop = client.post(
        "/api/whm/bulk/status-apply",
        json={"usernames": ["lifeone", "lifetwo"], "status": "active"},
        headers={"X-CSRF-Token": csrf},
    )
    assert noop.status_code == 200 and noop.get_json()["applied"] == 0 and noop.get_json()["unchanged"] == 2
    assert len(calls) == calls_before

    # Inject a failure on the second account. The first account's provider change
    # must be reversed and the database must return to the original active state.
    fail_domain = "two.example.test"
    failed = client.post("/api/whm/bulk/status-apply", json=payload, headers={"X-CSRF-Token": csrf})
    assert failed.status_code == 503, failed.data
    assert any(domains == ("one.example.test",) and desired == "enable" for domains, desired in calls), calls
    with db() as conn:
        assert {str(row[0]) for row in conn.execute("SELECT status FROM hosting_accounts WHERE username IN ('lifeone','lifetwo')")} == {"active"}
        assert {int(row[0]) for row in conn.execute("SELECT enabled FROM users WHERE username IN ('lifeone','lifetwo')")} == {1}
        assert {int(row[0]) for row in conn.execute("SELECT enabled FROM sites WHERE owner IN ('lifeone','lifetwo')")} == {1}
        assert int(conn.execute("SELECT COUNT(*) FROM account_suspension_sites WHERE username IN ('lifeone','lifetwo')").fetchone()[0]) == 0
        audit = conn.execute("SELECT detail FROM audit WHERE action='whm-bulk-account-status-failed' ORDER BY id DESC LIMIT 1").fetchone()
        assert audit and "status=suspended" in str(audit[0])

    duplicate = client.post(
        "/api/whm/bulk/status-preview",
        json={"usernames": ["lifeone", "lifeone"], "status": "suspended"},
        headers={"X-CSRF-Token": csrf},
    )
    assert duplicate.status_code == 400

    with client.session_transaction() as session:
        session.update(auth=True, user="lifeone", role="operator", csrf=csrf, step_up_user="lifeone", step_up_until=now + 600)
    denied = client.post(
        "/api/whm/bulk/status-preview",
        json={"usernames": ["lifeone"], "status": "suspended"},
        headers={"X-CSRF-Token": csrf},
    )
    assert denied.status_code == 403

print("Nexvary Panel WHM bulk account lifecycle gate: PASS")
