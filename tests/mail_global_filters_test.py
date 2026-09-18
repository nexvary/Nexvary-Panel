from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))

import mail_sieve

# Provider-side generation: global rules are emitted before mailbox rules and
# generic headers are validated rather than accepting free-form Sieve.
global_rules = mail_sieve._normalize_filters(
    [
        {
            "field": "header",
            "header_name": "X-Campaign-ID",
            "match_type": "contains",
            "pattern": "vip",
            "action": "fileinto",
            "destination": "Global",
            "priority": 5,
            "enabled": 1,
        }
    ],
    global_scope=True,
)
script = mail_sieve._build_script(
    "info@example.com",
    {"enabled": False, "subject": "", "body": "", "interval_days": 1},
    [],
    {"enabled": False, "action": "junk"},
    global_rules,
)
assert "# Account-wide global filters" in script
assert 'header :contains "X-Campaign-ID" "vip"' in script
assert 'fileinto :create "Global";' in script

try:
    mail_sieve._normalize_filters(
        [{"field": "header", "header_name": "Bad Header", "match_type": "is", "pattern": "x", "action": "discard", "priority": 1}],
        global_scope=True,
    )
    raise AssertionError("unsafe global header name accepted")
except ValueError:
    pass

with tempfile.TemporaryDirectory(prefix="nvp-mail-global-filters-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db
    from panel.hosting_features import FEATURES
    import panel.routes_mail_global_filters as routes_global

    assert FEATURES["email.global_filters"].maturity == "foundation"

    app = create_app()
    app.testing = True
    client = app.test_client()
    csrf = "global-filter-csrf"
    now = int(time.time())
    provider_calls: list[dict] = []
    fail_once = {"enabled": False, "seen": 0}

    def fake_mail(payload, timeout=0):
        snapshot = dict(payload)
        snapshot["global_filters"] = [dict(item) for item in payload.get("global_filters", [])]
        snapshot["global_domains"] = list(payload.get("global_domains", []))
        provider_calls.append(snapshot)
        if fail_once["enabled"] and payload.get("action") == "sieve-sync":
            fail_once["seen"] += 1
            if fail_once["seen"] == 2:
                fail_once["enabled"] = False
                return {"ok": False, "error": "simulated-sieve-failure"}
        return {"ok": True, "global_filters": len(payload.get("global_filters", []))}

    routes_global.mail_call = fake_mail

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        core_id = int(core["id"])
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("client01", "operator", "11" * 16, "22" * 32, now),
        )
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)", ("client01", core_id, now))
        conn.execute(
            "INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,1,?)",
            (core_id, "email.global_filters", now),
        )
        for domain in ("example.com", "second.example"):
            conn.execute(
                "INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",
                (domain, "static", "", None, "client01", now),
            )
        conn.execute(
            "INSERT INTO mailboxes(domain,localpart,quota_mb,enabled,owner,created_at,updated_at) VALUES(?,?,1024,1,?,?,?)",
            ("example.com", "info", "client01", now, now),
        )
        conn.execute(
            "INSERT INTO mailboxes(domain,localpart,quota_mb,enabled,owner,created_at,updated_at) VALUES(?,?,1024,1,?,?,?)",
            ("second.example", "sales", "client01", now, now),
        )

    with client.session_transaction() as sess:
        sess.update(auth=True, user="client01", role="operator", csrf=csrf, step_up_user="client01", step_up_until=now + 300)

    r = client.get("/api/mail/global-filters?domain=example.com")
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["feature_allowed"] is True
    assert body["owner"] == "client01"
    assert body["scope"] == "account"
    assert set(body["owner_domains"]) == {"example.com", "second.example"}
    assert body["mailbox_count"] == 2

    create_payload = {
        "domain": "example.com",
        "field": "header",
        "header_name": "X-Campaign-ID",
        "match_type": "contains",
        "pattern": "vip",
        "action": "fileinto",
        "destination": "Global",
        "priority": 10,
        "enabled": True,
    }
    before = len(provider_calls)
    r = client.post("/api/mail/global-filters", json=create_payload, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 201, r.data
    filter_id = int(r.get_json()["filter_id"])
    sync_calls = provider_calls[before:]
    assert len(sync_calls) == 2, sync_calls
    assert all(call["action"] == "sieve-sync" for call in sync_calls)
    assert all(call["global_filters"][0]["header_name"] == "X-Campaign-ID" for call in sync_calls)
    assert all(set(call["global_domains"]) == {"example.com", "second.example"} for call in sync_calls)

    r = client.put(
        f"/api/mail/global-filters/{filter_id}",
        json={
            "field": "subject",
            "header_name": "",
            "match_type": "contains",
            "pattern": "billing",
            "action": "redirect",
            "destination": "archive@external.example",
            "priority": 20,
            "enabled": True,
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.data
    assert r.get_json()["filters"][0]["destination"] == "archive@external.example"

    before = len(provider_calls)
    r = client.post(
        "/api/mail/global-filters",
        json={
            "domain": "example.com",
            "field": "from",
            "match_type": "contains",
            "pattern": "alerts",
            "action": "redirect",
            "destination": "loop@second.example",
            "priority": 30,
            "enabled": True,
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 400, r.data
    assert len(provider_calls) == before, "same-account redirect reached provider"

    # A failure while applying the second mailbox must roll metadata back and
    # resync already-touched mailboxes using the previous rule set.
    fail_once.update(enabled=True, seen=0)
    before = len(provider_calls)
    r = client.post(
        "/api/mail/global-filters",
        json={
            "domain": "example.com",
            "field": "subject",
            "match_type": "is",
            "pattern": "temporary",
            "action": "discard",
            "destination": "",
            "priority": 40,
            "enabled": True,
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 503, r.data
    failed_body = r.get_json()
    assert failed_body["rolled_back"] is True and failed_body["rollback_failed"] == [], failed_body
    with db() as conn:
        rows = conn.execute("SELECT id,pattern FROM mail_global_filters WHERE owner='client01' ORDER BY id").fetchall()
        assert len(rows) == 1 and rows[0]["pattern"] == "billing", rows
    rollback_calls = provider_calls[before:]
    assert len(rollback_calls) == 3, rollback_calls
    assert len(rollback_calls[-1]["global_filters"]) == 1
    assert rollback_calls[-1]["global_filters"][0]["pattern"] == "billing"

    with client.session_transaction() as sess:
        sess["step_up_until"] = 0
    r = client.delete(f"/api/mail/global-filters/{filter_id}", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 428, r.data

    with client.session_transaction() as sess:
        sess["step_up_until"] = now + 300
    r = client.delete(f"/api/mail/global-filters/{filter_id}", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.data
    assert r.get_json()["filters"] == []

    with db() as conn:
        details = "\n".join(str(row[0] or "") for row in conn.execute("SELECT detail FROM audit WHERE action LIKE 'mail-global-filter-%'").fetchall())
        assert "owner=client01" in details
        assert "mailboxes=2" in details

print("Nexvary Panel account-wide global email filters policy/provider rollback tests: PASS")
