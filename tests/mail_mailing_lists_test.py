from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))

import mail_agent

# Provider contract: distribution aliases are optimistic, bounded and rollback-safe.
writes: list[dict] = []
reloads: list[bool] = []
rollbacks: list[dict] = []
state = {
    "users": {},
    "domains": {"example.com": "OK"},
    "boxes": {},
    "aliases": {},
}
mail_agent._backend._snapshot = lambda: {key: dict(value) for key, value in state.items()}
mail_agent._backend._write_state = lambda value: writes.append({key: dict(items) for key, items in value.items()})
mail_agent._backend._reload = lambda: reloads.append(True)
mail_agent._backend._rollback = lambda snapshot: rollbacks.append(snapshot)

created = mail_agent._mailing_list_sync(
    "team@example.com",
    ["alice@external.example", "bob@external.example"],
    [],
)
assert created == {"ok": True, "address": "team@example.com", "member_count": 2}
assert writes[-1]["aliases"]["team@example.com"] == "alice@external.example,bob@external.example"
assert reloads

state["aliases"]["team@example.com"] = "alice@external.example,bob@external.example"
updated = mail_agent._mailing_list_sync(
    "team@example.com",
    ["alice@external.example", "carol@external.example"],
    ["alice@external.example", "bob@external.example"],
)
assert updated["member_count"] == 2
assert writes[-1]["aliases"]["team@example.com"] == "alice@external.example,carol@external.example"

try:
    mail_agent._mailing_list_sync(
        "team@example.com",
        ["alice@external.example"],
        ["wrong@external.example"],
    )
    raise AssertionError("provider optimistic conflict was accepted")
except RuntimeError as exc:
    assert str(exc) == "mailing-list-provider-conflict"

try:
    mail_agent._mailing_list_sync("loop@example.com", ["loop@example.com"], [])
    raise AssertionError("self-looping distribution list was accepted")
except ValueError as exc:
    assert str(exc) == "mailing-list-self-loop"

state["aliases"].pop("team@example.com", None)
state["boxes"]["occupied@example.com"] = "example.com/occupied/"
try:
    mail_agent._mailing_list_sync("occupied@example.com", ["alice@external.example"], [])
    raise AssertionError("distribution list overwrote mailbox source")
except RuntimeError as exc:
    assert str(exc) == "mailing-list-address-conflict"
state["boxes"].clear()

state["aliases"]["team@example.com"] = "alice@external.example,carol@external.example"
deleted = mail_agent._mailing_list_sync(
    "team@example.com",
    [],
    ["alice@external.example", "carol@external.example"],
)
assert deleted["member_count"] == 0
assert "team@example.com" not in writes[-1]["aliases"]

rollback_state = {
    "users": {}, "domains": {"rollback.example": "OK"}, "boxes": {}, "aliases": {}
}
mail_agent._backend._snapshot = lambda: {key: dict(value) for key, value in rollback_state.items()}

def fail_reload():
    raise RuntimeError("reload-failed")

mail_agent._backend._reload = fail_reload
try:
    mail_agent._mailing_list_sync("team@rollback.example", ["one@external.example"], [])
    raise AssertionError("provider reload failure was ignored")
except RuntimeError:
    pass
assert rollbacks, "distribution-list provider failed to rollback"

# Control-plane lifecycle: ownership, feature policy, local routing, cycle prevention and audit.
with tempfile.TemporaryDirectory(prefix="nvp-mail-lists-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_mail_lists as routes_mail_lists

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "mail-lists-csrf"
    provider_calls: list[dict] = []

    def fake_mail(payload, timeout=0):
        provider_calls.append(dict(payload))
        return {"ok": True, "address": payload.get("address", ""), "member_count": len(payload.get("members", []))}

    routes_mail_lists.mail_call = fake_mail

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
            (core_id, "email.mailing_lists", now),
        )

    with client.session_transaction() as sess:
        sess.update(auth=True, user="client01", role="operator", csrf=csrf, step_up_user="client01", step_up_until=now + 300)

    r = client.get("/api/mail/mailing-lists")
    assert r.status_code == 200, r.data
    assert r.get_json()["mailing_lists"] == []

    r = client.post(
        "/api/mail/mailing-lists",
        json={"domain": "example.com", "localpart": "team", "members": ["Alice@external.example", "bob@external.example"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 201, r.data
    team = r.get_json()["mailing_list"]
    team_id = int(team["id"])
    assert team["members"] == ["alice@external.example", "bob@external.example"]
    assert provider_calls[-1]["action"] == "mailing-list-sync"
    assert provider_calls[-1]["expected_members"] == []

    r = client.put(
        f"/api/mail/mailing-lists/{team_id}",
        json={"members": ["alice@external.example", "carol@external.example"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.data
    assert provider_calls[-1]["expected_members"] == ["alice@external.example", "bob@external.example"]

    # Create a second list and reject an indirect delivery cycle.
    r = client.post(
        "/api/mail/mailing-lists",
        json={"domain": "example.com", "localpart": "ops", "members": ["team@example.com"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 201, r.data
    ops_id = int(r.get_json()["mailing_list"]["id"])
    before = len(provider_calls)
    r = client.put(
        f"/api/mail/mailing-lists/{team_id}",
        json={"members": ["ops@example.com"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 409, r.data
    assert "loop" in r.get_json()["error"]
    assert len(provider_calls) == before

    # Existing mailbox/forwarder sources cannot be replaced by a list.
    with db() as conn:
        conn.execute(
            "INSERT INTO mailboxes(domain,localpart,quota_mb,enabled,owner,created_at,updated_at) VALUES(?,?,1024,1,?,?,?)",
            ("example.com", "box", "client01", now, now),
        )
    r = client.post(
        "/api/mail/mailing-lists",
        json={"domain": "example.com", "localpart": "box", "members": ["one@external.example"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 409, r.data

    # Remote routing must block local distribution aliases.
    with db() as conn:
        conn.execute("DELETE FROM mailboxes WHERE domain='example.com' AND localpart='box'")
        conn.execute(
            "INSERT INTO mail_routing_policies(domain,mode,owner,updated_at) VALUES(?,?,?,?) ON CONFLICT(domain) DO UPDATE SET mode=excluded.mode,owner=excluded.owner,updated_at=excluded.updated_at",
            ("example.com", "remote", "client01", now),
        )
    r = client.post(
        "/api/mail/mailing-lists",
        json={"domain": "example.com", "localpart": "remote", "members": ["one@external.example"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 409, r.data
    with db() as conn:
        conn.execute("UPDATE mail_routing_policies SET mode='local' WHERE domain='example.com'")

    # Feature gate and Step-Up are both mandatory.
    with db() as conn:
        conn.execute(
            "UPDATE hosting_package_features SET enabled=0,updated_at=? WHERE package_id=? AND feature_id='email.mailing_lists'",
            (now, core_id),
        )
    r = client.delete(f"/api/mail/mailing-lists/{ops_id}", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 403, r.data
    with db() as conn:
        conn.execute(
            "UPDATE hosting_package_features SET enabled=1,updated_at=? WHERE package_id=? AND feature_id='email.mailing_lists'",
            (now, core_id),
        )
    with client.session_transaction() as sess:
        sess["step_up_until"] = 0
    r = client.delete(f"/api/mail/mailing-lists/{ops_id}", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 428, r.data

    with client.session_transaction() as sess:
        sess["step_up_until"] = now + 300
    r = client.delete(f"/api/mail/mailing-lists/{ops_id}", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.data

    with db() as conn:
        details = "\n".join(str(row[0] or "") for row in conn.execute("SELECT detail FROM audit WHERE action LIKE 'mailing-list-%'").fetchall())
        assert "address=team@example.com" in details
        assert "alice@external.example" not in details
        assert "carol@external.example" not in details

print("Nexvary Panel mailing-list provider/control-plane tests: PASS")
