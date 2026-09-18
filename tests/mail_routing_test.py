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

# Provider contract: Local mode claims the domain in virtual_mailbox_domains;
# Remote mode removes that claim only when no local recipient resources remain.
writes: list[dict] = []
reloads: list[bool] = []
rollbacks: list[dict] = []
base_state = {
    "users": {},
    "domains": {"clean.example": "OK", "occupied.example": "OK"},
    "boxes": {"user@occupied.example": "occupied.example/user/"},
    "aliases": {},
}
mail_agent._backend._snapshot = lambda: {key: dict(value) for key, value in base_state.items()}
mail_agent._backend._write_state = lambda state: writes.append({key: dict(value) for key, value in state.items()})
mail_agent._backend._reload = lambda: reloads.append(True)
mail_agent._backend._rollback = lambda snapshot: rollbacks.append(snapshot)

result = mail_agent._routing_sync("clean.example", "remote")
assert result == {"ok": True, "domain": "clean.example", "mode": "remote"}
assert "clean.example" not in writes[-1]["domains"]
assert reloads

result = mail_agent._routing_sync("clean.example", "local")
assert result["ok"] is True and writes[-1]["domains"]["clean.example"] == "OK"

try:
    mail_agent._routing_sync("occupied.example", "remote")
    raise AssertionError("remote routing accepted a domain with local mailbox resources")
except RuntimeError as exc:
    assert str(exc) == "routing-conflict-local-resources"

alias_state = {
    "users": {},
    "domains": {"alias.example": "OK"},
    "boxes": {},
    "aliases": {"sales@alias.example": "archive@external.example"},
}
mail_agent._backend._snapshot = lambda: {key: dict(value) for key, value in alias_state.items()}
try:
    mail_agent._routing_sync("alias.example", "remote")
    raise AssertionError("remote routing accepted a domain with local aliases")
except RuntimeError as exc:
    assert str(exc) == "routing-conflict-local-resources"

rollback_state = {
    "users": {},
    "domains": {"rollback.example": "OK"},
    "boxes": {},
    "aliases": {},
}
mail_agent._backend._snapshot = lambda: {key: dict(value) for key, value in rollback_state.items()}

def fail_reload():
    raise RuntimeError("reload-failed")

mail_agent._backend._reload = fail_reload
try:
    mail_agent._routing_sync("rollback.example", "remote")
    raise AssertionError("provider reload failure was ignored")
except RuntimeError:
    pass
assert rollbacks, "provider source maps were not rolled back"

# Control-plane policy / ownership / step-up contract.
with tempfile.TemporaryDirectory(prefix="nvp-mail-routing-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_mail_security as routes_mail_security

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "mail-routing-csrf"
    provider_calls: list[dict] = []

    def fake_mail(payload, timeout=0):
        provider_calls.append(dict(payload))
        return {
            "ok": True,
            "domain": payload.get("domain", ""),
            "mode": payload.get("mode", "local"),
        }

    routes_mail_security.mail_call = fake_mail

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
            (core_id, "email.routing", now),
        )

    with client.session_transaction() as sess:
        sess.update(auth=True, user="client01", role="operator", csrf=csrf, step_up_user="client01", step_up_until=now + 300)

    r = client.get("/api/mail/routing?domain=example.com")
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["feature_allowed"] is True
    assert body["routing"]["mode"] == "local"
    assert body["local_resources"] == {"mailboxes": 0, "forwarders": 0, "catchall_forward": False}

    r = client.put(
        "/api/mail/routing",
        json={"domain": "example.com", "mode": "remote"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.data
    assert provider_calls[-1] == {"action": "routing-sync", "domain": "example.com", "mode": "remote"}
    with db() as conn:
        row = conn.execute("SELECT mode,owner FROM mail_routing_policies WHERE domain='example.com'").fetchone()
        assert row and row["mode"] == "remote" and row["owner"] == "client01"

    r = client.put(
        "/api/mail/routing",
        json={"domain": "example.com", "mode": "local"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.data
    assert provider_calls[-1]["mode"] == "local"

    with db() as conn:
        conn.execute(
            "INSERT INTO mailboxes(domain,localpart,quota_mb,enabled,owner,created_at,updated_at) VALUES(?,?,1024,1,?,?,?)",
            ("example.com", "info", "client01", now, now),
        )
    before = len(provider_calls)
    r = client.put(
        "/api/mail/routing",
        json={"domain": "example.com", "mode": "remote"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 409, r.data
    assert r.get_json()["local_resources"]["mailboxes"] == 1
    assert len(provider_calls) == before

    with db() as conn:
        conn.execute("DELETE FROM mailboxes WHERE domain='example.com'")
        conn.execute(
            "UPDATE hosting_package_features SET enabled=0,updated_at=? WHERE package_id=? AND feature_id='email.routing'",
            (now, core_id),
        )
    r = client.put(
        "/api/mail/routing",
        json={"domain": "example.com", "mode": "remote"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 403, r.data

    with db() as conn:
        conn.execute(
            "UPDATE hosting_package_features SET enabled=1,updated_at=? WHERE package_id=? AND feature_id='email.routing'",
            (now, core_id),
        )
    with client.session_transaction() as sess:
        sess["step_up_until"] = 0
    r = client.put(
        "/api/mail/routing",
        json={"domain": "example.com", "mode": "remote"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 428, r.data

    with db() as conn:
        details = "\n".join(str(row[0] or "") for row in conn.execute("SELECT detail FROM audit WHERE action='mail-routing'").fetchall())
        assert "domain=example.com" in details
        assert "mode=remote" in details

print("Nexvary Panel email-routing provider/policy/step-up tests: PASS")
