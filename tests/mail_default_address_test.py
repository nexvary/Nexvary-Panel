from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))

# Provider contract: @domain is the only catch-all map key and all writes remain rollbackable.
import mail_default

writes: list[dict] = []
reloads: list[bool] = []
rollbacks: list[dict] = []
base_state = {
    "users": {"known@example.com": "hash"},
    "domains": {"example.com": "OK"},
    "boxes": {"known@example.com": "example.com/known/"},
    "aliases": {"sales@example.com": "sales@external.net", "@example.com": "old@external.net"},
}
mail_default._snapshot = lambda: {key: dict(value) for key, value in base_state.items()}
mail_default._write_state = lambda state: writes.append({key: dict(value) for key, value in state.items()})
mail_default._reload = lambda: reloads.append(True)
mail_default._rollback = lambda snapshot: rollbacks.append(snapshot)

result = mail_default.default_address_sync("example.com", "forward", "catch@external.net")
assert result == {"ok": True, "domain": "example.com", "mode": "forward", "destination": "catch@external.net"}
assert writes[-1]["aliases"]["@example.com"] == "catch@external.net"
assert writes[-1]["aliases"]["sales@example.com"] == "sales@external.net"
assert reloads

result = mail_default.default_address_sync("example.com", "reject", "")
assert result["ok"] is True and result["mode"] == "reject"
assert "@example.com" not in writes[-1]["aliases"]
try:
    mail_default.default_address_sync("example.com", "forward", "loop@example.com")
    raise AssertionError("same-domain catch-all loop was accepted")
except ValueError as exc:
    assert str(exc) == "catchall-loop-risk"

# Provider failure restores the previous source maps.
def fail_reload():
    raise RuntimeError("reload-failed")
mail_default._reload = fail_reload
try:
    mail_default.default_address_sync("example.com", "forward", "catch@external.net")
    raise AssertionError("provider reload failure was ignored")
except RuntimeError:
    pass
assert rollbacks, "provider state was not rolled back"

# Control-plane policy / ownership gate.
with tempfile.TemporaryDirectory(prefix="nvp-mail-default-") as tmp:
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
    csrf = "mail-default-csrf"
    provider_calls: list[dict] = []

    def fake_mail(payload, timeout=0):
        provider_calls.append(dict(payload))
        return {"ok": True, "domain": payload.get("domain", ""), "mode": payload.get("mode", "reject"), "destination": payload.get("destination", "")}

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
            (core_id, "email.default_address", now),
        )

    with client.session_transaction() as sess:
        sess.update(auth=True, user="client01", role="operator", csrf=csrf, step_up_user="client01", step_up_until=now + 300)

    r = client.get("/api/mail/default-address?domain=example.com")
    assert r.status_code == 200, r.data
    assert r.get_json()["default_address"]["mode"] == "reject"
    assert r.get_json()["feature_allowed"] is True

    r = client.put(
        "/api/mail/default-address",
        json={"domain": "example.com", "mode": "forward", "destination": "catch@external.net"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.data
    assert provider_calls[-1]["action"] == "default-address-sync"
    assert provider_calls[-1]["mode"] == "forward"
    with db() as conn:
        row = conn.execute("SELECT mode,destination,owner FROM mail_default_addresses WHERE domain='example.com'").fetchone()
        assert row and row["mode"] == "forward" and row["destination"] == "catch@external.net" and row["owner"] == "client01"

    before = len(provider_calls)
    r = client.put(
        "/api/mail/default-address",
        json={"domain": "example.com", "mode": "forward", "destination": "loop@example.com"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 400, r.data
    assert len(provider_calls) == before

    with db() as conn:
        conn.execute("UPDATE hosting_package_features SET enabled=0,updated_at=? WHERE package_id=? AND feature_id='email.default_address'", (now, core_id))
    r = client.put(
        "/api/mail/default-address",
        json={"domain": "example.com", "mode": "reject"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 403, r.data

    with db() as conn:
        conn.execute("UPDATE hosting_package_features SET enabled=1,updated_at=? WHERE package_id=? AND feature_id='email.default_address'", (now, core_id))
    with client.session_transaction() as sess:
        sess["step_up_until"] = 0
    r = client.put(
        "/api/mail/default-address",
        json={"domain": "example.com", "mode": "reject"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 428, r.data

    with client.session_transaction() as sess:
        sess["step_up_until"] = now + 300
    r = client.put(
        "/api/mail/default-address",
        json={"domain": "example.com", "mode": "reject"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.data
    assert provider_calls[-1]["mode"] == "reject" and provider_calls[-1]["destination"] == ""

    with db() as conn:
        details = "\n".join(str(row[0] or "") for row in conn.execute("SELECT detail FROM audit WHERE action='mail-default-address'").fetchall())
        assert "catch@external.net" not in details
        assert "domain=example.com" in details

print("Nexvary Panel default-address provider/loop/policy/step-up tests: PASS")
