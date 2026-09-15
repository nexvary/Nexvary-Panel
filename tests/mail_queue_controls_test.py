from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-mail-queue-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_mail_queue as queue_routes
    import agent.mail_backend as mail_backend

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "mail-queue-csrf"
    calls: list[dict] = []

    def fake_mail_call(payload: dict, timeout: int = 0):
        calls.append({"payload": dict(payload), "timeout": timeout})
        return {"ok": True, "queue_id": payload.get("queue_id"), "deleted": True}

    queue_routes.mail_call = fake_mail_call

    with client.session_transaction() as session:
        session.update(auth=True, user="admin", role="admin", csrf=csrf, step_up_user="admin", step_up_until=now + 600)

    invalid = client.delete("/api/advanced/mail/queue/../../etc", headers={"X-CSRF-Token": csrf})
    assert invalid.status_code in {400, 404}
    assert not calls

    valid = client.delete("/api/advanced/mail/queue/ABC12345", headers={"X-CSRF-Token": csrf})
    assert valid.status_code == 200, valid.data
    assert calls == [{"payload": {"action": "queue-delete", "queue_id": "ABC12345"}, "timeout": 20}]

    with db() as conn:
        audit = conn.execute("SELECT action,detail FROM audit WHERE action='mail-queue-delete' ORDER BY id DESC LIMIT 1").fetchone()
        assert audit and audit["detail"] == "queue_id=ABC12345"
        assert "sender" not in audit["detail"].lower() and "recipient" not in audit["detail"].lower()
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("viewer01", "viewer", "00" * 16, "00" * 32, now),
        )

    with client.session_transaction() as session:
        session.clear()
        session.update(auth=True, user="admin", role="admin", csrf=csrf)
    no_step_up = client.delete("/api/advanced/mail/queue/ABC12345", headers={"X-CSRF-Token": csrf})
    assert no_step_up.status_code == 428

    with client.session_transaction() as session:
        session.clear()
        session.update(auth=True, user="viewer01", role="viewer", csrf=csrf, step_up_user="viewer01", step_up_until=now + 600)
    forbidden = client.delete("/api/advanced/mail/queue/ABC12345", headers={"X-CSRF-Token": csrf})
    assert forbidden.status_code == 403

    argv: list[list[str]] = []
    original_which = mail_backend.shutil.which
    original_run = mail_backend.subprocess.run
    try:
        mail_backend.shutil.which = lambda name: "/usr/sbin/postsuper" if name == "postsuper" else original_which(name)

        def fake_run(args, **kwargs):
            argv.append(list(args))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        mail_backend.subprocess.run = fake_run
        result = mail_backend.queue_delete("ABC12345")
        assert result == {"ok": True, "queue_id": "ABC12345", "deleted": True}
        assert argv == [["postsuper", "-d", "ABC12345"]]
        try:
            mail_backend.queue_delete("-ALL")
            raise AssertionError("option-like queue id must be rejected")
        except ValueError:
            pass
    finally:
        mail_backend.shutil.which = original_which
        mail_backend.subprocess.run = original_run

print("Nexvary Panel Mail Queue delete/Step-Up/allowlist gate: PASS")
