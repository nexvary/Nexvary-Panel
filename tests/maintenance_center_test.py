from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-maintenance-center-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_AGENT_SOCK"] = str(pathlib.Path(tmp) / "missing-agent.sock")

    import panel.routes_ops as ops
    from panel import create_app
    from panel.maintenance_policy import OPERATIONS
    from panel.privileged_policy import operation_policy

    # Keep the graphical Maintenance Center subordinate to the central privileged
    # operation contract.  A route-local policy may tighten controls, never weaken
    # Step-Up or silently extend a privileged operation's execution window.
    for operation in OPERATIONS.values():
        privileged = operation_policy(operation.agent_action)
        assert operation.step_up or not privileged.get("step_up"), operation.id
        assert operation.timeout <= int(privileged["timeout"]), operation.id
        assert operation.roles, operation.id
        assert operation.precheck and operation.postcheck, operation.id

    calls: list[dict] = []

    def fake_agent(payload, timeout=30):
        calls.append(dict(payload))
        if payload.get("action") == "service-restart" and payload.get("name") in {"nginx", "mariadb", "fail2ban", "docker"}:
            return {"ok": True, "output": "active"}
        return {"ok": False, "error": "unexpected action"}

    ops.agent_call = fake_agent
    app = create_app()
    app.testing = True
    client = app.test_client()
    csrf = "maintenance-csrf"
    now = int(time.time())

    with client.session_transaction() as session:
        session.update(auth=True, user="admin", role="admin", csrf=csrf)

    blocked = client.post(
        "/services/restart",
        data={"csrf_token": csrf, "name": "nginx"},
        follow_redirects=False,
    )
    assert blocked.status_code == 302, blocked.data
    assert blocked.headers["Location"].endswith("#security"), blocked.headers["Location"]
    assert not calls, "privileged maintenance action reached agent without Step-Up"

    docker_blocked = client.post(
        "/docker/control",
        data={"csrf_token": csrf, "container": "web-1", "desired": "restart"},
        follow_redirects=False,
    )
    assert docker_blocked.status_code == 302, docker_blocked.data
    assert docker_blocked.headers["Location"].endswith("#security"), docker_blocked.headers["Location"]
    assert not calls, "Docker mutation reached privileged agent without Step-Up"

    with client.session_transaction() as session:
        session["step_up_user"] = "admin"
        session["step_up_until"] = now + 300

    restarted = client.post(
        "/services/restart",
        data={"csrf_token": csrf, "name": "nginx"},
        follow_redirects=False,
    )
    assert restarted.status_code == 302, restarted.data
    assert restarted.headers["Location"].endswith("#services"), restarted.headers["Location"]
    assert calls == [{"action": "service-restart", "name": "nginx"}], calls

    denied = client.post(
        "/services/restart",
        data={"csrf_token": csrf, "name": "ssh"},
        follow_redirects=False,
    )
    assert denied.status_code == 302, denied.data
    assert len(calls) == 1, "non-allowlisted service reached privileged agent"

    services_html = (ROOT / "templates" / "sections" / "services.html").read_text(encoding="utf-8")
    index_html = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
    assert "قسم الصيانة" in services_html
    assert "MAINTENANCE CENTER" in services_html
    assert "لا Terminal ولا Shell أو أوامر عشوائية" in services_html
    assert 'href="#services" data-title="قسم الصيانة"' in index_html

print("NEXVARY graphical Maintenance Center privilege boundary gate: PASS")
