from __future__ import annotations

import os
import pathlib
import re
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
    from panel.core import db
    from panel.maintenance_policy import OPERATIONS
    from panel.privileged_policy import operation_policy

    risk_rank = {"low": 0, "medium": 1, "high": 2}
    for operation in OPERATIONS.values():
        privileged = operation_policy(operation.agent_action)
        assert operation.step_up or not privileged.get("step_up"), operation.id
        assert operation.timeout <= int(privileged["timeout"]), operation.id
        assert operation.risk in risk_rank, operation.id
        assert str(privileged.get("risk")) in risk_rank, operation.id
        assert risk_rank[operation.risk] >= risk_rank[str(privileged["risk"])], operation.id
        assert operation.roles, operation.id
        assert operation.precheck and operation.postcheck, operation.id
        assert operation.rollback is None or operation.rollback.strip(), operation.id

    calls: list[dict] = []

    def fake_agent(payload, timeout=30):
        calls.append(dict(payload))
        if payload.get("action") == "service-restart" and payload.get("name") in {"nginx", "mariadb", "fail2ban", "docker"}:
            return {"ok": True, "output": "active"}
        if payload.get("action") == "docker-control" and payload.get("desired") in {"start", "stop", "restart"}:
            return {"ok": True, "output": "container state changed"}
        return {"ok": False, "error": "unexpected action"}

    ops.agent_call = fake_agent
    app = create_app()
    app.testing = True
    client = app.test_client()
    csrf = "maintenance-csrf"
    now = int(time.time())

    with client.session_transaction() as session:
        session.update(auth=True, user="admin", role="admin", csrf=csrf)

    blocked = client.post("/services/restart", data={"csrf_token": csrf, "name": "nginx"}, follow_redirects=False)
    assert blocked.status_code == 302 and blocked.headers["Location"].endswith("#security")
    assert not calls, "privileged maintenance action reached agent without Step-Up"

    docker_blocked = client.post("/docker/control", data={"csrf_token": csrf, "container": "web-1", "desired": "restart"}, follow_redirects=False)
    assert docker_blocked.status_code == 302 and docker_blocked.headers["Location"].endswith("#security")
    assert not calls, "Docker mutation reached privileged agent without Step-Up"

    with client.session_transaction() as session:
        session["step_up_user"] = "admin"
        session["step_up_until"] = now + 300

    restarted = client.post("/services/restart", data={"csrf_token": csrf, "name": "nginx"}, follow_redirects=False)
    assert restarted.status_code == 302 and restarted.headers["Location"].endswith("#services")
    assert calls == [{"action": "service-restart", "name": "nginx"}], calls

    with db() as conn:
        receipts = conn.execute("SELECT action,detail FROM audit WHERE action LIKE 'maintenance-%' ORDER BY id").fetchall()
    assert len(receipts) == 2, receipts
    assert [r["action"] for r in receipts] == ["maintenance-start", "maintenance-success"], receipts
    receipt_ids = [re.search(r"change=([0-9a-f]{16})", r["detail"] or "") for r in receipts]
    assert all(receipt_ids) and receipt_ids[0].group(1) == receipt_ids[1].group(1), receipts
    assert all("operation=restart-nginx" in r["detail"] and "target=nginx" in r["detail"] for r in receipts)

    replay = client.post("/services/restart", data={"csrf_token": csrf, "name": "mariadb"}, follow_redirects=False)
    assert replay.status_code == 302 and replay.headers["Location"].endswith("#security")
    assert len(calls) == 1, "consumed Step-Up grant authorized a second privileged mutation"

    with client.session_transaction() as session:
        session["step_up_user"] = "admin"
        session["step_up_until"] = now + 300

    denied = client.post("/services/restart", data={"csrf_token": csrf, "name": "ssh"}, follow_redirects=False)
    assert denied.status_code == 302
    assert len(calls) == 1, "non-allowlisted service reached privileged agent"

    docker_ok = client.post("/docker/control", data={"csrf_token": csrf, "container": "web-1", "desired": "restart"}, follow_redirects=False)
    assert docker_ok.status_code == 302 and docker_ok.headers["Location"].endswith("#docker")
    assert calls[-1] == {"action": "docker-control", "container": "web-1", "desired": "restart"}, calls[-1]

    with db() as conn:
        docker_receipts = conn.execute("SELECT action,detail FROM audit WHERE detail LIKE '%operation=docker-restart%' ORDER BY id").fetchall()
    assert [r["action"] for r in docker_receipts] == ["maintenance-start", "maintenance-success"], docker_receipts
    docker_ids = [re.search(r"change=([0-9a-f]{16})", r["detail"] or "") for r in docker_receipts]
    assert all(docker_ids) and docker_ids[0].group(1) == docker_ids[1].group(1), docker_receipts
    assert all("target=web-1" in r["detail"] for r in docker_receipts)

    before = len(calls)
    docker_replay = client.post("/docker/control", data={"csrf_token": csrf, "container": "web-1", "desired": "stop"}, follow_redirects=False)
    assert docker_replay.status_code == 302 and docker_replay.headers["Location"].endswith("#security")
    assert len(calls) == before, "consumed Docker Step-Up grant authorized another mutation"

    with client.session_transaction() as session:
        session["step_up_user"] = "admin"
        session["step_up_until"] = now + 300

    docker_denied = client.post("/docker/control", data={"csrf_token": csrf, "container": "web-1", "desired": "exec"}, follow_redirects=False)
    assert docker_denied.status_code == 302
    assert len(calls) == before, "non-allowlisted Docker lifecycle verb reached privileged agent"

    services_html = (ROOT / "templates" / "sections" / "services.html").read_text(encoding="utf-8")
    index_html = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
    assert "قسم الصيانة" in services_html
    assert "MAINTENANCE CENTER" in services_html
    assert "لا Terminal ولا Shell أو أوامر عشوائية" in services_html
    assert 'href="#services" data-title="قسم الصيانة"' in index_html

print("NEXVARY graphical Maintenance Center privilege boundary gate: PASS")
