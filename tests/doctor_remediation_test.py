from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-doctor-remediation-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_AGENT_SOCK"] = str(pathlib.Path(tmp) / "missing-agent.sock")

    import panel.routes_health as health
    from panel import create_app
    from panel.db_layer import db

    state = {"nginx_active": False, "nginx_config": True}
    calls: list[dict] = []

    def doctor_result() -> dict:
        checks = [
            {
                "name": "NGINX configuration",
                "ok": state["nginx_config"],
                "severity": "ok" if state["nginx_config"] else "critical",
                "detail": "syntax is ok" if state["nginx_config"] else "nginx: configuration test failed",
            },
            {
                "name": "Service: nginx",
                "ok": state["nginx_active"],
                "severity": "ok" if state["nginx_active"] else "critical",
                "detail": "active" if state["nginx_active"] else "inactive",
            },
            {
                "name": "Disk capacity",
                "ok": False,
                "severity": "warning",
                "detail": "91.5% used",
            },
        ]
        return {
            "ok": True,
            "checks": {
                "summary": {
                    "total": len(checks),
                    "passed": sum(1 for item in checks if item["ok"]),
                    "failed": sum(1 for item in checks if not item["ok"]),
                },
                "checks": checks,
            },
        }

    def fake_agent(payload, timeout=30):
        calls.append(dict(payload))
        if payload.get("action") == "doctor":
            return doctor_result()
        if payload.get("action") == "service-restart":
            assert payload.get("name") == "nginx"
            state["nginx_active"] = True
            return {"ok": True, "output": "nginx active"}
        return {"ok": False, "error": "unexpected action"}

    health.agent_call = fake_agent
    app = create_app()
    app.testing = True
    client = app.test_client()
    csrf = "doctor-csrf"
    now = int(time.time())

    with client.session_transaction() as session:
        session.update(auth=True, user="admin", role="admin", csrf=csrf)

    preview = client.get("/api/doctor/remediation-preview")
    assert preview.status_code == 200, preview.data
    body = preview.get_json()
    by_check = {item["check"]: item for item in body["remediation"]}
    assert by_check["Service: nginx"]["safe"] is True
    assert by_check["Service: nginx"]["service"] == "nginx"
    assert by_check["Disk capacity"]["safe"] is False
    assert by_check["Disk capacity"]["action"] == "manual"

    no_step = client.post(
        "/api/doctor/remediate",
        json={"check": "Service: nginx"},
        headers={"X-CSRF-Token": csrf},
    )
    assert no_step.status_code == 428, no_step.data
    assert not any(call.get("action") == "service-restart" for call in calls)

    with client.session_transaction() as session:
        session["step_up_user"] = "admin"
        session["step_up_until"] = now + 300

    fixed = client.post(
        "/api/doctor/remediate",
        json={"check": "Service: nginx"},
        headers={"X-CSRF-Token": csrf},
    )
    assert fixed.status_code == 200, fixed.data
    fixed_body = fixed.get_json()
    assert fixed_body["verified"] is True
    assert fixed_body["after"]["ok"] is True
    assert sum(1 for call in calls if call.get("action") == "service-restart") == 1

    history = client.get("/api/doctor/remediations")
    assert history.status_code == 200, history.data
    rows = history.get_json()["remediations"]
    assert rows and rows[0]["check_name"] == "Service: nginx"
    assert rows[0]["status"] == "verified"
    with db() as conn:
        audit_text = " ".join(str(row[0]) for row in conn.execute("SELECT detail FROM audit").fetchall())
        assert "doctor-remediation" not in audit_text or "nginx" in audit_text

    state["nginx_active"] = False
    state["nginx_config"] = False
    preview = client.get("/api/doctor/remediation-preview")
    assert preview.status_code == 200, preview.data
    by_check = {item["check"]: item for item in preview.get_json()["remediation"]}
    assert by_check["Service: nginx"]["safe"] is False
    restart_count = sum(1 for call in calls if call.get("action") == "service-restart")
    blocked = client.post(
        "/api/doctor/remediate",
        json={"check": "Service: nginx"},
        headers={"X-CSRF-Token": csrf},
    )
    assert blocked.status_code == 409, blocked.data
    assert sum(1 for call in calls if call.get("action") == "service-restart") == restart_count

    with client.session_transaction() as session:
        session.update(user="operator1", role="operator", step_up_user="operator1", step_up_until=now + 300)
    denied = client.post(
        "/api/doctor/remediate",
        json={"check": "Service: nginx"},
        headers={"X-CSRF-Token": csrf},
    )
    assert denied.status_code == 403, denied.data

print("NEXVARY Doctor remediation policy gate: PASS")
