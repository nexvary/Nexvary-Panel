from __future__ import annotations

import hashlib
import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-fleet-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_fleet as routes

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "fleet-csrf"
    probes: list[str] = []
    local_actions: list[dict] = []
    remote_actions: list[dict] = []

    def fake_probe(endpoint: str):
        probes.append(endpoint)
        if "1.1.1.1" in endpoint:
            return {
                "status": "online",
                "remote_version": "0.8.0",
                "capabilities": {
                    "service.nginx.restart": True,
                    "service.mariadb.restart": True,
                    "server.time.ntp": True,
                    "server.updates.apply": True,
                },
                "latency_ms": 42,
            }
        return {
            "status": "degraded",
            "remote_version": "0.7.0",
            "capabilities": {"service.nginx.restart": True, "server.updates.apply": False},
            "latency_ms": 88,
        }

    def fake_agent_call(payload: dict, timeout: int = 30):
        local_actions.append(dict(payload))
        if payload == {"action": "service-restart", "name": "nginx"}:
            return {"ok": True, "service": "nginx", "active": True}
        if payload == {"action": "service-restart", "name": "mariadb"}:
            return {"ok": True, "service": "mariadb", "active": True}
        return {"ok": False, "error": "unexpected-local-action"}

    def fake_provider_call(payload: dict, timeout: int = 30):
        remote_actions.append(dict(payload))
        assert payload["action"] == "fleet-apply"
        assert payload["secret_id"] == "fleet-edge-1"
        assert payload["operation"] == "restart-nginx"
        assert len(payload["request_id"]) == 32
        return {"ok": True, "status": "applied", "result": {"service": "nginx", "active": True}}

    routes._probe_endpoint = fake_probe
    routes.agent_call = fake_agent_call
    routes.provider_call = fake_provider_call

    with db() as conn:
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("viewer01", "viewer", "00" * 16, "00" * 32, now),
        )

    with client.session_transaction() as session:
        session.update(auth=True, user="admin", role="admin", csrf=csrf, step_up_user="admin", step_up_until=now + 600)

    health = client.get("/api/fleet/v1/health")
    assert health.status_code == 200
    health_body = health.get_json()
    assert health_body["protocol"] == "fleet-v1"
    assert health_body["capabilities"]["service.nginx.restart"] is True
    assert health_body["capabilities"]["server.updates.apply"] is True

    private = client.post(
        "/api/fleet",
        json={"name": "Private Node", "endpoint": "https://127.0.0.1:8443", "credential_ref": "fleet-private"},
        headers={"X-CSRF-Token": csrf},
    )
    assert private.status_code == 400

    first = client.post(
        "/api/fleet",
        json={"name": "Primary Edge", "endpoint": "https://1.1.1.1:8443", "credential_ref": "fleet-edge-1"},
        headers={"X-CSRF-Token": csrf},
    )
    second = client.post(
        "/api/fleet",
        json={"name": "Secondary Edge", "endpoint": "https://8.8.8.8:8443", "credential_ref": "fleet-edge-2"},
        headers={"X-CSRF-Token": csrf},
    )
    assert first.status_code == 201 and second.status_code == 201
    first_id = int(first.get_json()["id"])
    second_id = int(second.get_json()["id"])
    assert first.get_json()["credential_configured"] is True

    legacy = client.post(
        "/api/advanced/fleet",
        json={"name": "Legacy", "endpoint": "https://1.1.1.1:8443"},
        headers={"X-CSRF-Token": csrf},
    )
    assert legacy.status_code == 410

    one = client.post(f"/api/fleet/{first_id}/probe", headers={"X-CSRF-Token": csrf})
    assert one.status_code == 200, one.data
    node = one.get_json()["node"]
    assert node["status"] == "online"
    assert node["latest_probe"]["remote_version"] == "0.8.0"
    assert node["latest_probe"]["capabilities"]["service.nginx.restart"] is True
    assert node["latest_probe"]["latency_ms"] == 42
    assert node["credential_configured"] is True
    assert "credential_ref" not in node

    batch = client.post(
        "/api/fleet/probe-all",
        json={"node_ids": [first_id, second_id]},
        headers={"X-CSRF-Token": csrf},
    )
    assert batch.status_code == 200 and batch.get_json()["probed"] == 2
    assert len(probes) == 3

    overview = client.get("/api/fleet")
    assert overview.status_code == 200
    body = overview.get_json()
    assert body["counts"]["total"] == 2 and body["counts"]["online"] == 1 and body["counts"]["degraded"] == 1
    assert body["remote_apply_supported"] is True and body["batch_limit"] == 25

    plan = client.post(
        "/api/fleet/plan",
        json={"node_ids": [first_id, second_id], "operation": "restart-nginx"},
        headers={"X-CSRF-Token": csrf},
    )
    assert plan.status_code == 200
    p = plan.get_json()
    assert p["apply_supported"] is True and p["ready_count"] == 1 and p["blocked_count"] == 1
    assert any(item["id"] == first_id and item["ready"] is True for item in p["nodes"])
    assert any(item["id"] == second_id and item["ready"] is False for item in p["nodes"])

    applied = client.post(
        "/api/fleet/apply",
        json={"node_ids": [first_id], "operation": "restart-nginx", "payload": {}},
        headers={"X-CSRF-Token": csrf},
    )
    assert applied.status_code == 200
    applied_body = applied.get_json()
    assert applied_body["ok"] is True and applied_body["applied_count"] == 1 and applied_body["failed_count"] == 0
    assert len(remote_actions) == 1

    jobs = client.get("/api/fleet/jobs")
    assert jobs.status_code == 200
    assert jobs.get_json()["jobs"][0]["direction"] == "outbound"
    assert jobs.get_json()["jobs"][0]["status"] == "applied"

    unsupported = client.post(
        "/api/fleet/plan",
        json={"node_ids": [first_id], "operation": "run-shell"},
        headers={"X-CSRF-Token": csrf},
    )
    assert unsupported.status_code == 400

    token_response = client.post(
        "/api/fleet/auth/tokens",
        json={"label": "Controller Alpha"},
        headers={"X-CSRF-Token": csrf},
    )
    assert token_response.status_code == 201
    token_body = token_response.get_json()
    machine_token = token_body["token_once"]
    token_id = int(token_body["id"])
    assert machine_token.startswith("nvp_fleet_")
    assert token_body["store_as"]["kind"] == "fleet"

    listed_tokens = client.get("/api/fleet/auth/tokens").get_json()["tokens"]
    assert listed_tokens[0]["id"] == token_id
    assert "token_once" not in listed_tokens[0] and "token_hash" not in listed_tokens[0]

    with db() as conn:
        stored = conn.execute("SELECT token_hash FROM fleet_inbound_tokens WHERE id=?", (token_id,)).fetchone()[0]
        assert stored == hashlib.sha256(machine_token.encode()).hexdigest()
        assert machine_token not in str(stored)

    request_id = "1" * 32
    machine_headers = {"Authorization": f"Bearer {machine_token}", "Idempotency-Key": request_id}
    machine = client.post(
        "/api/fleet/v1/apply",
        json={"operation": "restart-nginx", "request_id": request_id, "issued_at": int(time.time()), "payload": {}},
        headers=machine_headers,
    )
    assert machine.status_code == 200
    assert machine.get_json()["status"] == "applied"
    assert len(local_actions) == 1

    replay = client.post(
        "/api/fleet/v1/apply",
        json={"operation": "restart-nginx", "request_id": request_id, "issued_at": int(time.time()), "payload": {}},
        headers=machine_headers,
    )
    assert replay.status_code == 200 and replay.get_json()["status"] == "applied"
    assert len(local_actions) == 1, "idempotent replay must never execute the provider twice"

    invalid_machine = client.post(
        "/api/fleet/v1/apply",
        json={"operation": "restart-nginx", "request_id": "2" * 32, "issued_at": int(time.time()), "payload": {}},
        headers={"Authorization": "Bearer nvp_fleet_" + "x" * 50, "Idempotency-Key": "2" * 32},
    )
    assert invalid_machine.status_code == 401

    with db() as conn:
        assert int(conn.execute("SELECT COUNT(*) FROM fleet_probes").fetchone()[0]) == 3
        raw = " ".join(str(row[0]) for row in conn.execute("SELECT capabilities_json FROM fleet_probes").fetchall())
        assert "service.nginx.restart" in raw and "password" not in raw.lower()
        assert int(conn.execute("SELECT COUNT(*) FROM fleet_jobs WHERE direction='outbound'").fetchone()[0]) == 1
        assert int(conn.execute("SELECT COUNT(*) FROM fleet_jobs WHERE direction='inbound'").fetchone()[0]) == 1

    revoked = client.delete(f"/api/fleet/auth/tokens/{token_id}", headers={"X-CSRF-Token": csrf})
    assert revoked.status_code == 200 and revoked.get_json()["enabled"] is False

    with client.session_transaction() as session:
        session.clear()
        session.update(auth=True, user="viewer01", role="viewer", csrf=csrf)
    denied = client.get("/api/fleet")
    assert denied.status_code == 403

print("Nexvary Panel Fleet authenticated orchestration/SSRF/replay gate: PASS")
