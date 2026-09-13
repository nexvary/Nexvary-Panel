from __future__ import annotations

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

    def fake_probe(endpoint: str):
        probes.append(endpoint)
        if "1.1.1.1" in endpoint:
            return {
                "status": "online",
                "remote_version": "0.7.0",
                "capabilities": {"nginx": True, "autossl": True, "panel.upgrade": True, "mail": False},
                "latency_ms": 42,
            }
        return {
            "status": "degraded",
            "remote_version": "0.6.0",
            "capabilities": {"nginx": True, "autossl": False, "panel.upgrade": False},
            "latency_ms": 88,
        }

    routes._probe_endpoint = fake_probe

    with db() as conn:
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("viewer01", "viewer", "00" * 16, "00" * 32, now),
        )

    with client.session_transaction() as session:
        session.update(auth=True, user="admin", role="admin", csrf=csrf, step_up_user="admin", step_up_until=now + 600)

    private = client.post(
        "/api/fleet",
        json={"name": "Private Node", "endpoint": "https://127.0.0.1:8443"},
        headers={"X-CSRF-Token": csrf},
    )
    assert private.status_code == 400

    first = client.post(
        "/api/fleet",
        json={"name": "Primary Edge", "endpoint": "https://1.1.1.1:8443"},
        headers={"X-CSRF-Token": csrf},
    )
    second = client.post(
        "/api/fleet",
        json={"name": "Secondary Edge", "endpoint": "https://8.8.8.8:8443"},
        headers={"X-CSRF-Token": csrf},
    )
    assert first.status_code == 201 and second.status_code == 201
    first_id = int(first.get_json()["id"])
    second_id = int(second.get_json()["id"])

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
    assert node["latest_probe"]["remote_version"] == "0.7.0"
    assert node["latest_probe"]["capabilities"]["panel.upgrade"] is True
    assert node["latest_probe"]["latency_ms"] == 42

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
    assert body["remote_apply_supported"] is False and body["batch_limit"] == 25

    plan = client.post(
        "/api/fleet/plan",
        json={"node_ids": [first_id, second_id], "operation": "reload-nginx"},
        headers={"X-CSRF-Token": csrf},
    )
    assert plan.status_code == 200
    p = plan.get_json()
    assert p["apply_supported"] is False and p["ready_count"] == 1 and p["blocked_count"] == 1
    assert any(item["id"] == first_id and item["ready"] is True for item in p["nodes"])
    assert any(item["id"] == second_id and item["ready"] is False for item in p["nodes"])

    unsupported = client.post(
        "/api/fleet/plan",
        json={"node_ids": [first_id], "operation": "run-shell"},
        headers={"X-CSRF-Token": csrf},
    )
    assert unsupported.status_code == 400

    with db() as conn:
        assert int(conn.execute("SELECT COUNT(*) FROM fleet_probes").fetchone()[0]) == 3
        raw = " ".join(str(row[0]) for row in conn.execute("SELECT capabilities_json FROM fleet_probes").fetchall())
        assert "panel.upgrade" in raw and "password" not in raw.lower()

    with client.session_transaction() as session:
        session.clear()
        session.update(auth=True, user="viewer01", role="viewer", csrf=csrf)
    denied = client.get("/api/fleet")
    assert denied.status_code == 403

print("Nexvary Panel Fleet orchestration/SSRF/capability gate: PASS")
