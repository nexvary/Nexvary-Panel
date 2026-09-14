from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-resource-usage-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_resource_usage as resource_routes

    app = create_app(); app.testing = True; client = app.test_client(); now = int(time.time())
    with db() as conn:
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("client1", "operator", "88" * 16, "88" * 32, now),
        )
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("client2", "operator", "99" * 16, "99" * 32, now),
        )
        core_id = int(conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()[0])
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)", ("client1", core_id, now))
        conn.execute("INSERT INTO sites(domain,kind,target,enabled,owner,created_at) VALUES(?,?,?,?,?,?)", ("one.example.test", "php", "", 1, "client1", now))

    resource_routes.webtools_call = lambda payload, timeout=25: {
        "ok": True,
        "disk_bytes": 3 * 1024 * 1024 + 1,
        "filesystem_entries": 12,
        "bandwidth_bytes": 10 * 1024,
        "bandwidth_scope": "latest-log-window",
    }

    with client.session_transaction() as session:
        session.update(auth=True, user="client1", role="operator", csrf="usage-csrf")

    response = client.get("/api/hosting/resource-usage")
    assert response.status_code == 200, response.data
    body = response.get_json()
    assert body["measurement_complete"] is True
    assert body["sites_total"] == 1 and body["sites_measured"] == 1
    assert body["telemetry"]["disk"]["used"] == 4
    assert body["telemetry"]["disk"]["hard_quota_safe"] is True
    assert body["telemetry"]["bandwidth"]["sample_bytes"] == 10 * 1024
    assert body["telemetry"]["bandwidth"]["hard_quota_safe"] is False
    assert body["enforcement"] == {"disk": "eligible-when-complete", "bandwidth": "telemetry-only"}
    assert body["quota"]["max_sites"]["used"] == 1

    denied = client.get("/api/hosting/resource-usage?username=client2")
    assert denied.status_code == 403, denied.data

    with db() as conn:
        conn.execute("INSERT INTO sites(domain,kind,target,enabled,owner,created_at) VALUES(?,?,?,?,?,?)", ("two.example.test", "php", "", 1, "client1", now))

    def partial(payload, timeout=25):
        if payload.get("domain") == "two.example.test":
            return {"ok": False, "error": "measurement failed"}
        return {
            "ok": True,
            "disk_bytes": 1024 * 1024,
            "filesystem_entries": 3,
            "bandwidth_bytes": 100,
            "bandwidth_scope": "latest-log-window",
        }

    resource_routes.webtools_call = partial
    partial_response = client.get("/api/hosting/resource-usage")
    assert partial_response.status_code == 200, partial_response.data
    partial_body = partial_response.get_json()
    assert partial_body["measurement_complete"] is False
    assert partial_body["telemetry"]["disk"]["measured"] is False
    assert partial_body["telemetry"]["disk"]["hard_quota_safe"] is False
    assert partial_body["failures"] == ["two.example.test"]

print("NEXVARY package-aware Resource Usage API gate: PASS")
