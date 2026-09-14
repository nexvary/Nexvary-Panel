from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-server-lifecycle-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app

    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    def admin_session(step_up: bool = True):
        with client.session_transaction() as sess:
            sess.clear()
            sess["auth"] = True
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["csrf"] = "server-csrf"
            if step_up:
                sess["step_up_user"] = "admin"
                sess["step_up_until"] = int(time.time()) + 300

    def fake_server_call(payload: dict, timeout: int = 30) -> dict:
        action = payload.get("action")
        if action == "server-overview":
            return {
                "ok": True,
                "hostname": "host.example.com",
                "os": "Ubuntu 24.04 LTS",
                "kernel": "6.8.0",
                "architecture": "x86_64",
                "uptime_seconds": 7200,
                "load": [0.1, 0.2, 0.3],
                "reboot_required": False,
                "time": {"timezone": "UTC", "ntp": True, "synchronized": True, "epoch": 1},
            }
        if action == "server-network":
            return {"ok": True, "addresses": [{"interface": "eth0", "family": "inet", "address": "203.0.113.10", "prefixlen": 24, "scope": "global"}], "default_routes": [{"dev": "eth0", "gateway": "203.0.113.1", "protocol": "dhcp"}], "nameservers": ["1.1.1.1"]}
        if action == "server-processes":
            return {"ok": True, "processes": [{"pid": 10, "user": "root", "command": "nginx", "cpu": 1.2, "memory": 0.4, "elapsed_seconds": 600}]}
        if action == "server-updates-preview":
            return {"ok": True, "count": 2, "packages": [{"name": "nginx", "version": "1.1"}, {"name": "openssl", "version": "3.1"}], "fingerprint": "a" * 64, "reboot_required": False, "generated_at": int(time.time()), "apply_supported": False}
        if action == "server-time-enable-ntp":
            return {"ok": True, "time": {"timezone": "UTC", "ntp": True, "synchronized": True, "epoch": 1}}
        return {"ok": False, "error": "unexpected-action"}

    # Unauthenticated API remains JSON 401.
    response = client.get("/api/server-lifecycle/overview")
    assert response.status_code == 401

    admin_session()
    with patch("panel.routes_server_lifecycle.server_call", side_effect=fake_server_call):
        response = client.get("/api/server-lifecycle/overview")
        assert response.status_code == 200 and response.get_json()["hostname"] == "host.example.com"

        response = client.get("/api/server-lifecycle/network")
        assert response.status_code == 200 and response.get_json()["nameservers"] == ["1.1.1.1"]

        response = client.get("/api/server-lifecycle/processes")
        assert response.status_code == 200 and response.get_json()["processes"][0]["command"] == "nginx"

        response = client.get("/api/server-lifecycle/updates")
        assert response.status_code == 200
        body = response.get_json()
        assert body["count"] == 2 and body["apply_supported"] is False

        response = client.post(
            "/api/server-lifecycle/maintenance/preview",
            json={"kind": "system-updates"},
            headers={"X-CSRF-Token": "server-csrf"},
        )
        assert response.status_code == 201
        preview = response.get_json()["preview"]
        assert preview["status"] == "preview"
        assert preview["fingerprint"] == "a" * 64
        preview_id = preview["id"]

        response = client.get("/api/server-lifecycle/maintenance")
        assert response.status_code == 200
        assert response.get_json()["previews"][0]["id"] == preview_id

        response = client.post(
            f"/api/server-lifecycle/maintenance/{preview_id}/cancel",
            headers={"X-CSRF-Token": "server-csrf"},
        )
        assert response.status_code == 200 and response.get_json()["status"] == "cancelled"

        response = client.post(
            "/api/server-lifecycle/time/enable-ntp",
            headers={"X-CSRF-Token": "server-csrf"},
        )
        assert response.status_code == 200 and response.get_json()["time"]["ntp"] is True

        response = client.post(
            "/api/server-lifecycle/maintenance/preview",
            json={"kind": "not-allowed"},
            headers={"X-CSRF-Token": "server-csrf"},
        )
        assert response.status_code == 400

    admin_session(step_up=False)
    with patch("panel.routes_server_lifecycle.server_call", side_effect=fake_server_call):
        response = client.post(
            "/api/server-lifecycle/maintenance/preview",
            json={"kind": "reboot"},
            headers={"X-CSRF-Token": "server-csrf"},
        )
        assert response.status_code == 428

    routes = {rule.rule for rule in app.url_map.iter_rules()}
    assert "/api/server-lifecycle/maintenance/preview" in routes
    assert not any(path.endswith("/execute") for path in routes if path.startswith("/api/server-lifecycle/"))

print("Nexvary Panel Server Lifecycle control-plane gate: PASS")
