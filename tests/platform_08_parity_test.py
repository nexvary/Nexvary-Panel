from __future__ import annotations

import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-parity-08-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.extension_registry import BY_ID
    from panel.routes_fleet import PLAN_OPERATIONS

    app = create_app()
    rules = {rule.rule for rule in app.url_map.iter_rules()}

    required_routes = {
        "/api/server-lifecycle/maintenance/preview",
        "/api/server-lifecycle/maintenance/<int:preview_id>/apply",
        "/api/fleet/v1/health",
        "/api/fleet/v1/apply",
        "/api/fleet/plan",
        "/api/fleet/apply",
        "/api/fleet/jobs",
        "/api/migration-center/uploads",
        "/api/migration-center/inspect",
        "/api/migration-center/normalize",
        "/api/extensions",
    }
    missing = required_routes - rules
    assert not missing, f"Platform 0.8 parity routes missing: {sorted(missing)}"

    assert PLAN_OPERATIONS == {
        "restart-nginx": "service.nginx.restart",
        "restart-mariadb": "service.mariadb.restart",
        "enable-ntp": "server.time.ntp",
        "system-updates": "server.updates.apply",
    }

    fleet = BY_ID["fleet"]
    migration = BY_ID["migration-center"]
    assert fleet.maturity == "provider"
    assert migration.maturity == "provider"
    assert "/api/fleet" in fleet.api_prefixes
    assert "/api/migration-center" in migration.api_prefixes
    assert "nexvary-panel-provider" in fleet.provider_services
    assert "nexvary-panel-ops" in migration.provider_services

server_agent = (ROOT / "agent" / "server_agent.py").read_text(encoding="utf-8")
assert '"server-updates-apply"' in server_agent
assert "system-update-preview-stale" in server_agent
assert "apt-get" in server_agent

fleet_transport = (ROOT / "agent" / "fleet_transport.py").read_text(encoding="utf-8")
assert "Authorization" in fleet_transport and "Bearer" in fleet_transport
assert "Idempotency-Key" in fleet_transport

migration_adapters = (ROOT / "agent" / "migration_adapters.py").read_text(encoding="utf-8")
for marker in ("cpanel", "directadmin", "plesk", "MAX_ARCHIVE_BYTES", "unsafe-migration-archive-entry"):
    assert marker in migration_adapters.lower() if marker in {"cpanel", "directadmin", "plesk"} else marker in migration_adapters

install_08 = (ROOT / "installer" / "install-0.8.sh").read_text(encoding="utf-8")
for marker in ("fleet_transport.py", "migration_adapters.py", "hosting_ops_08_entry.py", "provider.sock", "ops.sock"):
    assert marker in install_08

print("Nexvary Panel Platform 0.8 targeted competitive-parity closure gate: PASS")
