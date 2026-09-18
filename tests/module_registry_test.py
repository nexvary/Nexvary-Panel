from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-modules-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db
    from panel.module_registry import MODULES, module_catalog, validate_modules

    modules = validate_modules()
    assert len(modules) >= 33
    assert tuple(modules) == MODULES
    ids = [m.id for m in modules]
    assert len(ids) == len(set(ids))
    assert {"extensions", "hosting", "resource_usage", "domains", "dnssec", "site_controls", "accounts", "mail", "mail_automation", "mail_queue", "transfers", "advanced_ops", "server_lifecycle", "fleet", "autossl", "deliverability", "domain_health", "wordpress_lifecycle", "wordpress_staging", "wordpress_updates", "security", "vault"}.issubset(ids)

    catalog = module_catalog()
    assert len(catalog) == len(modules)
    by_id = {item["id"]: item for item in catalog}
    assert "nexvary-panel-mail" in by_id["mail"]["provider_services"]
    assert "nexvary-panel-mail" in by_id["mail_security"]["provider_services"]
    assert "nexvary-panel-mail" in by_id["mail_automation"]["provider_services"]
    assert "nexvary-panel-mail" in by_id["mail_queue"]["provider_services"]
    assert "nexvary-panel-transfer" in by_id["transfers"]["provider_services"]
    assert "nexvary-panel-postgres" in by_id["advanced_ops"]["provider_services"]
    assert "nexvary-panel-server" in by_id["server_lifecycle"]["provider_services"]
    assert "nexvary-panel-webtools" in by_id["domains"]["provider_services"]
    assert "nexvary-panel-webtools" in by_id["resource_usage"]["provider_services"]
    assert "nexvary-panel-webtools" in by_id["site_controls"]["provider_services"]
    assert by_id["resource_usage"]["depends_on"] == ["hosting", "sites"]
    assert by_id["resource_usage"]["endpoint_namespace"] == "resource_usage"
    assert "metrics.resource_usage" in by_id["resource_usage"]["feature_prefixes"]
    assert by_id["site_controls"]["depends_on"] == ["hosting", "sites", "webtools"]
    assert by_id["site_controls"]["endpoint_namespace"] == "site_controls"
    assert by_id["site_controls"]["has_schema"] is True
    assert set(by_id["site_controls"]["feature_prefixes"]) == {
        "files.directory_privacy", "security.hotlink", "advanced.indexes", "advanced.mime_types", "metrics.raw_access"
    }
    assert "nexvary-panel-wordpress" in by_id["wordpress_updates"]["provider_services"]
    assert "nexvary-panel-wordpress" in by_id["wordpress_staging"]["provider_services"]
    assert by_id["extensions"]["has_schema"] is True
    assert by_id["domains"]["has_schema"] is True
    assert by_id["mail_automation"]["has_schema"] is True
    assert by_id["wordpress_staging"]["has_schema"] is True
    assert by_id["server_lifecycle"]["has_schema"] is True
    assert by_id["server_lifecycle"]["maturity"] == "foundation"
    assert by_id["server_lifecycle"]["depends_on"] == ["advanced_ops"]
    assert by_id["server_lifecycle"]["endpoint_namespace"] == "server_lifecycle"
    assert {"whm.server_time", "whm.updates", "whm.networking", "whm.ip_functions", "whm.processes"}.issubset(set(by_id["server_lifecycle"]["feature_prefixes"]))
    assert by_id["fleet"]["maturity"] == "provider"
    assert by_id["fleet"]["depends_on"] == ["advanced_ops"]
    assert "nexvary-panel-provider" in by_id["fleet"]["provider_services"]
    assert by_id["mail_automation"]["depends_on"] == ["mail", "mail_security"]
    assert set(by_id["mail_automation"]["feature_prefixes"]) == {"email.autoresponders", "email.filters", "email.spam_filters"}
    assert {"email.accounts", "email.default_address"}.issubset(set(by_id["mail_security"]["feature_prefixes"]))
    assert by_id["fleet"]["endpoint_namespace"] == "fleet"
    assert by_id["mail_queue"]["endpoint_namespace"] == "mail_queue"
    assert by_id["extensions"]["endpoint_namespace"] == "extensions"
    assert "whm.plugins" in by_id["extensions"]["feature_prefixes"]
    assert "whm.fleet" in by_id["fleet"]["feature_prefixes"]
    assert "whm.mail_queue" in by_id["mail_queue"]["feature_prefixes"]
    assert set(by_id["domain_health"]["depends_on"]) == {"domains", "advanced_ops", "autossl", "deliverability"}
    assert by_id["wordpress_staging"]["depends_on"] == ["wordpress_lifecycle", "sites"]
    assert by_id["wordpress_updates"]["depends_on"] == ["wordpress_lifecycle"]
    assert "email." in by_id["mail"]["feature_prefixes"]
    assert "domains." in by_id["domains"]["feature_prefixes"]

    app = create_app()
    endpoints = [rule.endpoint for rule in app.url_map.iter_rules()]
    assert len(endpoints) == len(set(endpoints)), "duplicate Flask endpoint after module composition"
    routes = {rule.rule for rule in app.url_map.iter_rules()}
    for path in (
        "/login",
        "/api/extensions",
        "/api/hosting/catalog",
        "/api/hosting/resource-usage",
        "/api/domains/aliases",
        "/api/site-controls",
        "/api/site-controls/privacy",
        "/api/site-controls/hotlink",
        "/api/site-controls/indexing",
        "/api/site-controls/mime",
        "/api/site-controls/raw-access",
        "/api/domain-health",
        "/api/accounts",
        "/api/mail",
        "/api/mail/default-address",
        "/api/mail/automation/<int:mailbox_id>",
        "/api/mail/automation/<int:mailbox_id>/autoresponder",
        "/api/mail/automation/<int:mailbox_id>/filters",
        "/api/mail/automation/<int:mailbox_id>/spam",
        "/api/advanced/mail/queue/<queue_id>",
        "/api/transfers",
        "/api/advanced/status",
        "/api/server-lifecycle/overview",
        "/api/server-lifecycle/network",
        "/api/server-lifecycle/processes",
        "/api/server-lifecycle/updates",
        "/api/server-lifecycle/maintenance/preview",
        "/api/fleet",
        "/api/fleet/probe-all",
        "/api/fleet/plan",
        "/api/fleet/apply",
        "/api/fleet/jobs",
        "/api/wordpress/components/check",
        "/api/wordpress/components/update",
        "/api/wordpress/components/rollback",
        "/api/wordpress/staging",
        "/api/wordpress/staging/clone",
        "/api/wordpress/staging/publish-preview",
        "/api/wordpress/staging/publish",
        "/api/wordpress/staging/publish-rollback",
    ):
        assert path in routes, f"missing module route: {path}"

    with db() as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "extension_states" in tables
        assert "domain_aliases" in tables
        assert "site_web_controls" in tables
        assert "mail_autoresponders" in tables
        assert "mail_filters" in tables
        assert "mail_spam_policies" in tables
        assert "mail_default_addresses" in tables
        assert "wordpress_staging" in tables
        assert "server_maintenance_previews" in tables
        assert "fleet_nodes" in tables
        assert "fleet_probes" in tables
        assert "fleet_jobs" in tables

print("Nexvary Panel module registry architecture gate: PASS")
