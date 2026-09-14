from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from flask import Flask

from .account_schema import ensure_account_schema
from .api_token_schema import ensure_api_token_schema
from .database_access_schema import ensure_database_access_schema
from .database_lifecycle_schema import ensure_database_lifecycle_schema
from .doctor_schema import ensure_doctor_schema
from .domain_schema import ensure_domain_schema
from .extension_registry import validate_extensions
from .extension_schema import ensure_extension_schema
from .hosting_consistency_schema import ensure_hosting_consistency_schema
from .mail_automation_schema import ensure_mail_automation_schema
from .mail_schema import ensure_mail_schema
from .ops_schema import ensure_ops_schema
from .transfer_schema import ensure_transfer_schema
from .wordpress_publish_schema import ensure_wordpress_publish_schema
from .wordpress_staging_schema import ensure_wordpress_staging_schema
from .wordpress_update_guard_schema import ensure_wordpress_update_guard_schema
from .routes_accounts import register_account_routes
from .routes_advanced_ops import register_advanced_ops_routes
from .routes_api_tokens import register_api_token_routes
from .routes_auth import register_auth_routes
from .routes_autossl import register_autossl_routes
from .routes_change_safety import register_change_safety_routes
from .routes_database_access import register_database_access_routes
from .routes_database_lifecycle import register_database_lifecycle_routes
from .routes_deliverability import register_deliverability_routes
from .routes_dns import register_dns_routes
from .routes_domain_guardian import register_domain_guardian_routes
from .routes_domain_health import register_domain_health_routes
from .routes_domains import register_domain_routes
from .routes_dnssec import register_dnssec_routes
from .routes_extensions import register_extension_routes
from .routes_fleet import register_fleet_routes
from .routes_fusion import register_fusion_routes
from .routes_health import register_health_routes
from .routes_hosting import register_hosting_routes
from .routes_integrations import register_integration_routes
from .routes_mail import register_mail_routes
from .routes_mail_automation import register_mail_automation_routes
from .routes_mail_queue import register_mail_queue_routes
from .routes_mail_security import register_mail_security_routes
from .routes_ops import register_ops_routes
from .routes_platform import register_platform_routes
from .routes_remote_backup import register_remote_backup_routes
from .routes_resource_usage import register_resource_usage_routes
from .routes_schedules import register_schedule_routes
from .routes_security import register_security_routes
from .routes_sites import register_site_routes
from .routes_transfers import register_transfer_routes
from .routes_vault import register_vault_routes
from .routes_webtools import register_webtools_routes
from .routes_whm_bulk import register_whm_bulk_routes
from .routes_wordpress_lifecycle import register_wordpress_lifecycle_routes
from .routes_wordpress_publish import register_wordpress_publish_routes
from .routes_wordpress_smart_guard import register_wordpress_smart_guard_routes
from .routes_wordpress_staging import register_wordpress_staging_routes
from .routes_wordpress_updates import register_wordpress_update_routes

SchemaHook = Callable[[], None]
RouteHook = Callable[[Flask], None]
TIERS = {"core", "hosting", "security", "observability", "providers", "automation", "server"}
MATURITY = {"native", "provider", "foundation"}


@dataclass(frozen=True, slots=True)
class PanelModule:
    id: str
    label: str
    tier: str
    route_hook: RouteHook
    schema_hook: SchemaHook | None = None
    depends_on: tuple[str, ...] = ()
    feature_prefixes: tuple[str, ...] = ()
    provider_services: tuple[str, ...] = ()
    ui_view: str | None = None
    maturity: str = "native"
    endpoint_namespace: str | None = None


MODULES: tuple[PanelModule, ...] = (
    PanelModule("auth", "Authentication", "core", register_auth_routes),
    PanelModule("extensions", "Extension Hub", "core", register_extension_routes, schema_hook=ensure_extension_schema, depends_on=("auth",), feature_prefixes=("whm.plugins",), maturity="native", endpoint_namespace="extensions"),
    PanelModule("api_tokens", "Scoped API Tokens", "security", register_api_token_routes, schema_hook=ensure_api_token_schema, depends_on=("auth",), feature_prefixes=("whm.api_tokens", "security.api_tokens"), ui_view="security", maturity="native", endpoint_namespace="api_tokens"),
    PanelModule("sites", "Sites", "hosting", register_site_routes, feature_prefixes=("domains.", "software."), provider_services=("nexvary-panel-agent",), ui_view="sites", maturity="provider"),
    PanelModule("operations", "Operations", "core", register_ops_routes, depends_on=("auth",), provider_services=("nexvary-panel-agent",), maturity="provider"),
    PanelModule("platform", "Platform", "core", register_platform_routes, depends_on=("auth",)),
    PanelModule("security", "Security", "security", register_security_routes, depends_on=("auth",), feature_prefixes=("security.",), ui_view="security"),
    PanelModule("health", "Health and Doctor", "observability", register_health_routes, schema_hook=ensure_doctor_schema, depends_on=("auth",), provider_services=("nexvary-panel-agent",), ui_view="services"),
    PanelModule("fusion", "Fusion Providers", "providers", register_fusion_routes, depends_on=("auth",), ui_view="fusion"),
    PanelModule("dns", "DNS Inventory", "hosting", register_dns_routes, depends_on=("sites",), feature_prefixes=("domains.",), ui_view="dns"),
    PanelModule("vault", "Secret Vault", "security", register_vault_routes, depends_on=("auth",), provider_services=("nexvary-panel-vault",), ui_view="vault", maturity="provider"),
    PanelModule("integrations", "Integration Targets", "providers", register_integration_routes, depends_on=("vault",), provider_services=("nexvary-panel-provider",), ui_view="integrations", maturity="provider"),
    PanelModule("remote_backup", "Remote Backup", "hosting", register_remote_backup_routes, depends_on=("integrations",), feature_prefixes=("files.backups",), provider_services=("nexvary-panel-provider",), ui_view="backups", maturity="provider"),
    PanelModule("hosting", "Hosting Suite", "hosting", register_hosting_routes, depends_on=("auth",), ui_view="hosting"),
    PanelModule("resource_usage", "Resource Usage", "observability", register_resource_usage_routes, depends_on=("hosting", "sites"), feature_prefixes=("metrics.resource_usage", "files.disk_usage", "metrics.bandwidth"), provider_services=("nexvary-panel-webtools",), ui_view="hosting", maturity="provider", endpoint_namespace="resource_usage"),
    PanelModule("database_access", "Database Access Manager", "hosting", register_database_access_routes, schema_hook=ensure_database_access_schema, depends_on=("hosting", "platform"), feature_prefixes=("databases.mariadb",), provider_services=("nexvary-panel-database",), ui_view="databases", maturity="provider", endpoint_namespace="database_access"),
    PanelModule("domains", "Domain Lifecycle", "hosting", register_domain_routes, schema_hook=ensure_domain_schema, depends_on=("hosting", "sites"), feature_prefixes=("domains.",), provider_services=("nexvary-panel-webtools",), ui_view="webtools", maturity="provider"),
    PanelModule("dnssec", "DNSSEC Lifecycle", "hosting", register_dnssec_routes, depends_on=("domains", "integrations"), feature_prefixes=("domains.zone_editor",), provider_services=("nexvary-panel-ops",), ui_view="webtools", maturity="provider"),
    PanelModule("webtools", "Web Tools", "hosting", register_webtools_routes, depends_on=("hosting", "sites"), feature_prefixes=("domains.", "metrics."), provider_services=("nexvary-panel-webtools",), ui_view="webtools", maturity="provider"),
    PanelModule("schedules", "Scheduled Tasks", "automation", register_schedule_routes, depends_on=("hosting", "sites"), feature_prefixes=("advanced.cron",), provider_services=("nexvary-panel-scheduler",), ui_view="schedules", maturity="provider"),
    PanelModule("accounts", "Accounts and Resellers", "hosting", register_account_routes, schema_hook=ensure_account_schema, depends_on=("hosting",), feature_prefixes=("whm.accounts", "whm.resellers"), ui_view="accounts"),
    PanelModule("whm_bulk", "WHM Bulk Operations", "server", register_whm_bulk_routes, schema_hook=ensure_hosting_consistency_schema, depends_on=("hosting", "accounts"), feature_prefixes=("whm.multi_account", "whm.packages"), ui_view="accounts", maturity="native"),
    PanelModule("mail", "Email Center", "hosting", register_mail_routes, schema_hook=ensure_mail_schema, depends_on=("accounts", "sites"), feature_prefixes=("email.",), provider_services=("nexvary-panel-mail",), ui_view="mail", maturity="provider"),
    PanelModule("mail_security", "Mail Security Controls", "security", register_mail_security_routes, depends_on=("mail",), feature_prefixes=("email.accounts",), provider_services=("nexvary-panel-mail",), ui_view="mail", maturity="provider"),
    PanelModule("mail_automation", "Mail Automation", "hosting", register_mail_automation_routes, schema_hook=ensure_mail_automation_schema, depends_on=("mail", "mail_security"), feature_prefixes=("email.autoresponders", "email.filters", "email.spam_filters"), provider_services=("nexvary-panel-mail",), ui_view="mail", maturity="provider"),
    PanelModule("mail_queue", "Mail Queue Controls", "server", register_mail_queue_routes, depends_on=("mail",), feature_prefixes=("whm.mail_queue",), provider_services=("nexvary-panel-mail",), ui_view="advancedops", maturity="provider", endpoint_namespace="mail_queue"),
    PanelModule("transfers", "Transfer Center", "hosting", register_transfer_routes, schema_hook=ensure_transfer_schema, depends_on=("accounts", "sites"), feature_prefixes=("files.ftp", "files.sftp"), provider_services=("nexvary-panel-transfer",), ui_view="transfers", maturity="provider"),
    PanelModule("advanced_ops", "Advanced Hosting Ops", "server", register_advanced_ops_routes, schema_hook=ensure_ops_schema, depends_on=("hosting", "sites", "integrations"), feature_prefixes=("domains.", "security.ssl", "email.", "software.php", "databases.postgresql", "whm."), provider_services=("nexvary-panel-ops", "nexvary-panel-postgres"), ui_view="advancedops", maturity="provider"),
    PanelModule("database_lifecycle", "Database Lifecycle", "hosting", register_database_lifecycle_routes, schema_hook=ensure_database_lifecycle_schema, depends_on=("database_access", "advanced_ops"), feature_prefixes=("databases.", "files.backups"), provider_services=("nexvary-panel-database", "nexvary-panel-postgres"), ui_view="databases", maturity="provider", endpoint_namespace="database_lifecycle"),
    PanelModule("fleet", "Fleet Orchestration", "server", register_fleet_routes, depends_on=("advanced_ops",), feature_prefixes=("whm.fleet",), ui_view="advancedops", maturity="foundation", endpoint_namespace="fleet"),
    PanelModule("autossl", "AutoSSL Policy", "automation", register_autossl_routes, depends_on=("advanced_ops",), feature_prefixes=("security.ssl",), provider_services=("nexvary-panel-autossl.timer", "nexvary-panel-ops"), ui_view="advancedops", maturity="provider"),
    PanelModule("deliverability", "Mail Deliverability", "hosting", register_deliverability_routes, depends_on=("mail", "advanced_ops"), feature_prefixes=("email.deliverability", "domains.zone_editor"), provider_services=("nexvary-panel-ops",), ui_view="advancedops", maturity="provider"),
    PanelModule("domain_health", "Domain Readiness", "observability", register_domain_health_routes, depends_on=("domains", "advanced_ops", "autossl", "deliverability"), feature_prefixes=("domains.", "security.ssl", "email.deliverability"), ui_view="advancedops"),
    PanelModule("change_safety", "Change Safety", "observability", register_change_safety_routes, depends_on=("health", "advanced_ops", "domain_health"), ui_view="advancedops"),
    PanelModule("domain_guardian", "NEXVARY Domain Guardian", "automation", register_domain_guardian_routes, depends_on=("domain_health", "change_safety", "autossl", "deliverability"), feature_prefixes=("domains.", "security.ssl", "email.deliverability"), ui_view="advancedops", maturity="native", endpoint_namespace="domain_guardian"),
    PanelModule("wordpress_lifecycle", "WordPress Lifecycle", "hosting", register_wordpress_lifecycle_routes, depends_on=("platform", "hosting"), feature_prefixes=("software.wordpress",), provider_services=("nexvary-panel-wordpress",), ui_view="wordpress", maturity="provider"),
    PanelModule("wordpress_staging", "WordPress Staging", "hosting", register_wordpress_staging_routes, schema_hook=ensure_wordpress_staging_schema, depends_on=("wordpress_lifecycle", "sites"), feature_prefixes=("software.wordpress",), provider_services=("nexvary-panel-wordpress",), ui_view="wordpress", maturity="provider"),
    PanelModule("wordpress_publish", "WordPress Selective Publish", "hosting", register_wordpress_publish_routes, schema_hook=ensure_wordpress_publish_schema, depends_on=("wordpress_staging",), feature_prefixes=("software.wordpress",), provider_services=("nexvary-panel-wordpress",), ui_view="wordpress", maturity="provider"),
    PanelModule("wordpress_updates", "WordPress Components", "hosting", register_wordpress_update_routes, depends_on=("wordpress_lifecycle",), feature_prefixes=("software.wordpress",), provider_services=("nexvary-panel-wordpress",), ui_view="wordpress", maturity="provider"),
    PanelModule("wordpress_smart_guard", "NEXVARY Smart Update Guard", "automation", register_wordpress_smart_guard_routes, schema_hook=ensure_wordpress_update_guard_schema, depends_on=("wordpress_staging", "wordpress_publish", "wordpress_updates"), feature_prefixes=("software.wordpress",), provider_services=("nexvary-panel-wordpress",), ui_view="wordpress", maturity="native", endpoint_namespace="wordpress_smart_guard"),
)


def validate_modules(modules: Iterable[PanelModule] = MODULES) -> tuple[PanelModule, ...]:
    ordered = tuple(modules)
    ids = [module.id for module in ordered]
    if len(ids) != len(set(ids)):
        raise RuntimeError("duplicate-panel-module-id")
    known = set(ids)
    position = {module_id: i for i, module_id in enumerate(ids)}
    for index, module in enumerate(ordered):
        if not module.id or not module.id.replace("_", "").isalnum():
            raise RuntimeError(f"invalid-panel-module-id:{module.id}")
        if module.tier not in TIERS:
            raise RuntimeError(f"invalid-panel-module-tier:{module.id}:{module.tier}")
        if module.maturity not in MATURITY:
            raise RuntimeError(f"invalid-panel-module-maturity:{module.id}:{module.maturity}")
        missing = set(module.depends_on) - known
        if missing:
            raise RuntimeError(f"missing-panel-module-dependency:{module.id}:{','.join(sorted(missing))}")
        if module.id in module.depends_on:
            raise RuntimeError(f"self-panel-module-dependency:{module.id}")
        late = [dependency for dependency in module.depends_on if position[dependency] >= index]
        if late:
            raise RuntimeError(f"unordered-panel-module-dependency:{module.id}:{','.join(sorted(late))}")
        if len(module.feature_prefixes) != len(set(module.feature_prefixes)):
            raise RuntimeError(f"duplicate-panel-module-feature-prefix:{module.id}")
        if len(module.provider_services) != len(set(module.provider_services)):
            raise RuntimeError(f"duplicate-panel-module-provider:{module.id}")
        if module.endpoint_namespace is not None and (not module.endpoint_namespace or not module.endpoint_namespace.replace("_", "").isalnum()):
            raise RuntimeError(f"invalid-panel-module-endpoint-namespace:{module.id}")
    validate_extensions(known)
    return ordered


def initialize_module_schemas() -> None:
    for module in validate_modules():
        if module.schema_hook is not None:
            module.schema_hook()


def _register_module_routes(app: Flask, module: PanelModule) -> None:
    namespace = module.endpoint_namespace
    if namespace is None:
        module.route_hook(app)
        return
    original = app.add_url_rule

    def namespaced_add_url_rule(rule, endpoint=None, view_func=None, **options):
        local_endpoint = endpoint
        if local_endpoint is None and view_func is not None:
            local_endpoint = view_func.__name__
        if local_endpoint is not None:
            local_endpoint = f"{namespace}.{local_endpoint}"
        return original(rule, endpoint=local_endpoint, view_func=view_func, **options)

    app.add_url_rule = namespaced_add_url_rule  # type: ignore[method-assign]
    try:
        module.route_hook(app)
    finally:
        app.add_url_rule = original  # type: ignore[method-assign]


def register_modules(app: Flask) -> None:
    for module in validate_modules():
        _register_module_routes(app, module)


def module_catalog() -> list[dict[str, object]]:
    return [
        {
            "id": module.id,
            "label": module.label,
            "tier": module.tier,
            "depends_on": list(module.depends_on),
            "feature_prefixes": list(module.feature_prefixes),
            "provider_services": list(module.provider_services),
            "ui_view": module.ui_view,
            "maturity": module.maturity,
            "has_schema": module.schema_hook is not None,
            "endpoint_namespace": module.endpoint_namespace,
        }
        for module in validate_modules()
    ]