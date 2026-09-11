from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from flask import Flask

from .account_schema import ensure_account_schema
from .domain_schema import ensure_domain_schema
from .mail_schema import ensure_mail_schema
from .ops_schema import ensure_ops_schema
from .transfer_schema import ensure_transfer_schema
from .routes_accounts import register_account_routes
from .routes_advanced_ops import register_advanced_ops_routes
from .routes_auth import register_auth_routes
from .routes_autossl import register_autossl_routes
from .routes_dns import register_dns_routes
from .routes_domains import register_domain_routes
from .routes_dnssec import register_dnssec_routes
from .routes_fusion import register_fusion_routes
from .routes_health import register_health_routes
from .routes_hosting import register_hosting_routes
from .routes_integrations import register_integration_routes
from .routes_mail import register_mail_routes
from .routes_ops import register_ops_routes
from .routes_platform import register_platform_routes
from .routes_remote_backup import register_remote_backup_routes
from .routes_schedules import register_schedule_routes
from .routes_security import register_security_routes
from .routes_sites import register_site_routes
from .routes_transfers import register_transfer_routes
from .routes_vault import register_vault_routes
from .routes_webtools import register_webtools_routes

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


MODULES: tuple[PanelModule, ...] = (
    PanelModule("auth", "Authentication", "core", register_auth_routes),
    PanelModule("sites", "Sites", "hosting", register_site_routes, feature_prefixes=("domains.", "software."), provider_services=("nexvary-panel-agent",), ui_view="sites", maturity="provider"),
    PanelModule("operations", "Operations", "core", register_ops_routes, depends_on=("auth",), provider_services=("nexvary-panel-agent",), maturity="provider"),
    PanelModule("platform", "Platform", "core", register_platform_routes, depends_on=("auth",)),
    PanelModule("security", "Security", "security", register_security_routes, depends_on=("auth",), feature_prefixes=("security.",), ui_view="security"),
    PanelModule("health", "Health and Doctor", "observability", register_health_routes, depends_on=("auth",), ui_view="services"),
    PanelModule("fusion", "Fusion Providers", "providers", register_fusion_routes, depends_on=("auth",), ui_view="fusion"),
    PanelModule("dns", "DNS Inventory", "hosting", register_dns_routes, depends_on=("sites",), feature_prefixes=("domains.",), ui_view="dns"),
    PanelModule("vault", "Secret Vault", "security", register_vault_routes, depends_on=("auth",), provider_services=("nexvary-panel-vault",), ui_view="vault", maturity="provider"),
    PanelModule("integrations", "Integration Targets", "providers", register_integration_routes, depends_on=("vault",), provider_services=("nexvary-panel-provider",), ui_view="integrations", maturity="provider"),
    PanelModule("remote_backup", "Remote Backup", "hosting", register_remote_backup_routes, depends_on=("integrations",), feature_prefixes=("files.backups",), provider_services=("nexvary-panel-provider",), ui_view="backups", maturity="provider"),
    PanelModule("hosting", "Hosting Suite", "hosting", register_hosting_routes, depends_on=("auth",), ui_view="hosting"),
    PanelModule("domains", "Domain Lifecycle", "hosting", register_domain_routes, schema_hook=ensure_domain_schema, depends_on=("hosting", "sites"), feature_prefixes=("domains.",), provider_services=("nexvary-panel-webtools",), ui_view="webtools", maturity="provider"),
    PanelModule("dnssec", "DNSSEC Lifecycle", "hosting", register_dnssec_routes, depends_on=("domains", "integrations"), feature_prefixes=("domains.zone_editor",), provider_services=("nexvary-panel-ops",), ui_view="webtools", maturity="provider"),
    PanelModule("webtools", "Web Tools", "hosting", register_webtools_routes, depends_on=("hosting", "sites"), feature_prefixes=("domains.", "metrics."), provider_services=("nexvary-panel-webtools",), ui_view="webtools", maturity="provider"),
    PanelModule("schedules", "Scheduled Tasks", "automation", register_schedule_routes, depends_on=("hosting", "sites"), feature_prefixes=("advanced.cron",), provider_services=("nexvary-panel-scheduler",), ui_view="schedules", maturity="provider"),
    PanelModule("accounts", "Accounts and Resellers", "hosting", register_account_routes, schema_hook=ensure_account_schema, depends_on=("hosting",), feature_prefixes=("whm.accounts", "whm.resellers"), ui_view="accounts"),
    PanelModule("mail", "Email Center", "hosting", register_mail_routes, schema_hook=ensure_mail_schema, depends_on=("accounts", "sites"), feature_prefixes=("email.",), provider_services=("nexvary-panel-mail",), ui_view="mail", maturity="provider"),
    PanelModule("transfers", "Transfer Center", "hosting", register_transfer_routes, schema_hook=ensure_transfer_schema, depends_on=("accounts", "sites"), feature_prefixes=("files.ftp", "files.sftp"), provider_services=("nexvary-panel-transfer",), ui_view="transfers", maturity="provider"),
    PanelModule("advanced_ops", "Advanced Hosting Ops", "server", register_advanced_ops_routes, schema_hook=ensure_ops_schema, depends_on=("hosting", "sites", "integrations"), feature_prefixes=("domains.", "security.ssl", "email.", "software.php", "databases.postgresql", "whm."), provider_services=("nexvary-panel-ops", "nexvary-panel-postgres"), ui_view="advancedops", maturity="provider"),
    PanelModule("autossl", "AutoSSL Policy", "automation", register_autossl_routes, depends_on=("advanced_ops",), feature_prefixes=("security.ssl",), provider_services=("nexvary-panel-autossl.timer", "nexvary-panel-ops"), ui_view="advancedops", maturity="provider"),
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
    return ordered


def initialize_module_schemas() -> None:
    for module in validate_modules():
        if module.schema_hook is not None:
            module.schema_hook()


def register_modules(app: Flask) -> None:
    for module in validate_modules():
        module.route_hook(app)


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
        }
        for module in validate_modules()
    ]
