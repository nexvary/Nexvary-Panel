from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from flask import Flask

from .account_schema import ensure_account_schema
from .mail_schema import ensure_mail_schema
from .ops_schema import ensure_ops_schema
from .transfer_schema import ensure_transfer_schema
from .routes_accounts import register_account_routes
from .routes_advanced_ops import register_advanced_ops_routes
from .routes_auth import register_auth_routes
from .routes_dns import register_dns_routes
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


MODULES: tuple[PanelModule, ...] = (
    PanelModule("auth", "Authentication", "core", register_auth_routes),
    PanelModule("sites", "Sites", "hosting", register_site_routes, feature_prefixes=("domains.", "software."), provider_services=("nexvary-panel-agent",)),
    PanelModule("operations", "Operations", "core", register_ops_routes, depends_on=("auth",), provider_services=("nexvary-panel-agent",)),
    PanelModule("platform", "Platform", "core", register_platform_routes, depends_on=("auth",)),
    PanelModule("security", "Security", "security", register_security_routes, depends_on=("auth",), feature_prefixes=("security.",)),
    PanelModule("health", "Health and Doctor", "observability", register_health_routes, depends_on=("auth",)),
    PanelModule("fusion", "Fusion Providers", "providers", register_fusion_routes, depends_on=("auth",)),
    PanelModule("dns", "DNS Inventory", "hosting", register_dns_routes, depends_on=("sites",), feature_prefixes=("domains.dns",)),
    PanelModule("vault", "Secret Vault", "security", register_vault_routes, depends_on=("auth",), provider_services=("nexvary-panel-vault",)),
    PanelModule("integrations", "Integration Targets", "providers", register_integration_routes, depends_on=("vault",), provider_services=("nexvary-panel-provider",)),
    PanelModule("remote_backup", "Remote Backup", "hosting", register_remote_backup_routes, depends_on=("integrations",), feature_prefixes=("files.backups",), provider_services=("nexvary-panel-provider",)),
    PanelModule("hosting", "Hosting Suite", "hosting", register_hosting_routes, depends_on=("auth",)),
    PanelModule("webtools", "Web Tools", "hosting", register_webtools_routes, depends_on=("hosting", "sites"), feature_prefixes=("domains.", "metrics."), provider_services=("nexvary-panel-webtools",)),
    PanelModule("schedules", "Scheduled Tasks", "automation", register_schedule_routes, depends_on=("hosting", "sites"), feature_prefixes=("advanced.cron",), provider_services=("nexvary-panel-scheduler",)),
    PanelModule("accounts", "Accounts and Resellers", "hosting", register_account_routes, schema_hook=ensure_account_schema, depends_on=("hosting",), feature_prefixes=("server.accounts", "server.resellers")),
    PanelModule("mail", "Email Center", "hosting", register_mail_routes, schema_hook=ensure_mail_schema, depends_on=("accounts", "sites"), feature_prefixes=("email.",), provider_services=("nexvary-panel-mail",)),
    PanelModule("transfers", "Transfer Center", "hosting", register_transfer_routes, schema_hook=ensure_transfer_schema, depends_on=("accounts", "sites"), feature_prefixes=("files.ftp", "files.sftp"), provider_services=("nexvary-panel-transfer",)),
    PanelModule("advanced_ops", "Advanced Hosting Ops", "server", register_advanced_ops_routes, schema_hook=ensure_ops_schema, depends_on=("hosting", "sites", "integrations"), feature_prefixes=("domains.", "security.ssl", "email.", "software.php", "databases.postgresql", "server."), provider_services=("nexvary-panel-ops", "nexvary-panel-postgres")),
)


def validate_modules(modules: Iterable[PanelModule] = MODULES) -> tuple[PanelModule, ...]:
    ordered = tuple(modules)
    ids = [module.id for module in ordered]
    if len(ids) != len(set(ids)):
        raise RuntimeError("duplicate-panel-module-id")
    known = set(ids)
    for module in ordered:
        if not module.id or not module.id.replace("_", "").isalnum():
            raise RuntimeError(f"invalid-panel-module-id:{module.id}")
        missing = set(module.depends_on) - known
        if missing:
            raise RuntimeError(f"missing-panel-module-dependency:{module.id}:{','.join(sorted(missing))}")
        if module.id in module.depends_on:
            raise RuntimeError(f"self-panel-module-dependency:{module.id}")
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
            "has_schema": module.schema_hook is not None,
        }
        for module in validate_modules()
    ]
