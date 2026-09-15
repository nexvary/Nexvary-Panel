from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class ExtensionManifest:
    extension_id: str
    label: str
    category: str
    description: str
    api_prefixes: tuple[str, ...]
    requires_modules: tuple[str, ...]
    provider_services: tuple[str, ...] = ()
    maturity: str = "provider"
    default_enabled: bool = True

    def as_dict(self) -> dict:
        data = asdict(self)
        data["api_prefixes"] = list(self.api_prefixes)
        data["requires_modules"] = list(self.requires_modules)
        data["provider_services"] = list(self.provider_services)
        return data


EXTENSIONS: tuple[ExtensionManifest, ...] = (
    ExtensionManifest(
        "dnssec",
        "DNSSEC Lifecycle",
        "dns",
        "Curated DNSSEC controls for bound DNS providers.",
        ("/api/dnssec",),
        ("domains", "dnssec"),
        ("nexvary-panel-ops",),
    ),
    ExtensionManifest(
        "autossl",
        "AutoSSL Policy",
        "security",
        "Automatic certificate policy and renewal orchestration.",
        ("/api/autossl",),
        ("advanced_ops", "autossl"),
        ("nexvary-panel-ops", "nexvary-panel-autossl.timer"),
    ),
    ExtensionManifest(
        "mail-queue",
        "Mail Queue Controls",
        "email",
        "Administrative Postfix queue inspection, flush and per-message deletion controls.",
        ("/api/advanced/mail/queue", "/api/advanced/mail/flush"),
        ("mail", "mail_queue"),
        ("nexvary-panel-mail", "nexvary-panel-ops"),
    ),
    ExtensionManifest(
        "deliverability",
        "Mail Deliverability",
        "email",
        "MX/SPF/DKIM/DMARC/MTA-STS/TLS-RPT posture and DNS repair previews.",
        ("/api/mail/deliverability",),
        ("mail", "deliverability"),
        ("nexvary-panel-ops",),
    ),
    ExtensionManifest(
        "fleet",
        "Fleet Orchestration",
        "server",
        "Authenticated multi-node health, capability inventory and allow-listed remote apply orchestration.",
        ("/api/fleet",),
        ("advanced_ops", "fleet"),
        ("nexvary-panel-provider",),
        maturity="provider",
    ),
    ExtensionManifest(
        "migration-center",
        "Migration Center 2.0",
        "hosting",
        "Compatibility inspection and normalized cPanel, DirectAdmin and Plesk migration bundles with rollback-aware restore.",
        ("/api/migration-center",),
        ("advanced_ops",),
        ("nexvary-panel-ops",),
        maturity="provider",
    ),
    ExtensionManifest(
        "wordpress-staging",
        "WordPress Staging & Publish",
        "wordpress",
        "Staging clone, selective publish previews and rollback-aware publishing.",
        ("/api/wordpress/staging",),
        ("wordpress_lifecycle", "wordpress_staging", "wordpress_publish"),
        ("nexvary-panel-wordpress",),
    ),
)

BY_ID = {item.extension_id: item for item in EXTENSIONS}


def extension_catalog() -> list[dict]:
    return [item.as_dict() for item in EXTENSIONS]


def validate_extensions(module_ids: set[str]) -> None:
    ids = [item.extension_id for item in EXTENSIONS]
    if len(ids) != len(set(ids)):
        raise RuntimeError("duplicate-extension-id")
    prefixes: dict[str, str] = {}
    for item in EXTENSIONS:
        if not item.extension_id or not item.extension_id.replace("-", "").isalnum():
            raise RuntimeError(f"invalid-extension-id:{item.extension_id}")
        missing = set(item.requires_modules) - module_ids
        if missing:
            raise RuntimeError(f"extension-missing-module:{item.extension_id}:{','.join(sorted(missing))}")
        for prefix in item.api_prefixes:
            if not prefix.startswith("/api/") or ".." in prefix:
                raise RuntimeError(f"invalid-extension-api-prefix:{item.extension_id}")
            owner = prefixes.get(prefix)
            if owner and owner != item.extension_id:
                raise RuntimeError(f"duplicate-extension-api-prefix:{prefix}")
            prefixes[prefix] = item.extension_id
