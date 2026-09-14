from __future__ import annotations

import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-release-contract-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_AGENT_SOCK"] = str(pathlib.Path(tmp) / "missing-agent.sock")
    os.environ["NVP_VAULT_SOCK"] = str(pathlib.Path(tmp) / "missing-vault.sock")
    os.environ["NVP_PROVIDER_SOCK"] = str(pathlib.Path(tmp) / "missing-provider.sock")
    os.environ["NVP_MAIL_SOCK"] = str(pathlib.Path(tmp) / "missing-mail.sock")
    os.environ["NVP_TRANSFER_SOCK"] = str(pathlib.Path(tmp) / "missing-transfer.sock")
    os.environ["NVP_OPS_SOCK"] = str(pathlib.Path(tmp) / "missing-ops.sock")

    from panel import create_app
    from panel.hosting_features import FEATURES
    from panel.module_registry import MODULES, validate_modules

    modules = validate_modules()
    by_id = {module.id: module for module in modules}

    critical_modules = {
        "domains",
        "dnssec",
        "advanced_ops",
        "autossl",
        "deliverability",
        "domain_health",
        "change_safety",
        "domain_guardian",
        "mail",
        "mail_security",
        "mail_automation",
        "mail_queue",
        "transfers",
        "database_lifecycle",
        "wordpress_lifecycle",
        "wordpress_staging",
        "wordpress_publish",
        "wordpress_updates",
        "wordpress_smart_guard",
    }
    missing_modules = critical_modules - set(by_id)
    assert not missing_modules, f"critical modules missing: {sorted(missing_modules)}"

    critical_features = {
        "domains.domains",
        "domains.zone_editor",
        "domains.dynamic_dns",
        "security.ssl_tls",
        "security.ssl_status",
        "email.accounts",
        "email.forwarders",
        "email.autoresponders",
        "email.filters",
        "email.spam_filters",
        "email.delivery_trace",
        "email.deliverability",
        "databases.mariadb",
        "databases.postgresql",
        "software.wordpress",
        "whm.mail_queue",
        "whm.multi_account",
        "whm.transfers",
    }
    missing_features = critical_features - set(FEATURES)
    assert not missing_features, f"critical features missing: {sorted(missing_features)}"
    planned = sorted(feature_id for feature_id in critical_features if FEATURES[feature_id].maturity == "planned")
    assert not planned, f"operational critical features regressed to planned: {planned}"

    # Every non-foundation module that advertises feature coverage must resolve at
    # least one advertised prefix to a real catalog capability. This catches stale
    # registry wiring without forbidding intentionally preview-only foundations.
    feature_ids = set(FEATURES)
    for module in modules:
        if module.maturity == "foundation" or not module.feature_prefixes:
            continue
        matches = {
            feature_id
            for prefix in module.feature_prefixes
            for feature_id in feature_ids
            if feature_id == prefix or feature_id.startswith(prefix)
        }
        assert matches, f"module {module.id} advertises no known feature capability"
        assert any(FEATURES[feature_id].maturity != "planned" for feature_id in matches), (
            module.id,
            "all advertised feature capabilities are planned",
        )

    # Privileged/provider-backed critical modules must point to systemd units that
    # actually exist in the repository. A UI/API module without its provider unit
    # is not releasable.
    provider_critical = {
        "advanced_ops",
        "autossl",
        "deliverability",
        "mail",
        "mail_security",
        "mail_automation",
        "mail_queue",
        "transfers",
        "database_lifecycle",
        "wordpress_lifecycle",
        "wordpress_staging",
        "wordpress_publish",
        "wordpress_updates",
        "wordpress_smart_guard",
    }
    for module_id in provider_critical:
        module = by_id[module_id]
        assert module.provider_services, f"critical provider module {module_id} has no declared provider service"
        for service in module.provider_services:
            filename = service if service.endswith((".service", ".timer")) else f"{service}.service"
            assert (ROOT / "systemd" / filename).is_file(), f"missing provider unit for {module_id}: {filename}"

    app = create_app()
    routes = {rule.rule for rule in app.url_map.iter_rules()}
    critical_routes = {
        "/api/advanced/dns/preview",
        "/api/advanced/ssl",
        "/api/autossl",
        "/api/autossl/preflight",
        "/api/domain-guardian",
        "/api/domain-guardian/prepare",
        "/api/wordpress/smart-guard",
        "/api/wordpress/smart-guard/preview",
    }
    missing_routes = critical_routes - routes
    assert not missing_routes, f"critical operational routes missing: {sorted(missing_routes)}"

    # Enforce the architectural promise that no generic browser-to-root terminal
    # endpoint appears under obvious shell/exec route names.
    forbidden_fragments = ("/terminal", "/shell", "/exec", "/command")
    unsafe_routes = sorted(route for route in routes if any(fragment in route.lower() for fragment in forbidden_fragments))
    assert not unsafe_routes, f"generic command surface detected: {unsafe_routes}"

print("Nexvary Panel strict critical capability release contract: PASS")
