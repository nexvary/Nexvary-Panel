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
    assert len(modules) >= 26
    assert tuple(modules) == MODULES
    ids = [m.id for m in modules]
    assert len(ids) == len(set(ids))
    assert {"hosting", "domains", "dnssec", "accounts", "mail", "transfers", "advanced_ops", "autossl", "deliverability", "domain_health", "wordpress_lifecycle", "wordpress_staging", "wordpress_updates", "security", "vault"}.issubset(ids)

    catalog = module_catalog()
    assert len(catalog) == len(modules)
    by_id = {item["id"]: item for item in catalog}
    assert "nexvary-panel-mail" in by_id["mail"]["provider_services"]
    assert "nexvary-panel-transfer" in by_id["transfers"]["provider_services"]
    assert "nexvary-panel-postgres" in by_id["advanced_ops"]["provider_services"]
    assert "nexvary-panel-webtools" in by_id["domains"]["provider_services"]
    assert "nexvary-panel-wordpress" in by_id["wordpress_updates"]["provider_services"]
    assert "nexvary-panel-wordpress" in by_id["wordpress_staging"]["provider_services"]
    assert by_id["domains"]["has_schema"] is True
    assert by_id["wordpress_staging"]["has_schema"] is True
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
        "/api/hosting/catalog",
        "/api/domains/aliases",
        "/api/domain-health",
        "/api/accounts",
        "/api/mail",
        "/api/transfers",
        "/api/advanced/status",
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
        assert "domain_aliases" in tables
        assert "wordpress_staging" in tables

print("Nexvary Panel module registry architecture gate: PASS")
