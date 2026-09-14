from __future__ import annotations

from collections import defaultdict

from flask import jsonify

from .hosting_features import CATEGORY_LABELS, FEATURES
from .security import role_required

MATURITY_WEIGHT = {"native": 1.0, "foundation": 0.65, "planned": 0.0}


def _feature_row(item) -> dict:
    return {
        "feature_id": item.feature_id,
        "category": item.category,
        "label": item.label,
        "scope": item.scope,
        "maturity": item.maturity,
        "risk": item.risk,
        "provider": item.provider,
        "description": item.description,
        "operational": item.maturity != "planned",
    }


def _coverage(rows: list) -> dict:
    total = len(rows)
    native = sum(1 for row in rows if row.maturity == "native")
    foundation = sum(1 for row in rows if row.maturity == "foundation")
    planned = sum(1 for row in rows if row.maturity == "planned")
    operational = native + foundation
    weighted = sum(MATURITY_WEIGHT.get(row.maturity, 0.0) for row in rows)
    return {
        "total": total,
        "native": native,
        "foundation": foundation,
        "planned": planned,
        "operational": operational,
        "coverage_percent": round((operational / total * 100.0), 1) if total else 0.0,
        "maturity_index": round((weighted / total * 100.0), 1) if total else 0.0,
    }


def build_parity_report() -> dict:
    # Local import avoids a module-registry import cycle while keeping this report
    # generated from the live registry instead of a duplicated module list.
    from .module_registry import module_catalog

    features = list(FEATURES.values())
    by_category: dict[str, list] = defaultdict(list)
    for item in features:
        by_category[item.category].append(item)

    categories = []
    for category, rows in sorted(by_category.items(), key=lambda pair: CATEGORY_LABELS.get(pair[0], pair[0])):
        categories.append({
            "id": category,
            "label": CATEGORY_LABELS.get(category, category),
            **_coverage(rows),
        })

    account_rows = [item for item in features if item.scope == "account"]
    server_rows = [item for item in features if item.scope == "server"]
    gaps = [
        _feature_row(item)
        for item in sorted(
            (item for item in features if item.maturity == "planned"),
            key=lambda item: (0 if item.scope == "account" else 1, CATEGORY_LABELS.get(item.category, item.category), item.label),
        )
    ]
    modules = module_catalog()
    module_summary = {
        "total": len(modules),
        "native": sum(1 for item in modules if item["maturity"] == "native"),
        "provider": sum(1 for item in modules if item["maturity"] == "provider"),
        "foundation": sum(1 for item in modules if item["maturity"] == "foundation"),
    }
    return {
        "summary": _coverage(features),
        "scopes": {
            "account": _coverage(account_rows),
            "server": _coverage(server_rows),
        },
        "categories": categories,
        "gaps": gaps,
        "modules": module_summary,
        "methodology": {
            "coverage": "Operational coverage counts Native + Foundation capabilities in Nexvary Panel's clean-room capability registry.",
            "maturity_index": "Internal weighted maturity index: Native=1.0, Foundation=0.65, Planned=0.0.",
            "warning": "This is an internal capability coverage metric, not an independent benchmark or a claim of feature-for-feature equivalence with cPanel, Plesk or DirectAdmin.",
        },
    }


def register_parity_routes(app):
    @app.get("/api/platform/parity")
    @role_required("admin")
    def platform_parity():
        return jsonify(ok=True, **build_parity_report())
