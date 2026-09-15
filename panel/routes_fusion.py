from __future__ import annotations

from flask import jsonify

from .core import role_required
from .providers import provider_snapshot


def register_fusion_routes(app):
    @app.get("/api/fusion/providers")
    @role_required("admin", "operator", "viewer")
    def fusion_providers():
        return jsonify(ok=True, **provider_snapshot())

    @app.get("/api/fusion/policy")
    @role_required("admin", "operator", "viewer")
    def fusion_policy():
        snap = provider_snapshot()
        return jsonify(ok=True, policy=snap["policy"], summary=snap["summary"])
