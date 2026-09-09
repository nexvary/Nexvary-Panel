from __future__ import annotations

import os
import secrets
import time
from pathlib import Path

from flask import Flask

from .config import VERSION
from .core import csrf_guard, csrf_token, ensure_schema_columns
from .routes_auth import register_auth_routes
from .routes_ops import register_ops_routes
from .routes_sites import register_site_routes
from .routes_platform import register_platform_routes
from .routes_security import register_security_routes
from .routes_health import register_health_routes
from .routes_fusion import register_fusion_routes
from .routes_dns import register_dns_routes
from .routes_vault import register_vault_routes
from .routes_integrations import register_integration_routes
from .routes_remote_backup import register_remote_backup_routes

ROOT = Path(__file__).resolve().parents[1]


def create_app() -> Flask:
    app = Flask(__name__, template_folder=str(ROOT / "templates"), static_folder=str(ROOT / "static"))
    app.config.update(
        SECRET_KEY=os.environ.get("NVP_SECRET", secrets.token_hex(32)),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=os.environ.get("NVP_COOKIE_SECURE", "1").lower() not in {"0", "false", "no"},
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=3600 * 8,
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    )
    ensure_schema_columns()
    app.before_request(csrf_guard)
    app.jinja_env.globals.update(csrf_token=csrf_token, panel_version=VERSION)

    @app.template_filter("when")
    def when(ts: int | None) -> str:
        return "—" if not ts else time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))

    @app.template_filter("bytes")
    def bytes_filter(value: int | float | None) -> str:
        n = float(value or 0)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024 or unit == "TB":
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    register_auth_routes(app)
    register_site_routes(app)
    register_ops_routes(app)
    register_platform_routes(app)
    register_security_routes(app)
    register_health_routes(app)
    register_fusion_routes(app)
    register_dns_routes(app)
    register_vault_routes(app)
    register_integration_routes(app)
    register_remote_backup_routes(app)
    return app
