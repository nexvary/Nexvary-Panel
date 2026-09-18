from __future__ import annotations

import os
import secrets
import time
from pathlib import Path

from flask import Flask

from .config import VERSION
from .core import csrf_guard, csrf_token, ensure_schema_columns
from .maintenance_policy import OPERATIONS as MAINTENANCE_OPERATIONS
from .module_registry import initialize_module_schemas, register_modules
from .routes_mail_dav import register_mail_dav_routes
from .routes_mail_global_filters import register_mail_global_filter_routes
from .routes_mail_lists import register_mail_list_routes
from .routes_migration_center import register_migration_center_routes

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
    initialize_module_schemas()
    app.before_request(csrf_guard)

    @app.after_request
    def security_headers(response):
        # Browser hardening is deliberately centralized so every HTML/API response inherits
        # the same baseline. CSP stays compatible with the existing self-hosted UI while
        # denying framing, plugin objects and unexpected network destinations.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
            "form-action 'self'; img-src 'self' data:; font-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'",
        )
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    # Read-only policy metadata for the graphical Maintenance Center. Templates can
    # explain the server-enforced boundary without accepting executable/argv data.
    app.jinja_env.globals.update(
        csrf_token=csrf_token,
        panel_version=VERSION,
        maintenance_operations=tuple(MAINTENANCE_OPERATIONS.values()),
    )

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

    register_modules(app)
    register_mail_dav_routes(app)
    register_mail_global_filter_routes(app)
    register_mail_list_routes(app)
    register_migration_center_routes(app)
    return app
