from __future__ import annotations

import re

from flask import jsonify, request, session

from .config import DOMAIN_RE
from .core import audit, db
from .hosting_policy import feature_allowed
from .security import role_required, step_up_required
from .wordpress_client import wordpress_call

KIND_SET = {"plugin", "theme"}
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")
SNAPSHOT_RE = re.compile(r"^[0-9]{10}-[a-f0-9]{8}$")


def _owner_role(conn, owner: str) -> str:
    if owner == "admin":
        return "admin"
    row = conn.execute("SELECT role FROM users WHERE username=?", (owner,)).fetchone()
    return str(row["role"]) if row else "operator"


def _authorized(domain: str) -> tuple[bool, tuple | None]:
    if not DOMAIN_RE.fullmatch(domain):
        return False, (jsonify(ok=False, error="invalid WordPress domain"), 400)
    with db() as conn:
        site = conn.execute("SELECT owner FROM sites WHERE domain=?", (domain,)).fetchone()
        if not site:
            return False, (jsonify(ok=False, error="WordPress site outside your scope"), 403)
        owner = str(site["owner"])
        if session.get("role") != "admin" and owner != str(session.get("user", "")):
            return False, (jsonify(ok=False, error="WordPress site outside your scope"), 403)
        if not feature_allowed("software.wordpress", username=owner, role=_owner_role(conn, owner), connection=conn):
            return False, (jsonify(ok=False, error="software.wordpress disabled by hosting policy"), 403)
    return True, None


def _component(data: dict) -> tuple[str, str, str] | None:
    domain = str(data.get("domain", "")).strip().lower().rstrip(".")
    kind = str(data.get("kind", "")).strip().lower()
    slug = str(data.get("slug", "")).strip().lower()
    if not DOMAIN_RE.fullmatch(domain) or kind not in KIND_SET or not SLUG_RE.fullmatch(slug):
        return None
    return domain, kind, slug


def _provider_error(result: dict):
    error = str(result.get("error", "wordpress component provider unavailable"))[:180]
    status = 404 if error in {"wordpress-component-not-installed", "wordpress-not-detected", "wordpress-root-unavailable", "wordpress-snapshot-not-found"} else 409 if error in {"wordpress-component-version-validation-failed", "wordpress-component-snapshot-invalid"} else 503
    return jsonify(ok=False, error=error), status


def register_wordpress_update_routes(app):
    @app.get("/api/wordpress/components/check")
    @role_required("admin", "operator", "viewer")
    def wordpress_component_check():
        data = {
            "domain": request.args.get("domain", ""),
            "kind": request.args.get("kind", ""),
            "slug": request.args.get("slug", ""),
        }
        parsed = _component(data)
        if not parsed:
            return jsonify(ok=False, error="invalid WordPress component request"), 400
        domain, kind, slug = parsed
        allowed, denied = _authorized(domain)
        if not allowed:
            return denied
        result = wordpress_call({"action": "component-check", "domain": domain, "kind": kind, "slug": slug}, timeout=35)
        if not result.get("ok"):
            return _provider_error(result)
        return jsonify(result)

    @app.post("/api/wordpress/components/update")
    @role_required("admin", "operator")
    @step_up_required
    def wordpress_component_update():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        parsed = _component(data)
        if not parsed:
            return jsonify(ok=False, error="invalid WordPress component request"), 400
        domain, kind, slug = parsed
        allowed, denied = _authorized(domain)
        if not allowed:
            return denied
        result = wordpress_call({"action": "component-update", "domain": domain, "kind": kind, "slug": slug}, timeout=120)
        if not result.get("ok"):
            audit("wordpress-component-update", f"domain={domain} kind={kind} slug={slug} status=failed")
            return _provider_error(result)
        audit(
            "wordpress-component-update",
            f"domain={domain} kind={kind} slug={slug} updated={int(bool(result.get('updated')))} snapshot={str(result.get('snapshot_id',''))[:32] or 'none'}",
        )
        return jsonify(result)

    @app.post("/api/wordpress/components/rollback")
    @role_required("admin", "operator")
    @step_up_required
    def wordpress_component_rollback():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        snapshot_id = str(data.get("snapshot_id", "")).strip().lower()
        if not DOMAIN_RE.fullmatch(domain) or not SNAPSHOT_RE.fullmatch(snapshot_id):
            return jsonify(ok=False, error="invalid WordPress component rollback request"), 400
        allowed, denied = _authorized(domain)
        if not allowed:
            return denied
        result = wordpress_call({"action": "component-rollback", "domain": domain, "snapshot_id": snapshot_id}, timeout=90)
        if not result.get("ok"):
            audit("wordpress-component-rollback", f"domain={domain} snapshot={snapshot_id} status=failed")
            return _provider_error(result)
        audit(
            "wordpress-component-rollback",
            f"domain={domain} kind={str(result.get('kind',''))[:16]} slug={str(result.get('slug',''))[:100]} snapshot={snapshot_id}",
        )
        return jsonify(result)
