from __future__ import annotations

import re
import time

from flask import jsonify, request, session

from .config import DOMAIN_RE
from .core import audit, db
from .hosting_policy import feature_allowed
from .security import role_required, step_up_required
from .wordpress_client import wordpress_call

SNAPSHOT_RE = re.compile(r"^[0-9]{10}-[a-f0-9]{8}$")


def _owner_role(conn, owner: str) -> str:
    if owner == "admin":
        return "admin"
    row = conn.execute("SELECT role FROM users WHERE username=?", (owner,)).fetchone()
    return str(row["role"]) if row else "operator"


def _context(conn, domain: str):
    if not DOMAIN_RE.fullmatch(domain):
        return None, None
    site = conn.execute("SELECT domain,kind,owner,enabled FROM sites WHERE domain=?", (domain,)).fetchone()
    if not site:
        return None, None
    owner = str(site["owner"])
    if session.get("role") != "admin" and owner != str(session.get("user", "")):
        return None, None
    role = _owner_role(conn, owner)
    if not feature_allowed("software.wordpress", username=owner, role=role, connection=conn):
        return site, None
    return site, role


def _provider_error(result: dict):
    error = str(result.get("error", "wordpress provider unavailable"))[:180]
    status = 404 if error in {"wordpress-not-detected", "wordpress-root-unavailable", "wordpress-snapshot-not-found"} else 503
    return jsonify(ok=False, error=error), status


def _authorized_domain(domain: str):
    with db() as conn:
        site, role = _context(conn, domain)
        if not site:
            return None, jsonify(ok=False, error="WordPress site outside your scope"), 403
        if role is None:
            return None, jsonify(ok=False, error="software.wordpress disabled by hosting policy"), 403
        return site, None, None


def register_wordpress_lifecycle_routes(app):
    @app.get("/api/wordpress/lifecycle")
    @role_required("admin", "operator", "viewer")
    def wordpress_lifecycle_inventory():
        domain = str(request.args.get("domain", "")).strip().lower().rstrip(".")
        with db() as conn:
            site, role = _context(conn, domain)
            if not site:
                return jsonify(ok=False, error="WordPress site outside your scope"), 403
            if role is None:
                return jsonify(ok=False, error="software.wordpress disabled by hosting policy"), 403
            registered = conn.execute(
                "SELECT domain,db_name,db_user,status,version,owner,created_at,updated_at FROM wordpress_instances WHERE domain=?",
                (domain,),
            ).fetchone()
        result = wordpress_call({"action": "inventory", "domain": domain}, timeout=25)
        if not result.get("ok"):
            return _provider_error(result)
        version = str(result.get("version", ""))[:40]
        now = int(time.time())
        if registered:
            with db() as conn:
                conn.execute(
                    "UPDATE wordpress_instances SET status=?,version=?,updated_at=? WHERE domain=?",
                    ("maintenance" if result.get("maintenance") else "active", version, now, domain),
                )
        return jsonify(
            ok=True,
            domain=domain,
            registered=bool(registered),
            version=version,
            maintenance=bool(result.get("maintenance")),
            config_present=bool(result.get("config_present")),
            plugin_count=int(result.get("plugin_count", 0) or 0),
            theme_count=int(result.get("theme_count", 0) or 0),
            plugins=(result.get("plugins") or [])[:500],
            themes=(result.get("themes") or [])[:500],
        )

    @app.post("/api/wordpress/integrity")
    @role_required("admin", "operator")
    def wordpress_integrity():
        data = request.get_json(silent=True) or {}
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        site, denied, status = _authorized_domain(domain)
        if denied is not None:
            return denied, status
        result = wordpress_call({"action": "integrity", "domain": domain}, timeout=45)
        audit("wordpress-integrity", f"domain={domain} status={'ok' if result.get('integrity_ok') else 'attention'}")
        if not result.get("ok"):
            return _provider_error(result)
        return jsonify(result)

    @app.put("/api/wordpress/maintenance")
    @role_required("admin", "operator")
    @step_up_required
    def wordpress_maintenance():
        data = request.get_json(silent=True) or {}
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        enabled = data.get("enabled")
        if not isinstance(enabled, bool):
            return jsonify(ok=False, error="enabled must be boolean"), 400
        site, denied, status = _authorized_domain(domain)
        if denied is not None:
            return denied, status
        result = wordpress_call({"action": "maintenance", "domain": domain, "enabled": enabled}, timeout=20)
        if not result.get("ok"):
            return _provider_error(result)
        with db() as conn:
            conn.execute(
                "UPDATE wordpress_instances SET status=?,updated_at=? WHERE domain=?",
                ("maintenance" if enabled else "active", int(time.time()), domain),
            )
        audit("wordpress-maintenance", f"domain={domain} enabled={int(enabled)}")
        return jsonify(ok=True, domain=domain, maintenance=enabled)

    @app.post("/api/wordpress/repair-core")
    @role_required("admin", "operator")
    @step_up_required
    def wordpress_repair_core():
        data = request.get_json(silent=True) or {}
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        site, denied, status = _authorized_domain(domain)
        if denied is not None:
            return denied, status
        result = wordpress_call({"action": "repair-core", "domain": domain}, timeout=90)
        if not result.get("ok"):
            audit("wordpress-core-repair", f"domain={domain} status=failed")
            return _provider_error(result)
        repaired = max(0, int(result.get("repaired", 0) or 0))
        snapshot_id = str(result.get("snapshot_id", ""))[:32]
        audit("wordpress-core-repair", f"domain={domain} repaired={repaired} snapshot={snapshot_id or 'none'}")
        return jsonify(
            ok=True,
            domain=domain,
            version=str(result.get("version", ""))[:40],
            repaired=repaired,
            snapshot_id=snapshot_id,
            integrity_ok=bool(result.get("integrity_ok")),
            detail=str(result.get("detail", ""))[:180],
        )

    @app.post("/api/wordpress/repair-rollback")
    @role_required("admin", "operator")
    @step_up_required
    def wordpress_repair_rollback():
        data = request.get_json(silent=True) or {}
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        snapshot_id = str(data.get("snapshot_id", "")).strip().lower()
        if not SNAPSHOT_RE.fullmatch(snapshot_id):
            return jsonify(ok=False, error="invalid WordPress repair snapshot"), 400
        site, denied, status = _authorized_domain(domain)
        if denied is not None:
            return denied, status
        result = wordpress_call({"action": "repair-rollback", "domain": domain, "snapshot_id": snapshot_id}, timeout=60)
        if not result.get("ok"):
            audit("wordpress-core-repair-rollback", f"domain={domain} snapshot={snapshot_id} status=failed")
            return _provider_error(result)
        rolled_back = max(0, int(result.get("rolled_back", 0) or 0))
        audit("wordpress-core-repair-rollback", f"domain={domain} snapshot={snapshot_id} files={rolled_back}")
        return jsonify(ok=True, domain=domain, snapshot_id=snapshot_id, rolled_back=rolled_back)
