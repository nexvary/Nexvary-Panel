from __future__ import annotations

from flask import jsonify, request, session

from .core import audit, db
from .hosting_policy import feature_allowed
from .php_ini_client import php_ini_call
from .security import role_required, step_up_required


def _scoped_php_site(conn, domain: str):
    row = conn.execute("SELECT domain,kind,owner,enabled FROM sites WHERE domain=?", (domain,)).fetchone()
    if not row or str(row["kind"]) != "php":
        return None
    role = str(session.get("role", "viewer"))
    user = str(session.get("user", ""))
    if role != "admin" and str(row["owner"]) != user:
        return None
    return row


def _target_policy(conn, owner: str) -> bool:
    target_role = "admin" if owner == "admin" else "operator"
    return feature_allowed("software.php_ini", username=owner, role=target_role, connection=conn)


def register_php_ini_routes(app):
    @app.get("/api/php-ini/sites")
    @role_required("admin", "operator")
    def php_ini_sites():
        role = str(session.get("role", "viewer"))
        user = str(session.get("user", ""))
        with db() as conn:
            if role == "admin":
                rows = conn.execute("SELECT domain,owner,enabled FROM sites WHERE kind='php' ORDER BY domain").fetchall()
            else:
                rows = conn.execute("SELECT domain,owner,enabled FROM sites WHERE kind='php' AND owner=? ORDER BY domain", (user,)).fetchall()
            sites = [dict(row) for row in rows if _target_policy(conn, str(row["owner"]))]
        return jsonify(ok=True, sites=sites)

    @app.get("/api/php-ini")
    @role_required("admin", "operator")
    def php_ini_get():
        domain = str(request.args.get("domain", "")).strip().lower().rstrip(".")
        with db() as conn:
            site = _scoped_php_site(conn, domain)
            if not site:
                return jsonify(ok=False, error="PHP site is outside your scope"), 404
            owner = str(site["owner"])
            if not _target_policy(conn, owner):
                return jsonify(ok=False, error="software.php_ini is disabled by target hosting policy"), 403
        result = php_ini_call({"action": "get", "domain": domain})
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "PHP INI provider unavailable"))[:160]), 503
        return jsonify(ok=True, domain=domain, managed=bool(result.get("managed")), settings=result.get("settings") or {}, allowed=result.get("allowed") or [])

    @app.put("/api/php-ini/<domain>")
    @role_required("admin", "operator")
    @step_up_required
    def php_ini_set(domain: str):
        domain = str(domain or "").strip().lower().rstrip(".")
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict) or not isinstance(data.get("settings"), dict):
            return jsonify(ok=False, error="settings object is required"), 400
        with db() as conn:
            site = _scoped_php_site(conn, domain)
            if not site:
                return jsonify(ok=False, error="PHP site is outside your scope"), 404
            owner = str(site["owner"])
            if not _target_policy(conn, owner):
                return jsonify(ok=False, error="software.php_ini is disabled by target hosting policy"), 403
        result = php_ini_call({"action": "set", "domain": domain, "settings": data["settings"]}, timeout=20)
        if not result.get("ok"):
            error = str(result.get("error", "PHP INI update failed"))[:160]
            status = 400 if error.startswith("invalid-") or error.startswith("malformed-") else 503
            return jsonify(ok=False, error=error), status
        keys = sorted(str(key)[:40] for key in (result.get("settings") or {}).keys())
        audit("php-ini-update", f"domain={domain} owner={owner} keys={','.join(keys)}")
        return jsonify(ok=True, domain=domain, managed=True, settings=result.get("settings") or {}, allowed=result.get("allowed") or [])
