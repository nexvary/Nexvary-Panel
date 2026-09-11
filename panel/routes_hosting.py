from __future__ import annotations

import re
import sqlite3
import time

from flask import jsonify, request, session

from .core import audit, db
from .hosting_features import CATEGORY_LABELS, FEATURES, feature_catalog, maturity_summary
from .security import login_required, role_required, step_up_required

PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{2,47}$")
LIMIT_KEYS = (
    "disk_mb", "bandwidth_mb", "max_sites", "max_databases", "max_mailboxes",
    "max_ftp_accounts", "max_cron_jobs", "max_subdomains", "max_backups",
)
LIMIT_MAX = {
    "disk_mb": 10 * 1024 * 1024,
    "bandwidth_mb": 100 * 1024 * 1024,
    "max_sites": 100000,
    "max_databases": 100000,
    "max_mailboxes": 100000,
    "max_ftp_accounts": 100000,
    "max_cron_jobs": 100000,
    "max_subdomains": 100000,
    "max_backups": 100000,
}
DEFAULT_ACCOUNT_FEATURES = {
    "files.file_manager", "files.disk_usage", "files.backups", "files.backup_wizard", "files.git",
    "domains.domains", "domains.redirects", "domains.zone_editor",
    "databases.mariadb", "databases.wizard",
    "metrics.visitors", "metrics.errors", "metrics.bandwidth", "metrics.resource_usage",
    "security.ssl_tls", "security.two_factor", "security.ssl_status",
    "software.wordpress", "software.php_manager", "software.node", "software.python", "software.optimize",
    "advanced.cron", "advanced.dns_trace", "advanced.error_pages",
    "preferences.password", "preferences.language", "preferences.users",
}


def _safe_package(row) -> dict:
    return {
        "id": int(row["id"]),
        "name": str(row["name"]),
        "description": str(row["description"] or ""),
        **{key: int(row[key]) for key in LIMIT_KEYS},
        "enabled": bool(row["enabled"]),
        "created_at": int(row["created_at"]),
        "updated_at": int(row["updated_at"]),
    }


def _package_for_user(conn, username: str, role: str | None = None):
    row = conn.execute(
        """SELECT p.* FROM user_hosting_package u
           JOIN hosting_packages p ON p.id=u.package_id
           WHERE u.username=? AND p.enabled=1""",
        (username,),
    ).fetchone()
    if row:
        return row
    effective_role = str(role or session.get("role") or "operator")
    fallback = "NEXVARY Unlimited" if effective_role == "admin" else "NEXVARY Core"
    return conn.execute("SELECT * FROM hosting_packages WHERE name=? AND enabled=1", (fallback,)).fetchone()


def _enabled_features(conn, package_id: int | None, role: str) -> set[str]:
    if role == "admin" and package_id is None:
        return set(FEATURES)
    explicit: dict[str, bool] = {}
    if package_id is not None:
        rows = conn.execute(
            "SELECT feature_id,enabled FROM hosting_package_features WHERE package_id=?", (package_id,)
        ).fetchall()
        explicit = {str(row["feature_id"]): bool(row["enabled"]) for row in rows}
    base = set(FEATURES) if role == "admin" else set(DEFAULT_ACCOUNT_FEATURES)
    for feature_id, enabled in explicit.items():
        if enabled:
            base.add(feature_id)
        else:
            base.discard(feature_id)
    return base


def _validate_limits(data: dict, current: dict | None = None) -> dict[str, int]:
    out: dict[str, int] = {}
    for key in LIMIT_KEYS:
        raw = data.get(key, current.get(key) if current else None)
        if raw is None:
            raise ValueError(f"missing {key}")
        if isinstance(raw, bool):
            raise ValueError(f"invalid {key}")
        try:
            value = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid {key}") from exc
        if value < 0 or value > LIMIT_MAX[key]:
            raise ValueError(f"{key} out of range")
        out[key] = value
    return out


def _package_payload(data: dict, current: dict | None = None) -> tuple[str, str, dict[str, int], int]:
    name = str(data.get("name", current.get("name") if current else "")).strip()
    if not PACKAGE_NAME_RE.fullmatch(name):
        raise ValueError("package name must be 3-48 safe characters")
    description = str(data.get("description", current.get("description") if current else "")).strip()
    if len(description) > 240 or any(ord(ch) < 32 and ch not in "\t" for ch in description):
        raise ValueError("invalid package description")
    limits = _validate_limits(data, current)
    enabled_raw = data.get("enabled", current.get("enabled") if current else True)
    enabled = 1 if bool(enabled_raw) else 0
    return name, description, limits, enabled


def _usage_for_user(conn, username: str) -> dict[str, int | None]:
    mariadb = int(conn.execute("SELECT COUNT(*) FROM databases WHERE owner=?", (username,)).fetchone()[0])
    postgres = int(conn.execute("SELECT COUNT(*) FROM postgres_resources WHERE owner=?", (username,)).fetchone()[0])
    return {
        "disk_mb": None,
        "bandwidth_mb": None,
        "max_sites": int(conn.execute("SELECT COUNT(*) FROM sites WHERE owner=?", (username,)).fetchone()[0]),
        "max_databases": mariadb + postgres,
        "max_mailboxes": int(conn.execute("SELECT COUNT(*) FROM mailboxes WHERE owner=? AND enabled=1", (username,)).fetchone()[0]),
        "max_ftp_accounts": int(conn.execute("SELECT COUNT(*) FROM transfer_accounts WHERE owner=? AND enabled=1", (username,)).fetchone()[0]),
        "max_cron_jobs": int(conn.execute("SELECT COUNT(*) FROM scheduled_tasks WHERE owner=?", (username,)).fetchone()[0]),
        "max_subdomains": int(conn.execute("SELECT COUNT(*) FROM domain_aliases WHERE owner=?", (username,)).fetchone()[0]),
        "max_backups": int(conn.execute("SELECT COUNT(*) FROM backups WHERE owner=?", (username,)).fetchone()[0]),
    }


def _package_impact(conn, username: str, target_package) -> dict:
    user = conn.execute("SELECT username,role,enabled FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        raise LookupError("user not found")
    role = str(user["role"])
    current = _package_for_user(conn, username, role=role)
    current_id = int(current["id"]) if current else None
    target_id = int(target_package["id"])
    current_features = _enabled_features(conn, current_id, role)
    target_features = _enabled_features(conn, target_id, role)
    removed = sorted(current_features - target_features)
    added = sorted(target_features - current_features)
    usage = _usage_for_user(conn, username)
    violations: list[dict] = []
    limits: dict[str, dict] = {}
    for key in LIMIT_KEYS:
        used = usage[key]
        limit = int(target_package[key])
        over = used is not None and int(used) > limit
        if over:
            violations.append({"limit": key, "used": int(used), "target": limit, "excess": int(used) - limit})
        limits[key] = {"used": used, "target": limit, "over": bool(over), "measured": used is not None}
    return {
        "username": username,
        "current_package": _safe_package(current) if current else None,
        "target_package": _safe_package(target_package),
        "same_package": current_id == target_id,
        "limits": limits,
        "violations": violations,
        "removed_features": removed,
        "added_features": added,
        "safe_to_assign": not violations,
        "unmeasured": [key for key in ("disk_mb", "bandwidth_mb") if usage[key] is None],
        "policy": "hard quota violations block package assignment; unmeasured disk/bandwidth are reported but do not silently claim compliance",
    }


def register_hosting_routes(app):
    @app.get("/api/hosting/catalog")
    @login_required
    def hosting_catalog():
        username = str(session.get("user", ""))[:64]
        role = str(session.get("role", "user"))
        with db() as conn:
            package = _package_for_user(conn, username, role=role)
            package_id = int(package["id"]) if package else None
            enabled = _enabled_features(conn, package_id, role)
        catalog = []
        for item in feature_catalog():
            row = dict(item)
            row["enabled"] = row["feature_id"] in enabled
            row["operational"] = row["maturity"] in {"native", "foundation"}
            catalog.append(row)
        return jsonify(
            ok=True,
            package=_safe_package(package) if package else None,
            catalog=catalog,
            categories=CATEGORY_LABELS,
            maturity=maturity_summary(),
        )

    @app.get("/api/hosting/packages")
    @role_required("admin")
    def hosting_packages():
        with db() as conn:
            packages = [_safe_package(row) for row in conn.execute("SELECT * FROM hosting_packages ORDER BY name").fetchall()]
            feature_rows = conn.execute(
                "SELECT package_id,feature_id,enabled FROM hosting_package_features ORDER BY package_id,feature_id"
            ).fetchall()
            assignments = [dict(row) for row in conn.execute(
                "SELECT username,package_id,assigned_at FROM user_hosting_package ORDER BY username"
            ).fetchall()]
        feature_map: dict[str, dict[str, bool]] = {}
        for row in feature_rows:
            feature_map.setdefault(str(int(row["package_id"])), {})[str(row["feature_id"])] = bool(row["enabled"])
        return jsonify(ok=True, packages=packages, feature_overrides=feature_map, assignments=assignments)

    @app.post("/api/hosting/package-impact")
    @role_required("admin")
    def hosting_package_impact():
        data = request.get_json(silent=True) or {}
        username = str(data.get("username", "")).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username):
            return jsonify(ok=False, error="invalid username"), 400
        try:
            package_id = int(data.get("package_id"))
        except (TypeError, ValueError):
            return jsonify(ok=False, error="invalid package_id"), 400
        with db() as conn:
            package = conn.execute("SELECT * FROM hosting_packages WHERE id=? AND enabled=1", (package_id,)).fetchone()
            if not package:
                return jsonify(ok=False, error="package not found or disabled"), 404
            try:
                impact = _package_impact(conn, username, package)
            except LookupError:
                return jsonify(ok=False, error="user not found"), 404
        return jsonify(ok=True, impact=impact)

    @app.post("/api/hosting/packages")
    @role_required("admin")
    @step_up_required
    def hosting_package_create():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        try:
            name, description, limits, enabled = _package_payload(data)
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        now = int(time.time())
        try:
            with db() as conn:
                cur = conn.execute(
                    """INSERT INTO hosting_packages(
                         name,description,disk_mb,bandwidth_mb,max_sites,max_databases,max_mailboxes,max_ftp_accounts,
                         max_cron_jobs,max_subdomains,max_backups,enabled,created_at,updated_at
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (name, description, *[limits[key] for key in LIMIT_KEYS], enabled, now, now),
                )
                package_id = int(cur.lastrowid)
        except sqlite3.IntegrityError:
            return jsonify(ok=False, error="package name already exists"), 409
        audit("hosting-package-create", f"package={name}")
        return jsonify(ok=True, id=package_id), 201

    @app.put("/api/hosting/packages/<int:package_id>")
    @role_required("admin")
    @step_up_required
    def hosting_package_update(package_id: int):
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        with db() as conn:
            row = conn.execute("SELECT * FROM hosting_packages WHERE id=?", (package_id,)).fetchone()
        if not row:
            return jsonify(ok=False, error="package not found"), 404
        current = _safe_package(row)
        try:
            name, description, limits, enabled = _package_payload(data, current)
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        now = int(time.time())
        try:
            with db() as conn:
                conn.execute(
                    """UPDATE hosting_packages SET name=?,description=?,disk_mb=?,bandwidth_mb=?,max_sites=?,max_databases=?,
                       max_mailboxes=?,max_ftp_accounts=?,max_cron_jobs=?,max_subdomains=?,max_backups=?,enabled=?,updated_at=?
                       WHERE id=?""",
                    (name, description, *[limits[key] for key in LIMIT_KEYS], enabled, now, package_id),
                )
        except sqlite3.IntegrityError:
            return jsonify(ok=False, error="package name already exists"), 409
        audit("hosting-package-update", f"package_id={package_id} name={name}")
        return jsonify(ok=True)

    @app.put("/api/hosting/packages/<int:package_id>/features/<path:feature_id>")
    @role_required("admin")
    @step_up_required
    def hosting_package_feature(package_id: int, feature_id: str):
        if feature_id not in FEATURES:
            return jsonify(ok=False, error="unknown feature"), 404
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict) or "enabled" not in data or not isinstance(data["enabled"], bool):
            return jsonify(ok=False, error="enabled must be boolean"), 400
        now = int(time.time())
        with db() as conn:
            if not conn.execute("SELECT 1 FROM hosting_packages WHERE id=?", (package_id,)).fetchone():
                return jsonify(ok=False, error="package not found"), 404
            conn.execute(
                """INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,?,?)
                   ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=excluded.enabled,updated_at=excluded.updated_at""",
                (package_id, feature_id, 1 if data["enabled"] else 0, now),
            )
        audit("hosting-feature-policy", f"package_id={package_id} feature={feature_id} enabled={int(data['enabled'])}")
        return jsonify(ok=True)

    @app.put("/api/hosting/users/<username>/package")
    @role_required("admin")
    @step_up_required
    def hosting_user_package(username: str):
        username = username.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username):
            return jsonify(ok=False, error="invalid username"), 400
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        try:
            package_id = int(data.get("package_id"))
        except (TypeError, ValueError):
            return jsonify(ok=False, error="invalid package_id"), 400
        now = int(time.time())
        with db() as conn:
            if not conn.execute("SELECT 1 FROM users WHERE username=? AND enabled=1", (username,)).fetchone():
                return jsonify(ok=False, error="user not found or disabled"), 404
            package = conn.execute("SELECT * FROM hosting_packages WHERE id=? AND enabled=1", (package_id,)).fetchone()
            if not package:
                return jsonify(ok=False, error="package not found or disabled"), 404
            impact = _package_impact(conn, username, package)
            if impact["violations"]:
                return jsonify(ok=False, error="package assignment blocked by current resource usage", impact=impact), 409
            conn.execute(
                """INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)
                   ON CONFLICT(username) DO UPDATE SET package_id=excluded.package_id,assigned_at=excluded.assigned_at""",
                (username, package_id, now),
            )
        audit("hosting-package-assign", f"user={username} package_id={package_id} removed_features={len(impact['removed_features'])}")
        return jsonify(ok=True, impact=impact)
