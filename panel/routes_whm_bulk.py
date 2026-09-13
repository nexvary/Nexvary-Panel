from __future__ import annotations

import re
import time

from flask import jsonify, request

from .core import audit, db
from .routes_hosting import _package_impact
from .security import role_required, step_up_required

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MAX_BULK_ACCOUNTS = 100


def _payload(data: object) -> tuple[list[str], int]:
    if not isinstance(data, dict):
        raise ValueError("invalid request")
    raw = data.get("usernames")
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_BULK_ACCOUNTS:
        raise ValueError(f"usernames must contain 1-{MAX_BULK_ACCOUNTS} accounts")
    usernames = [str(value).strip() for value in raw]
    if any(not USERNAME_RE.fullmatch(username) for username in usernames):
        raise ValueError("invalid account username")
    if len(usernames) != len(set(usernames)):
        raise ValueError("duplicate account username")
    try:
        package_id = int(data.get("package_id"))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid package_id") from exc
    if package_id < 1:
        raise ValueError("invalid package_id")
    return usernames, package_id


def _preview(conn, usernames: list[str], package_id: int) -> tuple[dict | None, list[dict], list[dict]]:
    package = conn.execute("SELECT * FROM hosting_packages WHERE id=? AND enabled=1", (package_id,)).fetchone()
    if not package:
        return None, [], [{"error": "package not found or disabled"}]
    impacts: list[dict] = []
    errors: list[dict] = []
    for username in usernames:
        account = conn.execute(
            """SELECT a.username,a.status,u.enabled,u.role
                 FROM hosting_accounts a JOIN users u ON u.username=a.username
                WHERE a.username=?""",
            (username,),
        ).fetchone()
        if not account:
            errors.append({"username": username, "error": "hosting account not found"})
            continue
        if str(account["role"]) != "operator":
            errors.append({"username": username, "error": "bulk package assignment targets hosting accounts only"})
            continue
        if not bool(account["enabled"]) or str(account["status"]) != "active":
            errors.append({"username": username, "error": "hosting account is not active"})
            continue
        try:
            impacts.append(_package_impact(conn, username, package))
        except LookupError:
            errors.append({"username": username, "error": "user not found"})
    return package, impacts, errors


def _response(usernames: list[str], package_id: int, impacts: list[dict], errors: list[dict]) -> dict:
    blocked = [impact for impact in impacts if not impact.get("safe_to_assign")]
    return {
        "usernames": usernames,
        "package_id": package_id,
        "count": len(usernames),
        "impacts": impacts,
        "errors": errors,
        "blocked": blocked,
        "safe_to_apply": not errors and not blocked and len(impacts) == len(usernames),
        "policy": "all-or-nothing: any missing/inactive account or hard quota violation blocks the complete bulk assignment",
    }


def register_whm_bulk_routes(app):
    @app.post("/api/whm/bulk/package-preview")
    @role_required("admin")
    def whm_bulk_package_preview():
        try:
            usernames, package_id = _payload(request.get_json(silent=True) or {})
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        with db() as conn:
            package, impacts, errors = _preview(conn, usernames, package_id)
        if not package:
            return jsonify(ok=False, error="package not found or disabled"), 404
        return jsonify(ok=True, preview=_response(usernames, package_id, impacts, errors))

    @app.post("/api/whm/bulk/package-assign")
    @role_required("admin")
    @step_up_required
    def whm_bulk_package_assign():
        try:
            usernames, package_id = _payload(request.get_json(silent=True) or {})
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        now = int(time.time())
        with db() as conn:
            package, impacts, errors = _preview(conn, usernames, package_id)
            if not package:
                return jsonify(ok=False, error="package not found or disabled"), 404
            preview = _response(usernames, package_id, impacts, errors)
            if not preview["safe_to_apply"]:
                return jsonify(ok=False, error="bulk package assignment blocked by account state or resource usage", preview=preview), 409
            for username in usernames:
                conn.execute(
                    """INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)
                       ON CONFLICT(username) DO UPDATE SET package_id=excluded.package_id,assigned_at=excluded.assigned_at""",
                    (username, package_id, now),
                )
        sample = ",".join(usernames[:10])
        audit("whm-bulk-package-assign", f"package_id={package_id} count={len(usernames)} sample={sample}")
        return jsonify(ok=True, applied=len(usernames), package_id=package_id, preview=preview)
