from __future__ import annotations

import re
import time

from flask import jsonify, request

from .core import audit, db
from .routes_accounts import _toggle_sites
from .routes_hosting import _package_impact
from .security import role_required, step_up_required

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MAX_BULK_ACCOUNTS = 100


def _usernames(data: object) -> list[str]:
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
    return usernames


def _payload(data: object) -> tuple[list[str], int]:
    usernames = _usernames(data)
    try:
        package_id = int(data.get("package_id"))  # type: ignore[union-attr]
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid package_id") from exc
    if package_id < 1:
        raise ValueError("invalid package_id")
    return usernames, package_id


def _status_payload(data: object) -> tuple[list[str], str]:
    usernames = _usernames(data)
    status = str(data.get("status", "")).strip().lower()  # type: ignore[union-attr]
    if status not in {"active", "suspended"}:
        raise ValueError("status must be active or suspended")
    return usernames, status


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


def _status_preview(conn, usernames: list[str], target: str) -> tuple[list[dict], list[dict]]:
    plans: list[dict] = []
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
        current = str(account["status"])
        if str(account["role"]) != "operator":
            errors.append({"username": username, "error": "bulk lifecycle targets hosting accounts only"})
            continue
        if current not in {"active", "suspended"}:
            errors.append({"username": username, "error": f"account is in transitional state: {current}"})
            continue
        if current == target:
            plans.append({"username": username, "current_status": current, "target_status": target, "affected_sites": 0, "domains": [], "no_op": True})
            continue
        if target == "suspended":
            sites = conn.execute("SELECT domain,enabled FROM sites WHERE owner=? ORDER BY domain", (username,)).fetchall()
            domains = [str(site["domain"]) for site in sites if bool(site["enabled"])]
        else:
            snapshots = conn.execute(
                "SELECT domain,was_enabled FROM account_suspension_sites WHERE username=? ORDER BY domain",
                (username,),
            ).fetchall()
            domains = [
                str(site["domain"])
                for site in snapshots
                if bool(site["was_enabled"])
                and conn.execute("SELECT 1 FROM sites WHERE domain=? AND owner=?", (site["domain"], username)).fetchone()
            ]
        plans.append(
            {
                "username": username,
                "current_status": current,
                "target_status": target,
                "affected_sites": len(domains),
                "domains": domains,
                "no_op": False,
            }
        )
    return plans, errors


def _status_response(usernames: list[str], target: str, plans: list[dict], errors: list[dict]) -> dict:
    transitions = [plan for plan in plans if not plan["no_op"]]
    noops = [plan for plan in plans if plan["no_op"]]
    return {
        "usernames": usernames,
        "status": target,
        "count": len(usernames),
        "transitions": transitions,
        "noops": noops,
        "errors": errors,
        "affected_sites": sum(int(plan["affected_sites"]) for plan in transitions),
        "safe_to_apply": not errors and len(plans) == len(usernames),
        "policy": "preview-first, all-or-nothing account lifecycle; managed-site changes are rolled back if any provider transition fails",
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

    @app.post("/api/whm/bulk/status-preview")
    @role_required("admin")
    def whm_bulk_status_preview():
        try:
            usernames, target = _status_payload(request.get_json(silent=True) or {})
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        with db() as conn:
            plans, errors = _status_preview(conn, usernames, target)
        return jsonify(ok=True, preview=_status_response(usernames, target, plans, errors))

    @app.post("/api/whm/bulk/status-apply")
    @role_required("admin")
    @step_up_required
    def whm_bulk_status_apply():
        try:
            usernames, target = _status_payload(request.get_json(silent=True) or {})
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400

        with db() as conn:
            plans, errors = _status_preview(conn, usernames, target)
            preview = _status_response(usernames, target, plans, errors)
            if not preview["safe_to_apply"]:
                return jsonify(ok=False, error="bulk account lifecycle blocked by account state", preview=preview), 409

        transitions = [plan for plan in plans if not plan["no_op"]]
        if not transitions:
            return jsonify(ok=True, applied=0, unchanged=len(plans), status=target, preview=preview)

        now = int(time.time())
        with db() as conn:
            for plan in transitions:
                username = str(plan["username"])
                if target == "suspended":
                    sites = conn.execute("SELECT domain,enabled FROM sites WHERE owner=? ORDER BY domain", (username,)).fetchall()
                    conn.execute("DELETE FROM account_suspension_sites WHERE username=?", (username,))
                    for site in sites:
                        conn.execute(
                            "INSERT INTO account_suspension_sites(username,domain,was_enabled,captured_at) VALUES(?,?,?,?)",
                            (username, str(site["domain"]), 1 if site["enabled"] else 0, now),
                        )
                    conn.execute("UPDATE hosting_accounts SET status='suspending',updated_at=? WHERE username=?", (now, username))
                    conn.execute("UPDATE users SET enabled=0 WHERE username=? AND role='operator'", (username,))
                else:
                    conn.execute("UPDATE hosting_accounts SET status='activating',updated_at=? WHERE username=?", (now, username))

        desired = "disable" if target == "suspended" else "enable"
        reverse = "enable" if target == "suspended" else "disable"
        completed_domains: list[str] = []
        failure = ""
        for plan in transitions:
            domains = list(plan["domains"])
            ok, detail = _toggle_sites(domains, desired)
            if not ok:
                failure = detail or f"managed site transition failed for {plan['username']}"
                break
            completed_domains.extend(domains)

        if failure:
            if completed_domains:
                _toggle_sites(completed_domains, reverse)
            with db() as conn:
                for plan in transitions:
                    username = str(plan["username"])
                    fallback = str(plan["current_status"])
                    conn.execute("UPDATE hosting_accounts SET status=?,updated_at=? WHERE username=?", (fallback, int(time.time()), username))
                    conn.execute("UPDATE users SET enabled=? WHERE username=? AND role='operator'", (1 if fallback == "active" else 0, username))
                    if target == "suspended":
                        conn.execute("DELETE FROM account_suspension_sites WHERE username=?", (username,))
            audit("whm-bulk-account-status-failed", f"status={target} count={len(transitions)} completed_sites={len(completed_domains)}")
            return jsonify(ok=False, error=failure, preview=preview), 503

        now = int(time.time())
        with db() as conn:
            for plan in transitions:
                username = str(plan["username"])
                domains = list(plan["domains"])
                if domains:
                    placeholders = ",".join("?" for _ in domains)
                    conn.execute(
                        f"UPDATE sites SET enabled=? WHERE owner=? AND domain IN ({placeholders})",
                        (0 if target == "suspended" else 1, username, *domains),
                    )
                conn.execute("UPDATE hosting_accounts SET status=?,updated_at=? WHERE username=?", (target, now, username))
                conn.execute("UPDATE users SET enabled=? WHERE username=? AND role='operator'", (1 if target == "active" else 0, username))
                if target == "active":
                    conn.execute("DELETE FROM account_suspension_sites WHERE username=?", (username,))

        sample = ",".join(str(plan["username"]) for plan in transitions[:10])
        audit(
            "whm-bulk-account-status",
            f"status={target} applied={len(transitions)} unchanged={len(plans)-len(transitions)} sites={preview['affected_sites']} sample={sample}",
        )
        return jsonify(
            ok=True,
            applied=len(transitions),
            unchanged=len(plans) - len(transitions),
            affected_sites=preview["affected_sites"],
            status=target,
            preview=preview,
        )
