from __future__ import annotations

import secrets
import sqlite3
import time

from flask import jsonify, request, session

from .config import DOMAIN_RE, PASSWORD_RE, USER_RE
from .core import agent_call, audit, db, password_hash
from .security import role_required, step_up_required


def _safe_account(row) -> dict:
    return {
        "username": str(row["username"]),
        "reseller_owner": str(row["reseller_owner"]),
        "primary_domain": str(row["primary_domain"]),
        "package_id": int(row["package_id"]),
        "package_name": str(row["package_name"]),
        "status": str(row["status"]),
        "login_enabled": bool(row["login_enabled"]),
        "created_at": int(row["created_at"]),
        "updated_at": int(row["updated_at"]),
    }


def _safe_reseller(row) -> dict:
    return {
        "username": str(row["username"]),
        "max_accounts": int(row["max_accounts"]),
        "enabled": bool(row["enabled"]),
        "login_enabled": bool(row["login_enabled"]),
        "accounts": int(row["accounts"]),
        "created_at": int(row["created_at"]),
        "updated_at": int(row["updated_at"]),
    }


def _owns_account(owner: str) -> bool:
    return session.get("role") == "admin" or owner == session.get("user")


def _package_allowed_for_actor(row) -> bool:
    if not row or not row["enabled"]:
        return False
    if session.get("role") == "admin":
        return True
    return str(row["name"]) != "NEXVARY Unlimited"


def _toggle_sites(domains: list[str], desired: str) -> tuple[bool, str]:
    completed: list[str] = []
    rollback = "enable" if desired == "disable" else "disable"
    for domain in domains:
        result = agent_call({"action": "site-toggle", "domain": domain, "desired": desired}, timeout=25)
        if not result.get("ok"):
            for changed in reversed(completed):
                agent_call({"action": "site-toggle", "domain": changed, "desired": rollback}, timeout=25)
            return False, str(result.get("error", f"site transition failed for {domain}"))[:180]
        completed.append(domain)
    return True, ""


def register_account_routes(app):
    @app.get("/api/accounts")
    @role_required("admin", "reseller")
    def accounts_list():
        actor = str(session.get("user", ""))[:64]
        with db() as conn:
            if session.get("role") == "admin":
                rows = conn.execute(
                    """SELECT a.*,p.name AS package_name,u.enabled AS login_enabled
                       FROM hosting_accounts a JOIN hosting_packages p ON p.id=a.package_id
                       JOIN users u ON u.username=a.username ORDER BY a.created_at DESC,a.username"""
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT a.*,p.name AS package_name,u.enabled AS login_enabled
                       FROM hosting_accounts a JOIN hosting_packages p ON p.id=a.package_id
                       JOIN users u ON u.username=a.username WHERE a.reseller_owner=?
                       ORDER BY a.created_at DESC,a.username""",
                    (actor,),
                ).fetchall()
            packages = [
                {"id": int(r["id"]), "name": str(r["name"]), "enabled": bool(r["enabled"])}
                for r in conn.execute("SELECT id,name,enabled FROM hosting_packages WHERE enabled=1 ORDER BY name").fetchall()
                if session.get("role") == "admin" or str(r["name"]) != "NEXVARY Unlimited"
            ]
            reseller = conn.execute("SELECT max_accounts,enabled FROM reseller_profiles WHERE username=?", (actor,)).fetchone()
        limit = int(reseller["max_accounts"]) if reseller else 0
        return jsonify(ok=True, accounts=[_safe_account(r) for r in rows], packages=packages, account_limit=limit)

    @app.get("/api/resellers")
    @role_required("admin")
    def resellers_list():
        with db() as conn:
            rows = conn.execute(
                """SELECT r.username,r.max_accounts,r.enabled,r.created_at,r.updated_at,
                          COALESCE(u.enabled,1) AS login_enabled,COUNT(a.username) AS accounts
                   FROM reseller_profiles r LEFT JOIN users u ON u.username=r.username
                   LEFT JOIN hosting_accounts a ON a.reseller_owner=r.username
                   WHERE r.username!='admin'
                   GROUP BY r.username,r.max_accounts,r.enabled,r.created_at,r.updated_at,u.enabled
                   ORDER BY r.username"""
            ).fetchall()
        return jsonify(ok=True, resellers=[_safe_reseller(r) for r in rows])

    @app.post("/api/resellers")
    @role_required("admin")
    @step_up_required
    def reseller_create():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        try:
            max_accounts = int(data.get("max_accounts", 25))
        except (TypeError, ValueError):
            max_accounts = -1
        if username == "admin" or not USER_RE.fullmatch(username) or not PASSWORD_RE.fullmatch(password) or not 1 <= max_accounts <= 100000:
            return jsonify(ok=False, error="invalid reseller credentials or account limit"), 400
        now = int(time.time())
        salt = secrets.token_hex(16)
        try:
            with db() as conn:
                conn.execute(
                    "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
                    (username, "reseller", salt, password_hash(password, salt), now),
                )
                conn.execute(
                    "INSERT INTO reseller_profiles(username,max_accounts,enabled,created_at,updated_at) VALUES(?,?,1,?,?)",
                    (username, max_accounts, now, now),
                )
        except sqlite3.IntegrityError:
            return jsonify(ok=False, error="username already exists"), 409
        audit("reseller-create", f"reseller={username} max_accounts={max_accounts}")
        return jsonify(ok=True, username=username), 201

    @app.put("/api/resellers/<username>")
    @role_required("admin")
    @step_up_required
    def reseller_update(username: str):
        username = username.strip()
        data = request.get_json(silent=True) or {}
        if not USER_RE.fullmatch(username) or not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        with db() as conn:
            row = conn.execute("SELECT * FROM reseller_profiles WHERE username=? AND username!='admin'", (username,)).fetchone()
            if not row:
                return jsonify(ok=False, error="reseller not found"), 404
            try:
                max_accounts = int(data.get("max_accounts", row["max_accounts"]))
            except (TypeError, ValueError):
                return jsonify(ok=False, error="invalid max_accounts"), 400
            enabled = data.get("enabled", bool(row["enabled"]))
            if not isinstance(enabled, bool) or not 1 <= max_accounts <= 100000:
                return jsonify(ok=False, error="invalid reseller policy"), 400
            conn.execute(
                "UPDATE reseller_profiles SET max_accounts=?,enabled=?,updated_at=? WHERE username=?",
                (max_accounts, 1 if enabled else 0, int(time.time()), username),
            )
            conn.execute("UPDATE users SET enabled=? WHERE username=? AND role='reseller'", (1 if enabled else 0, username))
        audit("reseller-update", f"reseller={username} max_accounts={max_accounts} enabled={int(enabled)}")
        return jsonify(ok=True)

    @app.post("/api/accounts")
    @role_required("admin", "reseller")
    @step_up_required
    def account_create():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        domain = str(data.get("primary_domain", "")).strip().lower()
        try:
            package_id = int(data.get("package_id"))
        except (TypeError, ValueError):
            package_id = 0
        if username == "admin" or not USER_RE.fullmatch(username) or not PASSWORD_RE.fullmatch(password) or not DOMAIN_RE.fullmatch(domain) or package_id < 1:
            return jsonify(ok=False, error="invalid account credentials, domain or package"), 400
        actor = str(session.get("user", ""))[:64]
        owner = "admin" if session.get("role") == "admin" else actor
        now = int(time.time())
        salt = secrets.token_hex(16)
        try:
            with db() as conn:
                package = conn.execute("SELECT id,name,enabled FROM hosting_packages WHERE id=?", (package_id,)).fetchone()
                if not _package_allowed_for_actor(package):
                    return jsonify(ok=False, error="package is not available to this actor"), 403
                if conn.execute("SELECT 1 FROM sites WHERE domain=?", (domain,)).fetchone():
                    return jsonify(ok=False, error="primary domain is already registered as a site"), 409
                profile = conn.execute("SELECT max_accounts,enabled FROM reseller_profiles WHERE username=?", (owner,)).fetchone()
                if not profile or not profile["enabled"]:
                    return jsonify(ok=False, error="reseller profile is disabled"), 403
                used = int(conn.execute("SELECT COUNT(*) FROM hosting_accounts WHERE reseller_owner=?", (owner,)).fetchone()[0])
                if used >= int(profile["max_accounts"]):
                    return jsonify(ok=False, error="reseller account quota reached"), 409
                conn.execute(
                    "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
                    (username, "operator", salt, password_hash(password, salt), now),
                )
                conn.execute(
                    "INSERT INTO hosting_accounts(username,reseller_owner,primary_domain,package_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                    (username, owner, domain, package_id, "active", now, now),
                )
                conn.execute(
                    "INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)",
                    (username, package_id, now),
                )
        except sqlite3.IntegrityError:
            return jsonify(ok=False, error="username or primary domain already exists"), 409
        audit("hosting-account-create", f"account={username} reseller={owner} domain={domain} package_id={package_id}")
        return jsonify(ok=True, username=username), 201

    @app.put("/api/accounts/<username>/package")
    @role_required("admin", "reseller")
    @step_up_required
    def account_package(username: str):
        username = username.strip()
        if not USER_RE.fullmatch(username):
            return jsonify(ok=False, error="invalid account username"), 400
        data = request.get_json(silent=True) or {}
        try:
            package_id = int(data.get("package_id")) if isinstance(data, dict) else 0
        except (TypeError, ValueError):
            package_id = 0
        with db() as conn:
            account = conn.execute("SELECT reseller_owner FROM hosting_accounts WHERE username=?", (username,)).fetchone()
            if not account:
                return jsonify(ok=False, error="hosting account not found"), 404
            if not _owns_account(str(account["reseller_owner"])):
                return jsonify(ok=False, error="hosting account is outside your reseller scope"), 403
            package = conn.execute("SELECT id,name,enabled FROM hosting_packages WHERE id=?", (package_id,)).fetchone()
            if not _package_allowed_for_actor(package):
                return jsonify(ok=False, error="package is not available to this actor"), 403
            now = int(time.time())
            conn.execute("UPDATE hosting_accounts SET package_id=?,updated_at=? WHERE username=?", (package_id, now, username))
            conn.execute(
                """INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)
                   ON CONFLICT(username) DO UPDATE SET package_id=excluded.package_id,assigned_at=excluded.assigned_at""",
                (username, package_id, now),
            )
        audit("hosting-account-package", f"account={username} package_id={package_id}")
        return jsonify(ok=True)

    @app.put("/api/accounts/<username>/status")
    @role_required("admin", "reseller")
    @step_up_required
    def account_status(username: str):
        username = username.strip()
        data = request.get_json(silent=True) or {}
        status = str(data.get("status", "")) if isinstance(data, dict) else ""
        if not USER_RE.fullmatch(username) or status not in {"active", "suspended"}:
            return jsonify(ok=False, error="valid account and active/suspended status required"), 400
        with db() as conn:
            account = conn.execute("SELECT reseller_owner,status FROM hosting_accounts WHERE username=?", (username,)).fetchone()
            if not account:
                return jsonify(ok=False, error="hosting account not found"), 404
            if not _owns_account(str(account["reseller_owner"])):
                return jsonify(ok=False, error="hosting account is outside your reseller scope"), 403
            current_status = str(account["status"])
            if current_status == status:
                return jsonify(ok=True, status=status, scope="control-plane+managed-sites")
            now = int(time.time())
            if status == "suspended":
                sites = conn.execute("SELECT domain,enabled FROM sites WHERE owner=? ORDER BY domain", (username,)).fetchall()
                conn.execute("DELETE FROM account_suspension_sites WHERE username=?", (username,))
                for site in sites:
                    conn.execute(
                        "INSERT INTO account_suspension_sites(username,domain,was_enabled,captured_at) VALUES(?,?,?,?)",
                        (username, str(site["domain"]), 1 if site["enabled"] else 0, now),
                    )
                conn.execute("UPDATE hosting_accounts SET status='suspending',updated_at=? WHERE username=?", (now, username))
                conn.execute("UPDATE users SET enabled=0 WHERE username=? AND role='operator'", (username,))
                domains = [str(site["domain"]) for site in sites if site["enabled"]]
            else:
                snapshots = conn.execute("SELECT domain,was_enabled FROM account_suspension_sites WHERE username=? ORDER BY domain", (username,)).fetchall()
                conn.execute("UPDATE hosting_accounts SET status='activating',updated_at=? WHERE username=?", (now, username))
                domains = [str(site["domain"]) for site in snapshots if site["was_enabled"] and conn.execute("SELECT 1 FROM sites WHERE domain=? AND owner=?", (site["domain"], username)).fetchone()]

        desired = "disable" if status == "suspended" else "enable"
        ok, detail = _toggle_sites(domains, desired)
        if not ok:
            with db() as conn:
                fallback = "active" if status == "suspended" else "suspended"
                conn.execute("UPDATE hosting_accounts SET status=?,updated_at=? WHERE username=?", (fallback, int(time.time()), username))
                conn.execute("UPDATE users SET enabled=? WHERE username=? AND role='operator'", (1 if fallback == "active" else 0, username))
                if status == "suspended":
                    conn.execute("DELETE FROM account_suspension_sites WHERE username=?", (username,))
            audit("hosting-account-status-failed", f"account={username} requested={status} sites={len(domains)}")
            return jsonify(ok=False, error=detail or "managed site transition failed"), 503

        now = int(time.time())
        with db() as conn:
            if status == "suspended":
                if domains:
                    placeholders = ",".join("?" for _ in domains)
                    conn.execute(f"UPDATE sites SET enabled=0 WHERE owner=? AND domain IN ({placeholders})", (username, *domains))
                conn.execute("UPDATE hosting_accounts SET status='suspended',updated_at=? WHERE username=?", (now, username))
                conn.execute("UPDATE users SET enabled=0 WHERE username=? AND role='operator'", (username,))
            else:
                if domains:
                    placeholders = ",".join("?" for _ in domains)
                    conn.execute(f"UPDATE sites SET enabled=1 WHERE owner=? AND domain IN ({placeholders})", (username, *domains))
                conn.execute("UPDATE hosting_accounts SET status='active',updated_at=? WHERE username=?", (now, username))
                conn.execute("UPDATE users SET enabled=1 WHERE username=? AND role='operator'", (username,))
                conn.execute("DELETE FROM account_suspension_sites WHERE username=?", (username,))
        audit("hosting-account-status", f"account={username} status={status} sites={len(domains)} scope=control-plane+managed-sites")
        return jsonify(ok=True, status=status, affected_sites=len(domains), scope="control-plane+managed-sites")
