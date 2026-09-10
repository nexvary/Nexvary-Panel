from __future__ import annotations

import re
import sqlite3
import time

from flask import jsonify, request, session

from .config import DOMAIN_RE
from .core import audit, db
from .hosting_policy import feature_allowed, package_limit
from .ops_client import ops_call
from .security import role_required, step_up_required
from .webtools_client import webtools_call

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}$")


def _site_scope(conn, domain: str):
    row = conn.execute("SELECT domain,owner,enabled FROM sites WHERE domain=?", (domain,)).fetchone()
    if not row:
        return None
    if session.get("role") != "admin" and str(row["owner"]) != str(session.get("user", "")):
        return None
    return row


def _owner_role(conn, owner: str) -> str:
    if owner == "admin":
        return "admin"
    row = conn.execute("SELECT role FROM users WHERE username=?", (owner,)).fetchone()
    return str(row["role"]) if row else "operator"


def _alias_rows(conn, domain: str) -> list[dict]:
    rows = conn.execute("SELECT id,domain,alias,owner,created_at,updated_at FROM domain_aliases WHERE domain=? ORDER BY alias", (domain,)).fetchall()
    return [dict(row) | {"kind": "subdomain" if str(row["alias"]).endswith("." + domain) else "alias"} for row in rows]


def _sync(conn, domain: str) -> dict:
    aliases = [str(row["alias"]) for row in conn.execute("SELECT alias FROM domain_aliases WHERE domain=? ORDER BY alias", (domain,)).fetchall()]
    return webtools_call({"action": "domain-alias-sync", "domain": domain, "aliases": aliases}, timeout=35)


def _ssl_feature_for_owner(conn, owner: str) -> bool:
    from .hosting_policy import enabled_features, package_for_user
    role = _owner_role(conn, owner)
    package = package_for_user(conn, owner, role)
    package_id = int(package["id"]) if package else None
    return "security.ssl_tls" in enabled_features(conn, package_id, role)


def _package_limit_for_owner(conn, limit_name: str, owner: str) -> int:
    return package_limit(limit_name, username=owner, role=_owner_role(conn, owner), connection=conn)


def register_domain_routes(app):
    @app.get("/api/domains/aliases")
    @role_required("admin", "operator")
    def domain_aliases_list():
        if not feature_allowed("domains.domains"):
            return jsonify(ok=False, error="domains.domains disabled by hosting policy"), 403
        domain = str(request.args.get("domain", "")).strip().lower()
        if not DOMAIN_RE.fullmatch(domain):
            return jsonify(ok=False, error="invalid domain"), 400
        with db() as conn:
            site = _site_scope(conn, domain)
            if not site:
                return jsonify(ok=False, error="site outside your scope"), 403
            rows = _alias_rows(conn, domain)
            owner = str(site["owner"])
            used = int(conn.execute("SELECT COUNT(*) FROM domain_aliases WHERE owner=?", (owner,)).fetchone()[0])
            limit = _package_limit_for_owner(conn, "max_subdomains", owner)
        return jsonify(ok=True, domain=domain, aliases=rows, quota={"used": used, "limit": limit, "remaining": max(0, limit-used)})

    @app.get("/api/domains/lifecycle")
    @role_required("admin", "operator")
    def domain_lifecycle():
        domain = str(request.args.get("domain", "")).strip().lower()
        if not DOMAIN_RE.fullmatch(domain):
            return jsonify(ok=False, error="invalid domain"), 400
        with db() as conn:
            site = _site_scope(conn, domain)
            if not site:
                return jsonify(ok=False, error="site outside your scope"), 403
            owner = str(site["owner"])
            aliases = _alias_rows(conn, domain)
            binding = conn.execute(
                """SELECT b.target_id,t.name,t.provider,t.endpoint,b.updated_at
                   FROM dns_zone_bindings b JOIN integration_targets t ON t.id=b.target_id
                   WHERE b.domain=? AND t.enabled=1""", (domain,)
            ).fetchone()
            changes = conn.execute(
                "SELECT id,operation,record_type,record_name,status,created_at,applied_at FROM dns_changes WHERE domain=? AND owner=? ORDER BY id DESC LIMIT 20",
                (domain, owner),
            ).fetchall()
            policy = conn.execute(
                "SELECT contact_email,auto_renew,renew_before_days,last_check,last_renewal,last_status,last_detail,updated_at FROM ssl_policies WHERE domain=?",
                (domain,),
            ).fetchone()
            ssl_allowed = _ssl_feature_for_owner(conn, owner)
            limit = _package_limit_for_owner(conn, "max_subdomains", owner)
            used = int(conn.execute("SELECT COUNT(*) FROM domain_aliases WHERE owner=?", (owner,)).fetchone()[0])
        ssl = ops_call({"action": "ssl-status", "domain": domain}, timeout=10) if ssl_allowed else {"ok": False, "error": "security.ssl_tls disabled by hosting policy"}
        suggestions = [
            {"record_type": "CNAME", "record_name": item["alias"], "record_value": domain, "ttl": 300}
            for item in aliases
        ]
        return jsonify(
            ok=True, domain=domain, owner=owner, enabled=bool(site["enabled"]), aliases=aliases,
            alias_quota={"used": used, "limit": limit, "remaining": max(0, limit-used)},
            dns_binding=dict(binding) if binding else None, dns_changes=[dict(row) for row in changes],
            dns_suggestions=suggestions, ssl=ssl, ssl_policy=(dict(policy) if policy else {
                "contact_email": "", "auto_renew": 0, "renew_before_days": 30, "last_check": 0,
                "last_renewal": 0, "last_status": "unknown", "last_detail": "", "updated_at": 0,
            }),
        )

    @app.post("/api/domains/aliases")
    @role_required("admin", "operator")
    @step_up_required
    def domain_alias_create():
        if not feature_allowed("domains.domains"):
            return jsonify(ok=False, error="domains.domains disabled by hosting policy"), 403
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        alias = str(data.get("alias", "")).strip().lower().rstrip(".")
        if not DOMAIN_RE.fullmatch(domain) or not DOMAIN_RE.fullmatch(alias) or alias in {domain, f"www.{domain}"}:
            return jsonify(ok=False, error="invalid domain alias"), 400
        now = int(time.time())
        with db() as conn:
            site = _site_scope(conn, domain)
            if not site:
                return jsonify(ok=False, error="site outside your scope"), 403
            owner = str(site["owner"])
            used = int(conn.execute("SELECT COUNT(*) FROM domain_aliases WHERE owner=?", (owner,)).fetchone()[0])
            limit = _package_limit_for_owner(conn, "max_subdomains", owner)
            if limit <= 0 or used >= limit:
                return jsonify(ok=False, error="domain alias/subdomain quota reached"), 409
            if conn.execute("SELECT 1 FROM sites WHERE domain=?", (alias,)).fetchone() or conn.execute("SELECT 1 FROM hosting_accounts WHERE primary_domain=?", (alias,)).fetchone():
                return jsonify(ok=False, error="alias is already reserved by a managed domain or account"), 409
            try:
                conn.execute("INSERT INTO domain_aliases(domain,alias,owner,created_at,updated_at) VALUES(?,?,?,?,?)", (domain, alias, owner, now, now))
            except sqlite3.IntegrityError:
                return jsonify(ok=False, error="domain alias already exists"), 409
            result = _sync(conn, domain)
            if not result.get("ok"):
                conn.rollback()
                return jsonify(ok=False, error=str(result.get("error", "domain alias provider failed"))[:180]), 502
            rows = _alias_rows(conn, domain)
        audit("domain-alias-create", f"domain={domain} alias={alias} owner={owner}")
        return jsonify(ok=True, domain=domain, aliases=rows), 201

    @app.delete("/api/domains/aliases/<int:alias_id>")
    @role_required("admin", "operator")
    @step_up_required
    def domain_alias_delete(alias_id: int):
        if not feature_allowed("domains.domains"):
            return jsonify(ok=False, error="domains.domains disabled by hosting policy"), 403
        with db() as conn:
            row = conn.execute("SELECT id,domain,alias,owner FROM domain_aliases WHERE id=?", (alias_id,)).fetchone()
            if not row or not _site_scope(conn, str(row["domain"])):
                return jsonify(ok=False, error="domain alias not found"), 404
            conn.execute("DELETE FROM domain_aliases WHERE id=?", (alias_id,))
            result = _sync(conn, str(row["domain"]))
            if not result.get("ok"):
                conn.rollback()
                return jsonify(ok=False, error=str(result.get("error", "domain alias provider failed"))[:180]), 502
            rows = _alias_rows(conn, str(row["domain"]))
        audit("domain-alias-delete", f"domain={row['domain']} alias={row['alias']} owner={row['owner']}")
        return jsonify(ok=True, domain=str(row["domain"]), aliases=rows)

    @app.put("/api/domains/ssl-policy")
    @role_required("admin", "operator")
    @step_up_required
    def domain_ssl_policy():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        domain = str(data.get("domain", "")).strip().lower()
        email = str(data.get("contact_email", "")).strip().lower()
        auto_renew = data.get("auto_renew", False)
        try:
            renew_before = int(data.get("renew_before_days", 30))
        except (TypeError, ValueError):
            renew_before = 0
        if not DOMAIN_RE.fullmatch(domain) or not isinstance(auto_renew, bool) or not 7 <= renew_before <= 60:
            return jsonify(ok=False, error="invalid SSL renewal policy"), 400
        if email and not EMAIL_RE.fullmatch(email):
            return jsonify(ok=False, error="valid contact email required"), 400
        with db() as conn:
            site = _site_scope(conn, domain)
            if not site:
                return jsonify(ok=False, error="site outside your scope"), 403
            owner = str(site["owner"])
            if not _ssl_feature_for_owner(conn, owner):
                return jsonify(ok=False, error="security.ssl_tls disabled by hosting policy"), 403
            now = int(time.time())
            conn.execute(
                """INSERT INTO ssl_policies(domain,owner,contact_email,auto_renew,renew_before_days,updated_at)
                   VALUES(?,?,?,?,?,?) ON CONFLICT(domain) DO UPDATE SET owner=excluded.owner,
                   contact_email=excluded.contact_email,auto_renew=excluded.auto_renew,
                   renew_before_days=excluded.renew_before_days,updated_at=excluded.updated_at""",
                (domain, owner, email, 1 if auto_renew else 0, renew_before, now),
            )
        audit("ssl-policy-update", f"domain={domain} auto_renew={int(auto_renew)} renew_before_days={renew_before}")
        return jsonify(ok=True, domain=domain, auto_renew=auto_renew, renew_before_days=renew_before)

    @app.post("/api/domains/ssl/issue")
    @role_required("admin", "operator")
    @step_up_required
    def domain_ssl_issue():
        data = request.get_json(silent=True) or {}
        domain = str(data.get("domain", "")).strip().lower()
        email = str(data.get("contact_email", "")).strip().lower()
        if not EMAIL_RE.fullmatch(email):
            return jsonify(ok=False, error="valid contact email required"), 400
        with db() as conn:
            site = _site_scope(conn, domain)
            if not site:
                return jsonify(ok=False, error="site outside your scope"), 403
            owner = str(site["owner"])
            if not _ssl_feature_for_owner(conn, owner):
                return jsonify(ok=False, error="security.ssl_tls disabled by hosting policy"), 403
        result = ops_call({"action": "ssl-issue", "domain": domain, "email": email}, timeout=240)
        now = int(time.time())
        with db() as conn:
            conn.execute("INSERT INTO ssl_jobs(domain,action,contact_email,status,detail,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                         (domain, "issue", email, "success" if result.get("ok") else "failed", str(result.get("detail", result.get("error", "")))[:1000], owner, now, now))
            conn.execute(
                """INSERT INTO ssl_policies(domain,owner,contact_email,last_check,last_renewal,last_status,last_detail,updated_at)
                   VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(domain) DO UPDATE SET owner=excluded.owner,contact_email=excluded.contact_email,
                   last_check=excluded.last_check,last_renewal=excluded.last_renewal,last_status=excluded.last_status,
                   last_detail=excluded.last_detail,updated_at=excluded.updated_at""",
                (domain, owner, email, now, now if result.get("ok") else 0, "valid" if result.get("ok") else "failed", str(result.get("detail", result.get("error", "")))[:700], now),
            )
        audit("domain-ssl-issue", f"domain={domain} status={'ok' if result.get('ok') else 'failed'}")
        return jsonify(result), (200 if result.get("ok") else 503)

    @app.post("/api/domains/ssl/renew")
    @role_required("admin", "operator")
    @step_up_required
    def domain_ssl_renew():
        data = request.get_json(silent=True) or {}
        domain = str(data.get("domain", "")).strip().lower()
        with db() as conn:
            site = _site_scope(conn, domain)
            if not site:
                return jsonify(ok=False, error="site outside your scope"), 403
            owner = str(site["owner"])
            if not _ssl_feature_for_owner(conn, owner):
                return jsonify(ok=False, error="security.ssl_tls disabled by hosting policy"), 403
            policy = conn.execute("SELECT contact_email FROM ssl_policies WHERE domain=?", (domain,)).fetchone()
            email = str(policy["contact_email"]) if policy else ""
        result = ops_call({"action": "ssl-renew", "domain": domain}, timeout=240)
        now = int(time.time())
        with db() as conn:
            conn.execute("INSERT INTO ssl_jobs(domain,action,contact_email,status,detail,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                         (domain, "renew", email, "success" if result.get("ok") else "failed", str(result.get("detail", result.get("error", "")))[:1000], owner, now, now))
            conn.execute(
                """INSERT INTO ssl_policies(domain,owner,last_check,last_renewal,last_status,last_detail,updated_at)
                   VALUES(?,?,?,?,?,?,?) ON CONFLICT(domain) DO UPDATE SET owner=excluded.owner,last_check=excluded.last_check,
                   last_renewal=excluded.last_renewal,last_status=excluded.last_status,last_detail=excluded.last_detail,
                   updated_at=excluded.updated_at""",
                (domain, owner, now, now if result.get("ok") else 0, "valid" if result.get("ok") else "failed", str(result.get("detail", result.get("error", "")))[:700], now),
            )
        audit("domain-ssl-renew", f"domain={domain} status={'ok' if result.get('ok') else 'failed'}")
        return jsonify(result), (200 if result.get("ok") else 503)
