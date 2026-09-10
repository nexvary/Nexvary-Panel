from __future__ import annotations

import sqlite3
import time

from flask import jsonify, request, session

from .config import DOMAIN_RE
from .core import audit, db
from .hosting_policy import feature_allowed, package_limit
from .security import role_required, step_up_required
from .webtools_client import webtools_call


def _site_scope(conn, domain: str):
    row = conn.execute("SELECT domain,owner,enabled FROM sites WHERE domain=?", (domain,)).fetchone()
    if not row:
        return None
    if session.get("role") != "admin" and str(row["owner"]) != str(session.get("user", "")):
        return None
    return row


def _alias_rows(conn, domain: str) -> list[dict]:
    rows = conn.execute("SELECT id,domain,alias,owner,created_at,updated_at FROM domain_aliases WHERE domain=? ORDER BY alias", (domain,)).fetchall()
    return [dict(row) | {"kind": "subdomain" if str(row["alias"]).endswith("." + domain) else "alias"} for row in rows]


def _sync(conn, domain: str) -> dict:
    aliases = [str(row["alias"]) for row in conn.execute("SELECT alias FROM domain_aliases WHERE domain=? ORDER BY alias", (domain,)).fetchall()]
    return webtools_call({"action": "domain-alias-sync", "domain": domain, "aliases": aliases}, timeout=35)


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
            if not _site_scope(conn, domain):
                return jsonify(ok=False, error="site outside your scope"), 403
            rows = _alias_rows(conn, domain)
            owner = str(session.get("user", ""))[:64]
            used = int(conn.execute("SELECT COUNT(*) FROM domain_aliases WHERE owner=?", (owner,)).fetchone()[0]) if session.get("role") != "admin" else len(rows)
        limit = package_limit("max_subdomains")
        return jsonify(ok=True, domain=domain, aliases=rows, quota={"used": used, "limit": limit, "remaining": max(0, limit-used)})

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
        owner = str(session.get("user", ""))[:64]
        now = int(time.time())
        with db() as conn:
            site = _site_scope(conn, domain)
            if not site:
                return jsonify(ok=False, error="site outside your scope"), 403
            owner = str(site["owner"])
            used = int(conn.execute("SELECT COUNT(*) FROM domain_aliases WHERE owner=?", (owner,)).fetchone()[0])
            limit = package_limit("max_subdomains", username=owner, role="admin" if owner == "admin" else "operator")
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
