from __future__ import annotations

import re
import sqlite3
import time
from urllib.parse import urlsplit

from flask import jsonify, request, session

from .config import DOMAIN_RE
from .core import audit, can_manage_domain, db
from .hosting_policy import feature_allowed
from .security import login_required, role_required, step_up_required
from .webtools_client import webtools_call

SOURCE_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!&'()*+,=:@%/\-]{0,200}$")
ALLOWED_REDIRECT_CODES = {301, 302, 307, 308}
ALLOWED_ERROR_CODES = {400, 401, 403, 404, 405, 408, 410, 429, 500, 502, 503, 504}
MAX_ERROR_HTML = 64 * 1024


def _domain(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.lower().strip()
    return value if DOMAIN_RE.fullmatch(value) and can_manage_domain(value) else None


def _source_path(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not SOURCE_PATH_RE.fullmatch(value) or any(ch in value for ch in ";{}\\\"$"):
        return None
    return value


def _redirect_target(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > 1200 or any(ch in value for ch in "\r\n\t ;{}\\\"'$"):
        return None
    if value.startswith("/"):
        return value if _source_path(value) else None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        return None
    if not re.fullmatch(r"[A-Za-z0-9.-]+", parsed.hostname):
        return None
    return value


def _feature_or_403(feature_id: str):
    if not feature_allowed(feature_id):
        return jsonify(ok=False, error="feature disabled by hosting package policy"), 403
    return None


def _redirect_rows(conn, domain: str) -> list[dict]:
    rows = conn.execute(
        "SELECT id,source_path,target,status_code,created_at,updated_at FROM site_redirects WHERE domain=? ORDER BY source_path",
        (domain,),
    ).fetchall()
    return [dict(row) for row in rows]


def _error_rows(conn, domain: str) -> list[dict]:
    rows = conn.execute(
        "SELECT status_code,html,created_at,updated_at FROM site_error_pages WHERE domain=? ORDER BY status_code",
        (domain,),
    ).fetchall()
    return [dict(row) for row in rows]


def register_webtools_routes(app):
    @app.get("/api/webtools/sites")
    @login_required
    def webtools_sites():
        username = str(session.get("user", ""))
        role = str(session.get("role", "viewer"))
        with db() as conn:
            if role == "admin":
                rows = conn.execute("SELECT domain,kind,enabled FROM sites ORDER BY domain").fetchall()
            else:
                rows = conn.execute("SELECT domain,kind,enabled FROM sites WHERE owner=? ORDER BY domain", (username,)).fetchall()
        return jsonify(ok=True, sites=[dict(row) for row in rows])

    @app.get("/api/webtools/redirects")
    @login_required
    def webtools_redirects():
        denied = _feature_or_403("domains.redirects")
        if denied:
            return denied
        domain = _domain(request.args.get("domain", ""))
        if not domain:
            return jsonify(ok=False, error="invalid or unauthorized domain"), 400
        with db() as conn:
            return jsonify(ok=True, domain=domain, redirects=_redirect_rows(conn, domain))

    @app.post("/api/webtools/redirects")
    @role_required("admin", "operator")
    @step_up_required
    def webtools_redirect_create():
        denied = _feature_or_403("domains.redirects")
        if denied:
            return denied
        data = request.get_json(silent=True) or {}
        domain = _domain(data.get("domain"))
        source = _source_path(data.get("source_path"))
        target = _redirect_target(data.get("target"))
        try:
            code = int(data.get("status_code", 301))
        except (TypeError, ValueError):
            code = 0
        if not domain or not source or not target or code not in ALLOWED_REDIRECT_CODES:
            return jsonify(ok=False, error="invalid redirect request"), 400
        now = int(time.time())
        with db() as conn:
            try:
                conn.execute(
                    "INSERT INTO site_redirects(domain,source_path,target,status_code,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                    (domain, source, target, code, session.get("user", "admin"), now, now),
                )
            except sqlite3.IntegrityError:
                return jsonify(ok=False, error="redirect source already exists"), 409
            rules = _redirect_rows(conn, domain)
            result = webtools_call({"action": "redirect-sync", "domain": domain, "rules": rules}, timeout=35)
            if not result.get("ok"):
                conn.rollback()
                return jsonify(ok=False, error=str(result.get("error", "redirect sync failed"))), 502
        audit("redirect-create", f"domain={domain} source={source} code={code} target={target[:180]}")
        return jsonify(ok=True, domain=domain, redirects=rules), 201

    @app.delete("/api/webtools/redirects/<int:redirect_id>")
    @role_required("admin", "operator")
    @step_up_required
    def webtools_redirect_delete(redirect_id: int):
        denied = _feature_or_403("domains.redirects")
        if denied:
            return denied
        with db() as conn:
            row = conn.execute("SELECT domain,source_path FROM site_redirects WHERE id=?", (redirect_id,)).fetchone()
            if not row or not _domain(row["domain"]):
                return jsonify(ok=False, error="redirect not found"), 404
            domain, source = str(row["domain"]), str(row["source_path"])
            conn.execute("DELETE FROM site_redirects WHERE id=?", (redirect_id,))
            rules = _redirect_rows(conn, domain)
            result = webtools_call({"action": "redirect-sync", "domain": domain, "rules": rules}, timeout=35)
            if not result.get("ok"):
                conn.rollback()
                return jsonify(ok=False, error=str(result.get("error", "redirect sync failed"))), 502
        audit("redirect-delete", f"domain={domain} source={source}")
        return jsonify(ok=True, domain=domain, redirects=rules)

    @app.get("/api/webtools/error-pages")
    @login_required
    def webtools_error_pages():
        denied = _feature_or_403("advanced.error_pages")
        if denied:
            return denied
        domain = _domain(request.args.get("domain", ""))
        if not domain:
            return jsonify(ok=False, error="invalid or unauthorized domain"), 400
        with db() as conn:
            return jsonify(ok=True, domain=domain, pages=_error_rows(conn, domain), allowed_codes=sorted(ALLOWED_ERROR_CODES))

    @app.put("/api/webtools/error-pages/<int:status_code>")
    @role_required("admin", "operator")
    @step_up_required
    def webtools_error_page_save(status_code: int):
        denied = _feature_or_403("advanced.error_pages")
        if denied:
            return denied
        data = request.get_json(silent=True) or {}
        domain = _domain(data.get("domain"))
        html = data.get("html")
        if status_code not in ALLOWED_ERROR_CODES or not domain or not isinstance(html, str) or len(html.encode("utf-8")) > MAX_ERROR_HTML:
            return jsonify(ok=False, error="invalid error page request"), 400
        now = int(time.time())
        with db() as conn:
            conn.execute(
                """INSERT INTO site_error_pages(domain,status_code,html,owner,created_at,updated_at) VALUES(?,?,?,?,?,?)
                   ON CONFLICT(domain,status_code) DO UPDATE SET html=excluded.html,owner=excluded.owner,updated_at=excluded.updated_at""",
                (domain, status_code, html, session.get("user", "admin"), now, now),
            )
            pages = _error_rows(conn, domain)
            result = webtools_call({"action": "error-page-sync", "domain": domain, "pages": pages}, timeout=35)
            if not result.get("ok"):
                conn.rollback()
                return jsonify(ok=False, error=str(result.get("error", "error page sync failed"))), 502
        audit("error-page-save", f"domain={domain} status={status_code} bytes={len(html.encode('utf-8'))}")
        return jsonify(ok=True, domain=domain, pages=pages)

    @app.delete("/api/webtools/error-pages/<int:status_code>")
    @role_required("admin", "operator")
    @step_up_required
    def webtools_error_page_delete(status_code: int):
        denied = _feature_or_403("advanced.error_pages")
        if denied:
            return denied
        domain = _domain(request.args.get("domain", ""))
        if status_code not in ALLOWED_ERROR_CODES or not domain:
            return jsonify(ok=False, error="invalid error page request"), 400
        with db() as conn:
            conn.execute("DELETE FROM site_error_pages WHERE domain=? AND status_code=?", (domain, status_code))
            pages = _error_rows(conn, domain)
            result = webtools_call({"action": "error-page-sync", "domain": domain, "pages": pages}, timeout=35)
            if not result.get("ok"):
                conn.rollback()
                return jsonify(ok=False, error=str(result.get("error", "error page sync failed"))), 502
        audit("error-page-delete", f"domain={domain} status={status_code}")
        return jsonify(ok=True, domain=domain, pages=pages)

    @app.get("/api/webtools/metrics")
    @login_required
    def webtools_metrics():
        if not (feature_allowed("metrics.visitors") or feature_allowed("metrics.bandwidth")):
            return jsonify(ok=False, error="metrics disabled by hosting package policy"), 403
        domain = _domain(request.args.get("domain", ""))
        if not domain:
            return jsonify(ok=False, error="invalid or unauthorized domain"), 400
        result = webtools_call({"action": "site-metrics", "domain": domain}, timeout=15)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "metrics unavailable"))), 502
        return jsonify(ok=True, domain=domain, metrics=result.get("metrics") or {})
