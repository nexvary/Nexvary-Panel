from __future__ import annotations

import re
import time

from flask import jsonify, request, session

from .config import DOMAIN_RE
from .core import audit, db
from .hosting_policy import feature_allowed
from .ops_client import ops_call
from .security import role_required, step_up_required

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}$")
MIN_RENEW_DAYS = 7
MAX_RENEW_DAYS = 60
MAX_AUTOSSL_NAMES = 25


def _owner_role(conn, owner: str) -> str:
    if owner == "admin":
        return "admin"
    row = conn.execute("SELECT role FROM users WHERE username=?", (owner,)).fetchone()
    return str(row["role"]) if row else "operator"


def _site_context(conn, domain: str):
    if not DOMAIN_RE.fullmatch(domain):
        return None
    row = conn.execute("SELECT domain,owner,enabled FROM sites WHERE domain=?", (domain,)).fetchone()
    if not row:
        return None
    owner = str(row["owner"])
    if session.get("role") != "admin" and owner != str(session.get("user", "")):
        return None
    return row


def _policy_row(conn, domain: str):
    return conn.execute(
        """SELECT domain,owner,contact_email,auto_renew,renew_before_days,last_check,
                  last_renewal,last_status,last_detail,updated_at
           FROM ssl_policies WHERE domain=?""",
        (domain,),
    ).fetchone()


def _desired_names(conn, domain: str) -> list[str]:
    names = [domain]
    rows = conn.execute("SELECT alias FROM domain_aliases WHERE domain=? ORDER BY alias LIMIT ?", (domain, MAX_AUTOSSL_NAMES - 1)).fetchall()
    for row in rows:
        name = str(row["alias"] or "").strip().lower().rstrip(".")
        if name and DOMAIN_RE.fullmatch(name) and name not in names:
            names.append(name)
    return names[:MAX_AUTOSSL_NAMES]


def _serialize(row, *, feature_enabled: bool, site_enabled: bool) -> dict:
    if row is None:
        return {
            "configured": False,
            "auto_renew": False,
            "contact_email": "",
            "renew_before_days": 30,
            "last_check": 0,
            "last_renewal": 0,
            "last_status": "unconfigured",
            "last_detail": "",
            "updated_at": 0,
            "feature_enabled": feature_enabled,
            "site_enabled": site_enabled,
        }
    return {
        "configured": True,
        "auto_renew": bool(row["auto_renew"]),
        "contact_email": str(row["contact_email"] or ""),
        "renew_before_days": int(row["renew_before_days"] or 30),
        "last_check": int(row["last_check"] or 0),
        "last_renewal": int(row["last_renewal"] or 0),
        "last_status": str(row["last_status"] or "unknown")[:32],
        "last_detail": str(row["last_detail"] or "")[:700],
        "updated_at": int(row["updated_at"] or 0),
        "feature_enabled": feature_enabled,
        "site_enabled": site_enabled,
    }


def _authorized_site(conn, domain: str):
    site = _site_context(conn, domain)
    if not site:
        return None, None, (jsonify(ok=False, error="site outside your scope"), 403)
    owner = str(site["owner"])
    owner_role = _owner_role(conn, owner)
    if not feature_allowed("security.ssl_tls", username=owner, role=owner_role, connection=conn):
        return None, None, (jsonify(ok=False, error="security.ssl_tls disabled by hosting policy"), 403)
    return site, owner, None


def register_autossl_routes(app):
    @app.get("/api/autossl")
    @role_required("admin", "operator")
    def autossl_inventory():
        requested = str(request.args.get("domain", "")).strip().lower().rstrip(".")
        actor = str(session.get("user", ""))[:64]
        role = str(session.get("role", "operator"))
        with db() as conn:
            if requested:
                site = _site_context(conn, requested)
                if not site:
                    return jsonify(ok=False, error="site outside your scope"), 403
                owner = str(site["owner"])
                enabled = feature_allowed("security.ssl_tls", username=owner, role=_owner_role(conn, owner), connection=conn)
                return jsonify(
                    ok=True,
                    domain=requested,
                    names=_desired_names(conn, requested),
                    policy=_serialize(_policy_row(conn, requested), feature_enabled=enabled, site_enabled=bool(site["enabled"])),
                )

            if role == "admin":
                sites = conn.execute("SELECT domain,owner,enabled FROM sites ORDER BY domain").fetchall()
            else:
                sites = conn.execute("SELECT domain,owner,enabled FROM sites WHERE owner=? ORDER BY domain", (actor,)).fetchall()
            policies = []
            for site in sites:
                domain = str(site["domain"])
                owner = str(site["owner"])
                enabled = feature_allowed("security.ssl_tls", username=owner, role=_owner_role(conn, owner), connection=conn)
                policies.append({
                    "domain": domain,
                    "owner": owner,
                    "names": _desired_names(conn, domain),
                    **_serialize(_policy_row(conn, domain), feature_enabled=enabled, site_enabled=bool(site["enabled"])),
                })
        return jsonify(ok=True, policies=policies)

    @app.get("/api/autossl/preflight")
    @role_required("admin", "operator")
    def autossl_preflight():
        domain = str(request.args.get("domain", "")).strip().lower().rstrip(".")
        with db() as conn:
            site, owner, denied = _authorized_site(conn, domain)
            if denied:
                return denied
            names = _desired_names(conn, domain)
        result = ops_call({"action": "ssl-preflight", "domain": domain, "domains": names}, timeout=35)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "AutoSSL preflight unavailable"))[:180]), 502
        return jsonify(ok=True, domain=domain, names=names, preflight=result)

    @app.post("/api/autossl/<path:domain>/issue")
    @role_required("admin", "operator")
    @step_up_required
    def autossl_issue(domain: str):
        domain = str(domain).strip().lower().rstrip(".")
        data = request.get_json(silent=True) or {}
        email = str(data.get("email", "")).strip().lower()
        if not EMAIL_RE.fullmatch(email) or len(email) > 320:
            return jsonify(ok=False, error="valid AutoSSL contact email required"), 400
        with db() as conn:
            site, owner, denied = _authorized_site(conn, domain)
            if denied:
                return denied
            names = _desired_names(conn, domain)
        result = ops_call({"action": "ssl-issue", "domain": domain, "domains": names, "email": email}, timeout=240)
        now = int(time.time())
        with db() as conn:
            conn.execute(
                "INSERT INTO ssl_jobs(domain,action,contact_email,status,detail,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (domain, "autossl-issue", email, "success" if result.get("ok") else "failed", str(result.get("detail", result.get("error", "")))[:1000], owner, now, now),
            )
        audit("autossl-issue", f"domain={domain} owner={owner} names={len(names)} status={'ok' if result.get('ok') else 'failed'}")
        return jsonify(result), (200 if result.get("ok") else 503)

    @app.post("/api/autossl/<path:domain>/renew")
    @role_required("admin", "operator")
    @step_up_required
    def autossl_renew(domain: str):
        domain = str(domain).strip().lower().rstrip(".")
        with db() as conn:
            site, owner, denied = _authorized_site(conn, domain)
            if denied:
                return denied
            names = _desired_names(conn, domain)
        result = ops_call({"action": "ssl-renew", "domain": domain, "domains": names}, timeout=240)
        now = int(time.time())
        with db() as conn:
            conn.execute(
                "INSERT INTO ssl_jobs(domain,action,contact_email,status,detail,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (domain, "autossl-renew", "", "success" if result.get("ok") else "failed", str(result.get("detail", result.get("error", "")))[:1000], owner, now, now),
            )
        audit("autossl-renew", f"domain={domain} owner={owner} names={len(names)} status={'ok' if result.get('ok') else 'failed'}")
        return jsonify(result), (200 if result.get("ok") else 503)

    @app.put("/api/autossl/<path:domain>")
    @role_required("admin", "operator")
    @step_up_required
    def autossl_policy_save(domain: str):
        domain = str(domain).strip().lower().rstrip(".")
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        auto_renew = data.get("auto_renew")
        contact_email = str(data.get("contact_email", "")).strip().lower()
        try:
            renew_before_days = int(data.get("renew_before_days", 30))
        except (TypeError, ValueError):
            renew_before_days = 0
        if not isinstance(auto_renew, bool) or not MIN_RENEW_DAYS <= renew_before_days <= MAX_RENEW_DAYS:
            return jsonify(ok=False, error="invalid AutoSSL policy"), 400
        if contact_email and (len(contact_email) > 320 or not EMAIL_RE.fullmatch(contact_email)):
            return jsonify(ok=False, error="invalid AutoSSL contact email"), 400
        if auto_renew and not contact_email:
            return jsonify(ok=False, error="contact email required when AutoSSL is enabled"), 400

        now = int(time.time())
        with db() as conn:
            site, owner, denied = _authorized_site(conn, domain)
            if denied:
                return denied
            conn.execute(
                """INSERT INTO ssl_policies(domain,owner,contact_email,auto_renew,renew_before_days,last_check,last_renewal,last_status,last_detail,updated_at)
                   VALUES(?,?,?,?,?,0,0,'pending','',?)
                   ON CONFLICT(domain) DO UPDATE SET
                     owner=excluded.owner,
                     contact_email=excluded.contact_email,
                     auto_renew=excluded.auto_renew,
                     renew_before_days=excluded.renew_before_days,
                     last_check=CASE
                       WHEN ssl_policies.auto_renew<>excluded.auto_renew
                         OR ssl_policies.contact_email<>excluded.contact_email
                         OR ssl_policies.renew_before_days<>excluded.renew_before_days
                       THEN 0 ELSE ssl_policies.last_check END,
                     last_status=CASE
                       WHEN excluded.auto_renew=1 THEN 'pending' ELSE 'disabled' END,
                     last_detail=CASE
                       WHEN excluded.auto_renew=1 THEN 'AutoSSL policy updated; awaiting scheduler check'
                       ELSE 'AutoSSL disabled by account policy' END,
                     updated_at=excluded.updated_at""",
                (domain, owner, contact_email, 1 if auto_renew else 0, renew_before_days, now),
            )
            row = _policy_row(conn, domain)
            names = _desired_names(conn, domain)
        audit("autossl-policy", f"domain={domain} owner={owner} enabled={int(auto_renew)} renew_before_days={renew_before_days} names={len(names)}")
        return jsonify(ok=True, domain=domain, names=names, policy=_serialize(row, feature_enabled=True, site_enabled=bool(site["enabled"])))
