from __future__ import annotations

from flask import jsonify, request, session

from .config import DOMAIN_RE
from .core import db
from .hosting_policy import feature_allowed
from .security import role_required


def _owner_role(conn, owner: str) -> str:
    if owner == "admin":
        return "admin"
    row = conn.execute("SELECT role FROM users WHERE username=?", (owner,)).fetchone()
    return str(row["role"]) if row else "operator"


def _visible_site(conn, domain: str):
    row = conn.execute(
        "SELECT domain,kind,enabled,owner FROM sites WHERE domain=?", (domain,)
    ).fetchone()
    if not row:
        return None
    if session.get("role") != "admin" and str(row["owner"]) != str(session.get("user", "")):
        return None
    return row


def _check(checks: list[dict], check_id: str, label: str, ok: bool, weight: int, *, detail: str = "", view: str = "") -> None:
    checks.append({
        "id": check_id,
        "label": label,
        "ok": bool(ok),
        "weight": max(0, int(weight)),
        "detail": str(detail)[:240],
        "view": str(view)[:40],
    })


def _snapshot(conn, site) -> dict:
    domain = str(site["domain"])
    owner = str(site["owner"])
    role = _owner_role(conn, owner)

    domain_feature = feature_allowed("domains.domains", username=owner, role=role, connection=conn)
    zone_feature = feature_allowed("domains.zone_editor", username=owner, role=role, connection=conn)
    ssl_feature = feature_allowed("security.ssl_tls", username=owner, role=role, connection=conn)
    mail_feature = feature_allowed("email.accounts", username=owner, role=role, connection=conn)
    deliverability_feature = feature_allowed("email.deliverability", username=owner, role=role, connection=conn)

    aliases = int(conn.execute("SELECT COUNT(*) FROM domain_aliases WHERE domain=?", (domain,)).fetchone()[0])
    binding = conn.execute(
        """SELECT b.target_id,t.name,t.provider,t.enabled,t.updated_at
           FROM dns_zone_bindings b
           JOIN integration_targets t ON t.id=b.target_id
           WHERE b.domain=?""",
        (domain,),
    ).fetchone()
    pending_dns = int(conn.execute(
        "SELECT COUNT(*) FROM dns_changes WHERE domain=? AND status='preview'", (domain,)
    ).fetchone()[0])
    latest_dns = conn.execute(
        """SELECT id,operation,record_type,status,created_at,applied_at
           FROM dns_changes WHERE domain=? ORDER BY id DESC LIMIT 1""",
        (domain,),
    ).fetchone()
    policy = conn.execute(
        """SELECT auto_renew,renew_before_days,last_check,last_renewal,last_status,updated_at
           FROM ssl_policies WHERE domain=?""",
        (domain,),
    ).fetchone()
    latest_ssl = conn.execute(
        """SELECT action,status,created_at,updated_at
           FROM ssl_jobs WHERE domain=? ORDER BY id DESC LIMIT 1""",
        (domain,),
    ).fetchone()
    mail_domain = conn.execute(
        "SELECT enabled FROM mail_domains WHERE domain=? AND owner=?", (domain, owner)
    ).fetchone()
    mailbox_count = int(conn.execute(
        "SELECT COUNT(*) FROM mailboxes WHERE domain=? AND owner=? AND enabled=1", (domain, owner)
    ).fetchone()[0])
    forwarder_count = int(conn.execute(
        "SELECT COUNT(*) FROM mail_forwarders WHERE domain=? AND owner=? AND enabled=1", (domain, owner)
    ).fetchone()[0])

    binding_active = bool(binding and binding["enabled"])
    provider = str(binding["provider"]) if binding else ""
    ssl_auto = bool(policy and policy["auto_renew"])
    ssl_last_ok = bool(latest_ssl and str(latest_ssl["status"]).lower() == "success")
    mail_enabled = bool(mail_domain and mail_domain["enabled"])

    checks: list[dict] = []
    _check(checks, "site-enabled", "Managed site is enabled", bool(site["enabled"]), 20,
           detail="الموقع مفعل داخل Nexvary Panel.", view="sites")
    _check(checks, "domain-policy", "Domain feature policy", domain_feature, 10,
           detail="domains.domains متاحة في باقة الحساب.", view="hosting")
    _check(checks, "dns-provider", "DNS provider binding", binding_active, 20,
           detail=(f"{provider} target #{int(binding['target_id'])}" if binding_active else "لا يوجد Cloudflare/PowerDNS target فعال."),
           view="advancedops")
    _check(checks, "dns-preview-clean", "No unapplied DNS previews", pending_dns == 0, 10,
           detail=("لا توجد تغييرات DNS معلقة." if pending_dns == 0 else f"{pending_dns} DNS preview تحتاج مراجعة."),
           view="advancedops")
    _check(checks, "zone-editor-policy", "DNS write entitlement", zone_feature, 10,
           detail="domains.zone_editor متاحة للحساب.", view="hosting")
    _check(checks, "ssl-entitlement", "SSL/TLS entitlement", ssl_feature, 10,
           detail="security.ssl_tls متاحة للحساب.", view="hosting")
    _check(checks, "ssl-automation", "Certificate lifecycle managed", bool(ssl_feature and (ssl_auto or ssl_last_ok)), 20,
           detail=(
               f"AutoSSL مفعل؛ التجديد قبل {int(policy['renew_before_days'])} يوم."
               if ssl_auto else
               "يوجد إصدار/تجديد SSL ناجح مسجل." if ssl_last_ok else
               "فعّل AutoSSL أو نفذ إصدار شهادة ناجح."
           ), view="advancedops")

    # Mail is optional for a web-only domain. It becomes part of the score only after a mail domain is enabled.
    if mail_enabled:
        _check(checks, "mail-entitlement", "Mail feature policy", bool(mail_feature and deliverability_feature), 10,
               detail="Email Accounts وDeliverability متاحتان.", view="mail")
        _check(checks, "mail-routing", "Mail routing configured", mailbox_count + forwarder_count > 0, 10,
               detail=f"{mailbox_count} mailbox · {forwarder_count} forwarder", view="mail")

    denominator = sum(int(item["weight"]) for item in checks) or 1
    earned = sum(int(item["weight"]) for item in checks if item["ok"])
    score = round(earned * 100 / denominator)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"

    recommendations = [
        {
            "id": item["id"],
            "message": item["detail"] or item["label"],
            "view": item["view"],
        }
        for item in checks if not item["ok"]
    ]

    return {
        "domain": domain,
        "owner": owner,
        "kind": str(site["kind"]),
        "score": score,
        "grade": grade,
        "checks": checks,
        "recommendations": recommendations,
        "domain_lifecycle": {"aliases": aliases},
        "dns": {
            "bound": binding_active,
            "provider": provider,
            "target_id": int(binding["target_id"]) if binding else 0,
            "target_name": str(binding["name"]) if binding else "",
            "pending_previews": pending_dns,
            "latest_change": dict(latest_dns) if latest_dns else None,
            "dnssec": {
                "supported_by_bound_provider": bool(binding_active and provider in {"cloudflare", "powerdns"}),
                "state": "provider-check-required" if binding_active else "unavailable",
            },
        },
        "ssl": {
            "feature_enabled": ssl_feature,
            "policy_configured": bool(policy),
            "auto_renew": ssl_auto,
            "renew_before_days": int(policy["renew_before_days"]) if policy else 30,
            "last_status": str(policy["last_status"]) if policy else "unconfigured",
            "last_check": int(policy["last_check"]) if policy else 0,
            "last_renewal": int(policy["last_renewal"]) if policy else 0,
            "latest_job": dict(latest_ssl) if latest_ssl else None,
        },
        "mail": {
            "enabled": mail_enabled,
            "mailboxes": mailbox_count,
            "forwarders": forwarder_count,
            "deliverability_feature": deliverability_feature,
            "live_deliverability": "use /api/mail/deliverability/health for DNS-based score",
        },
    }


def register_domain_health_routes(app):
    @app.get("/api/domain-health")
    @role_required("admin", "operator", "viewer")
    def domain_health():
        requested = str(request.args.get("domain", "")).strip().lower().rstrip(".")
        with db() as conn:
            if requested:
                if not DOMAIN_RE.fullmatch(requested):
                    return jsonify(ok=False, error="invalid domain"), 400
                site = _visible_site(conn, requested)
                if not site:
                    return jsonify(ok=False, error="domain outside your scope"), 403
                return jsonify(ok=True, readiness=_snapshot(conn, site))

            if session.get("role") == "admin":
                rows = conn.execute("SELECT domain,kind,enabled,owner FROM sites ORDER BY domain").fetchall()
            else:
                rows = conn.execute(
                    "SELECT domain,kind,enabled,owner FROM sites WHERE owner=? ORDER BY domain",
                    (str(session.get("user", "")),),
                ).fetchall()
            items = [_snapshot(conn, row) for row in rows]
        return jsonify(ok=True, domains=items, count=len(items))
