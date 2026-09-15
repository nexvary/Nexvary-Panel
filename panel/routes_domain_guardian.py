from __future__ import annotations

import ipaddress
import re
import time

from flask import jsonify, request, session

from .config import DOMAIN_RE
from .core import audit, db
from .hosting_policy import feature_allowed
from .routes_autossl import EMAIL_RE
from .routes_deliverability import _dns_binding, _health as build_deliverability_health, _insert_preview
from .routes_domain_health import _snapshot as build_domain_readiness
from .security import role_required, step_up_required

SELECTOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$")
SAFE_ACTIONS = {"enable-autossl", "prepare-mail-dns"}


def _site(conn, domain: str):
    if not DOMAIN_RE.fullmatch(domain):
        return None
    row = conn.execute("SELECT domain,kind,enabled,owner FROM sites WHERE domain=?", (domain,)).fetchone()
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


def _safety_posture(conn, domain: str, owner: str) -> dict:
    dns_rows = conn.execute(
        "SELECT status,snapshot_json,created_at,applied_at FROM dns_changes WHERE domain=? AND owner=? ORDER BY id DESC LIMIT 20",
        (domain, owner),
    ).fetchall()
    ssl_rows = conn.execute(
        "SELECT action,status,created_at,updated_at FROM ssl_jobs WHERE domain=? AND owner=? ORDER BY id DESC LIMIT 10",
        (domain, owner),
    ).fetchall()
    now = int(time.time())
    risk = 0
    attention: list[dict] = []
    for row in dns_rows:
        state = str(row["status"] or "")
        if state == "applied" and not str(row["snapshot_json"] or "").strip():
            risk += 30
            attention.append({"id": "dns-no-snapshot", "severity": "critical", "message": "DNS change applied without a rollback snapshot."})
        elif state == "preview" and now - int(row["created_at"] or now) > 86400:
            risk += 8
            attention.append({"id": "stale-dns-preview", "severity": "warning", "message": "DNS preview has been waiting for more than 24 hours."})
    failed_ssl = [row for row in ssl_rows if str(row["status"] or "").lower() == "failed"]
    if failed_ssl:
        risk += min(30, len(failed_ssl) * 15)
        attention.append({"id": "ssl-job-failure", "severity": "warning", "message": f"{len(failed_ssl)} recent SSL job(s) failed."})
    score = max(0, 100 - min(100, risk))
    return {
        "score": score,
        "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F",
        "dns_events": len(dns_rows),
        "ssl_events": len(ssl_rows),
        "attention": attention,
    }


def _plan(readiness: dict, deliverability: dict | None, safety: dict) -> list[dict]:
    actions: list[dict] = []
    failed = {str(item.get("id", "")) for item in readiness.get("recommendations", [])}
    if "site-enabled" in failed:
        actions.append({"id": "enable-site", "mode": "manual", "severity": "critical", "view": "sites", "message": "Enable the managed site before trust automation."})
    if not readiness.get("dns", {}).get("bound"):
        actions.append({"id": "bind-dns-provider", "mode": "manual", "severity": "critical", "view": "integrations", "message": "Bind the domain to an approved Cloudflare or PowerDNS target."})
    if int(readiness.get("dns", {}).get("pending_previews", 0)):
        actions.append({"id": "review-dns-previews", "mode": "review", "severity": "warning", "view": "advancedops", "message": "Review pending DNS previews before preparing more external changes."})
    ssl = readiness.get("ssl", {})
    if ssl.get("feature_enabled") and not ssl.get("auto_renew"):
        actions.append({"id": "enable-autossl", "mode": "safe-prepare", "severity": "warning", "view": "advancedops", "requires": ["contact_email"], "message": "Prepare an AutoSSL renewal policy. This does not issue a certificate immediately."})
    if readiness.get("mail", {}).get("enabled") and deliverability:
        rec_ids = {str(item.get("id", "")) for item in deliverability.get("recommendations", [])}
        dns_fixable = rec_ids & {"mx", "spf", "dmarc", "tls-rpt"}
        if dns_fixable:
            actions.append({"id": "prepare-mail-dns", "mode": "safe-prepare", "severity": "warning", "view": "advancedops", "message": "Create reviewable DNS previews for missing mail records; nothing is applied automatically."})
        if "dkim" in rec_ids:
            actions.append({"id": "publish-dkim", "mode": "manual", "severity": "warning", "view": "mail", "message": "Generate or select the active DKIM key, then publish its DNS record."})
        if "mta-sts" in rec_ids:
            actions.append({"id": "mta-sts", "mode": "manual", "severity": "info", "view": "mail", "message": "MTA-STS remains an optional hardening step after core mail authentication is healthy."})
    for item in safety.get("attention", []):
        actions.append({"id": f"safety:{item['id']}", "mode": "review", "severity": item.get("severity", "warning"), "view": "advancedops", "message": item.get("message", "Review recent changes.")})
    return actions


def _trust_score(readiness: dict, deliverability: dict | None, safety: dict) -> tuple[int, str]:
    readiness_score = int(readiness.get("score", 0))
    safety_score = int(safety.get("score", 0))
    if readiness.get("mail", {}).get("enabled") and deliverability is not None:
        score = round(readiness_score * 0.60 + int(deliverability.get("score", 0)) * 0.25 + safety_score * 0.15)
    else:
        score = round(readiness_score * 0.80 + safety_score * 0.20)
    state = "protected" if score >= 90 else "strong" if score >= 80 else "attention" if score >= 60 else "risk"
    return score, state


def _snapshot(domain: str, selector: str, *, live: bool) -> tuple[dict | None, tuple | None]:
    with db() as conn:
        site = _site(conn, domain)
        if not site:
            return None, (jsonify(ok=False, error="domain outside your scope"), 403)
        readiness = build_domain_readiness(conn, site)
        owner = str(site["owner"])
        role = _owner_role(conn, owner)
        safety = _safety_posture(conn, domain, owner)
        mail_live_allowed = bool(
            readiness.get("mail", {}).get("enabled")
            and feature_allowed("email.deliverability", username=owner, role=role, connection=conn)
        )
    deliverability = build_deliverability_health(domain, selector) if live and mail_live_allowed else None
    score, state = _trust_score(readiness, deliverability, safety)
    plan = _plan(readiness, deliverability, safety)
    return {
        "domain": domain,
        "owner": owner,
        "score": score,
        "state": state,
        "readiness": readiness,
        "deliverability": deliverability,
        "safety": safety,
        "plan": plan,
        "safe_prepare_count": sum(1 for item in plan if item.get("mode") == "safe-prepare"),
        "live_checks": bool(live and mail_live_allowed),
    }, None


def register_domain_guardian_routes(app):
    @app.get("/api/domain-guardian")
    @role_required("admin", "operator", "viewer")
    def domain_guardian():
        domain = str(request.args.get("domain", "")).strip().lower().rstrip(".")
        selector = str(request.args.get("selector", "default")).strip().lower()
        live = str(request.args.get("live", "0")).lower() in {"1", "true", "yes"}
        if not DOMAIN_RE.fullmatch(domain) or not SELECTOR_RE.fullmatch(selector):
            return jsonify(ok=False, error="invalid domain or DKIM selector"), 400
        snapshot, denied = _snapshot(domain, selector, live=live)
        if denied:
            return denied
        return jsonify(ok=True, guardian=snapshot)

    @app.post("/api/domain-guardian/prepare")
    @role_required("admin", "operator")
    @step_up_required
    def domain_guardian_prepare():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        selector = str(data.get("selector", "default")).strip().lower()
        contact_email = str(data.get("contact_email", "")).strip().lower()
        mail_host = str(data.get("mail_host", f"mail.{domain}")).strip().lower().rstrip(".")
        mail_ipv4 = str(data.get("mail_ipv4", "")).strip()
        requested = data.get("actions")
        actions = set(requested) if isinstance(requested, list) else set(SAFE_ACTIONS)
        if not actions.issubset(SAFE_ACTIONS):
            return jsonify(ok=False, error="unsupported guardian action"), 400
        if not DOMAIN_RE.fullmatch(domain) or not SELECTOR_RE.fullmatch(selector):
            return jsonify(ok=False, error="invalid domain or DKIM selector"), 400
        if not DOMAIN_RE.fullmatch(mail_host) or (mail_host != domain and not mail_host.endswith("." + domain)):
            return jsonify(ok=False, error="mail_host must remain inside the managed domain"), 400
        if mail_ipv4:
            try:
                address = ipaddress.ip_address(mail_ipv4)
            except ValueError:
                return jsonify(ok=False, error="invalid mail IPv4 address"), 400
            if address.version != 4 or not address.is_global:
                return jsonify(ok=False, error="mail IPv4 must be public"), 400

        now = int(time.time())
        prepared: list[dict] = []
        skipped: list[dict] = []
        with db() as conn:
            site = _site(conn, domain)
            if not site:
                return jsonify(ok=False, error="domain outside your scope"), 403
            owner = str(site["owner"])
            role = _owner_role(conn, owner)

            if "enable-autossl" in actions:
                if not feature_allowed("security.ssl_tls", username=owner, role=role, connection=conn):
                    skipped.append({"id": "enable-autossl", "reason": "SSL/TLS disabled by hosting policy"})
                elif not contact_email or len(contact_email) > 320 or not EMAIL_RE.fullmatch(contact_email):
                    skipped.append({"id": "enable-autossl", "reason": "valid contact_email required"})
                else:
                    conn.execute(
                        """INSERT INTO ssl_policies(domain,owner,contact_email,auto_renew,renew_before_days,last_check,last_renewal,last_status,last_detail,updated_at)
                           VALUES(?,?,?,?,30,0,0,'pending','Domain Guardian prepared AutoSSL policy',?)
                           ON CONFLICT(domain) DO UPDATE SET owner=excluded.owner,contact_email=excluded.contact_email,
                             auto_renew=1,renew_before_days=30,last_check=0,last_status='pending',
                             last_detail='Domain Guardian prepared AutoSSL policy',updated_at=excluded.updated_at""",
                        (domain, owner, contact_email, 1, now),
                    )
                    prepared.append({"id": "enable-autossl", "external_change": False, "detail": "AutoSSL policy enabled; certificate issuance remains separate."})

            if "prepare-mail-dns" in actions:
                mail_domain = conn.execute("SELECT enabled FROM mail_domains WHERE domain=? AND owner=?", (domain, owner)).fetchone()
                if not mail_domain or not mail_domain["enabled"]:
                    skipped.append({"id": "prepare-mail-dns", "reason": "mail domain is not enabled"})
                elif not feature_allowed("email.deliverability", username=owner, role=role, connection=conn) or not feature_allowed("domains.zone_editor", username=owner, role=role, connection=conn):
                    skipped.append({"id": "prepare-mail-dns", "reason": "deliverability or zone editor disabled by hosting policy"})
                else:
                    binding = _dns_binding(conn, domain)
                    if not binding:
                        skipped.append({"id": "prepare-mail-dns", "reason": "no active Cloudflare/PowerDNS binding"})
                    else:
                        health = build_deliverability_health(domain, selector)
                        checks = health.get("checks", {})
                        desired: list[tuple[str, str, str, int]] = []
                        if not checks.get("mx"):
                            desired.append(("MX", domain, mail_host, 10))
                        if mail_ipv4 and not checks.get("mail_host_a"):
                            desired.append(("A", mail_host, mail_ipv4, 0))
                        if not checks.get("spf"):
                            desired.append(("TXT", domain, "v=spf1 mx -all", 0))
                        if not checks.get("dmarc"):
                            desired.append(("TXT", f"_dmarc.{domain}", f"v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}; adkim=s; aspf=s", 0))
                        if not checks.get("tls_rpt"):
                            desired.append(("TXT", f"_smtp._tls.{domain}", f"v=TLSRPTv1; rua=mailto:postmaster@{domain}", 0))
                        ids: list[int] = []
                        for record_type, name, value, priority in desired:
                            preview_id, _ = _insert_preview(
                                conn,
                                domain=domain,
                                owner=owner,
                                target_id=int(binding["target_id"]),
                                record_type=record_type,
                                record_name=name,
                                record_value=value,
                                ttl=300,
                                priority=priority,
                            )
                            ids.append(preview_id)
                        prepared.append({"id": "prepare-mail-dns", "external_change": False, "preview_ids": ids, "detail": f"Prepared {len(ids)} reviewable DNS preview(s)."})

        audit("domain-guardian-prepare", f"domain={domain} owner={owner} prepared={','.join(item['id'] for item in prepared) or 'none'} skipped={len(skipped)}")
        snapshot, _ = _snapshot(domain, selector, live=False)
        return jsonify(
            ok=True,
            domain=domain,
            prepared=prepared,
            skipped=skipped,
            guardian=snapshot,
            safety_note="No external DNS record was applied and no certificate was issued. Review DNS previews and run AutoSSL preflight before external changes.",
        )
