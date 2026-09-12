from __future__ import annotations

import ipaddress
import re
import time

import dns.resolver
from flask import jsonify, request, session

from .config import DOMAIN_RE
from .core import audit, db
from .hosting_policy import feature_allowed
from .security import role_required, step_up_required

SELECTOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$")
MAX_DNS_RESULTS = 20


def _owner_role(conn, owner: str) -> str:
    if owner == "admin":
        return "admin"
    row = conn.execute("SELECT role FROM users WHERE username=?", (owner,)).fetchone()
    return str(row["role"]) if row else "operator"


def _domain_owner(conn, domain: str) -> str | None:
    row = conn.execute("SELECT owner FROM sites WHERE domain=?", (domain,)).fetchone()
    if row:
        return str(row["owner"])
    row = conn.execute("SELECT username FROM hosting_accounts WHERE primary_domain=?", (domain,)).fetchone()
    if row:
        return str(row["username"])
    row = conn.execute("SELECT owner FROM mail_domains WHERE domain=?", (domain,)).fetchone()
    return str(row["owner"]) if row else None


def _context(conn, domain: str) -> tuple[str | None, str | None]:
    if not DOMAIN_RE.fullmatch(domain):
        return None, None
    owner = _domain_owner(conn, domain)
    if not owner:
        return None, None
    if session.get("role") != "admin" and owner != str(session.get("user", "")):
        return None, None
    return owner, _owner_role(conn, owner)


def _resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.5
    resolver.lifetime = 4.0
    return resolver


def _query(resolver: dns.resolver.Resolver, name: str, rdtype: str) -> list[str]:
    try:
        answer = resolver.resolve(name, rdtype, raise_on_no_answer=False)
    except Exception:
        return []
    rows: list[str] = []
    for item in answer:
        if rdtype == "TXT" and hasattr(item, "strings"):
            try:
                text = b"".join(item.strings).decode("utf-8", errors="replace")
            except Exception:
                text = str(item).strip('"')
        else:
            text = str(item).strip()
        if text and text not in rows:
            rows.append(text[:4096])
        if len(rows) >= MAX_DNS_RESULTS:
            break
    return rows


def _tag_map(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in value.split(";"):
        if "=" not in part:
            continue
        key, val = part.split("=", 1)
        key = key.strip().lower()
        if key:
            out[key] = val.strip()
    return out


def _health(domain: str, selector: str) -> dict:
    resolver = _resolver()
    mx = _query(resolver, domain, "MX")
    txt = _query(resolver, domain, "TXT")
    dmarc_all = _query(resolver, f"_dmarc.{domain}", "TXT")
    dkim_all = _query(resolver, f"{selector}._domainkey.{domain}", "TXT")
    mta_sts_all = _query(resolver, f"_mta-sts.{domain}", "TXT")
    tls_rpt_all = _query(resolver, f"_smtp._tls.{domain}", "TXT")
    mail_host = f"mail.{domain}"
    mail_a = _query(resolver, mail_host, "A")

    spf = [row for row in txt if row.lower().startswith("v=spf1")]
    dmarc = [row for row in dmarc_all if row.lower().startswith("v=dmarc1")]
    dkim = [row for row in dkim_all if row.lower().startswith("v=dkim1") or "p=" in row.lower()]
    mta_sts = [row for row in mta_sts_all if row.lower().startswith("v=stsv1")]
    tls_rpt = [row for row in tls_rpt_all if row.lower().startswith("v=tlsrptv1")]

    dmarc_tags = _tag_map(dmarc[0]) if len(dmarc) == 1 else {}
    dmarc_policy = dmarc_tags.get("p", "").lower()
    strict_dmarc = dmarc_policy in {"quarantine", "reject"}

    score = 0
    score += 25 if mx else 0
    score += 20 if len(spf) == 1 else 0
    score += 20 if len(dmarc) == 1 else 0
    score += 10 if strict_dmarc else 0
    score += 15 if dkim else 0
    score += 5 if mta_sts else 0
    score += 5 if tls_rpt else 0

    recommendations: list[dict[str, str]] = []
    if not mx:
        recommendations.append({"id": "mx", "severity": "critical", "message": "لا يوجد MX منشور للنطاق."})
    if len(spf) == 0:
        recommendations.append({"id": "spf", "severity": "critical", "message": "لا يوجد SPF. يمكن تجهيز Preview آمن لسجل TXT."})
    elif len(spf) > 1:
        recommendations.append({"id": "spf-multiple", "severity": "critical", "message": "يوجد أكثر من SPF؛ يجب دمجها في سجل SPF واحد."})
    if len(dmarc) == 0:
        recommendations.append({"id": "dmarc", "severity": "warning", "message": "DMARC غير موجود."})
    elif len(dmarc) > 1:
        recommendations.append({"id": "dmarc-multiple", "severity": "critical", "message": "يوجد أكثر من DMARC؛ يجب نشر سجل DMARC واحد فقط."})
    elif dmarc_policy not in {"quarantine", "reject"}:
        recommendations.append({"id": "dmarc-policy", "severity": "warning", "message": "DMARC موجود لكن سياسة p ليست quarantine/reject."})
    if not dkim:
        recommendations.append({"id": "dkim", "severity": "warning", "message": f"لم يتم العثور على DKIM للـselector: {selector}."})
    if not mta_sts:
        recommendations.append({"id": "mta-sts", "severity": "info", "message": "MTA-STS DNS marker غير موجود."})
    if not tls_rpt:
        recommendations.append({"id": "tls-rpt", "severity": "info", "message": "SMTP TLS Reporting غير موجود."})

    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return {
        "domain": domain,
        "selector": selector,
        "score": score,
        "grade": grade,
        "checks": {
            "mx": mx,
            "spf": spf,
            "dmarc": dmarc,
            "dmarc_policy": dmarc_policy,
            "dkim": dkim,
            "mta_sts": mta_sts,
            "tls_rpt": tls_rpt,
            "mail_host": mail_host,
            "mail_host_a": mail_a,
        },
        "recommendations": recommendations,
    }


def _dns_binding(conn, domain: str):
    return conn.execute(
        """SELECT b.target_id,t.provider,t.enabled
           FROM dns_zone_bindings b JOIN integration_targets t ON t.id=b.target_id
           WHERE b.domain=? AND t.enabled=1 AND t.provider IN ('cloudflare','powerdns')""",
        (domain,),
    ).fetchone()


def _existing_preview(conn, *, domain: str, owner: str, record_type: str, record_name: str, record_value: str):
    return conn.execute(
        """SELECT id FROM dns_changes
           WHERE domain=? AND owner=? AND status='preview' AND operation='create'
             AND record_type=? AND record_name=? AND record_value=?
           ORDER BY id DESC LIMIT 1""",
        (domain, owner, record_type, record_name, record_value),
    ).fetchone()


def _insert_preview(conn, *, domain: str, owner: str, target_id: int, record_type: str, record_name: str,
                    record_value: str, ttl: int = 300, priority: int = 0) -> tuple[int, bool]:
    existing = _existing_preview(
        conn,
        domain=domain,
        owner=owner,
        record_type=record_type,
        record_name=record_name,
        record_value=record_value,
    )
    if existing:
        return int(existing["id"]), False
    cur = conn.execute(
        """INSERT INTO dns_changes(
             domain,target_id,operation,record_type,record_name,record_value,ttl,priority,
             provider_record_id,status,snapshot_json,owner,created_at,applied_at
           ) VALUES(?,?,'create',?,?,?,?,?,'','preview','',?,?,0)""",
        (domain, target_id, record_type, record_name, record_value, ttl, priority, owner, int(time.time())),
    )
    return int(cur.lastrowid), True


def register_deliverability_routes(app):
    @app.get("/api/mail/deliverability/health")
    @role_required("admin", "operator")
    def deliverability_health():
        domain = str(request.args.get("domain", "")).strip().lower().rstrip(".")
        selector = str(request.args.get("selector", "default")).strip().lower()
        if not DOMAIN_RE.fullmatch(domain) or not SELECTOR_RE.fullmatch(selector):
            return jsonify(ok=False, error="invalid domain or DKIM selector"), 400
        with db() as conn:
            owner, role = _context(conn, domain)
            if not owner or not role:
                return jsonify(ok=False, error="mail domain outside your scope"), 403
            if not feature_allowed("email.deliverability", username=owner, role=role, connection=conn):
                return jsonify(ok=False, error="email.deliverability disabled by hosting policy"), 403
        result = _health(domain, selector)
        return jsonify(ok=True, **result)

    @app.post("/api/mail/deliverability/prepare-dns")
    @role_required("admin", "operator")
    @step_up_required
    def deliverability_prepare_dns():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        selector = str(data.get("selector", "default")).strip().lower()
        mail_host = str(data.get("mail_host", f"mail.{domain}")).strip().lower().rstrip(".")
        mail_ipv4 = str(data.get("mail_ipv4", "")).strip()
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
                return jsonify(ok=False, error="mail IPv4 must be a public IPv4 address"), 400

        health = _health(domain, selector)
        checks = health["checks"]
        created: list[dict] = []
        reused: list[int] = []
        with db() as conn:
            owner, role = _context(conn, domain)
            if not owner or not role:
                return jsonify(ok=False, error="mail domain outside your scope"), 403
            if not feature_allowed("email.deliverability", username=owner, role=role, connection=conn):
                return jsonify(ok=False, error="email.deliverability disabled by hosting policy"), 403
            if not feature_allowed("domains.zone_editor", username=owner, role=role, connection=conn):
                return jsonify(ok=False, error="domains.zone_editor disabled by hosting policy"), 403
            binding = _dns_binding(conn, domain)
            if not binding:
                return jsonify(ok=False, error="DNS zone has no active Cloudflare/PowerDNS binding"), 409
            target_id = int(binding["target_id"])

            desired: list[tuple[str, str, str, int]] = []
            if not checks["mx"]:
                desired.append(("MX", domain, mail_host, 10))
            if mail_ipv4 and not checks["mail_host_a"]:
                desired.append(("A", mail_host, mail_ipv4, 0))
            if not checks["spf"]:
                desired.append(("TXT", domain, "v=spf1 mx -all", 0))
            if not checks["dmarc"]:
                desired.append(("TXT", f"_dmarc.{domain}", f"v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}; adkim=s; aspf=s", 0))
            if not checks["tls_rpt"]:
                desired.append(("TXT", f"_smtp._tls.{domain}", f"v=TLSRPTv1; rua=mailto:postmaster@{domain}", 0))

            for record_type, name, value, priority in desired:
                preview_id, was_created = _insert_preview(
                    conn,
                    domain=domain,
                    owner=owner,
                    target_id=target_id,
                    record_type=record_type,
                    record_name=name,
                    record_value=value,
                    ttl=300,
                    priority=priority,
                )
                if was_created:
                    created.append({
                        "id": preview_id,
                        "record_type": record_type,
                        "record_name": name,
                        "record_value": value,
                        "priority": priority,
                        "status": "preview",
                    })
                else:
                    reused.append(preview_id)

        audit("mail-deliverability-dns-preview", f"domain={domain} owner={owner} created={len(created)} reused={len(reused)}")
        return jsonify(
            ok=True,
            domain=domain,
            provider=str(binding["provider"]),
            created=created,
            reused_preview_ids=reused,
            note="DNS was not changed. Review each preview and apply it through the DNS change flow.",
        )
