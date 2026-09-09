from __future__ import annotations

import time

import dns.exception
import dns.resolver
from flask import jsonify, request

from .config import DOMAIN_RE
from .core import can_manage_domain, db, role_required

RECORD_TYPES = ("A", "AAAA", "NS", "MX", "TXT", "CAA")
MAX_RECORDS_PER_TYPE = 20
MAX_TEXT = 500


def _registered_site(domain: str) -> bool:
    with db() as conn:
        return bool(conn.execute("SELECT 1 FROM sites WHERE domain=? LIMIT 1", (domain,)).fetchone())


def _record_text(record) -> str:
    try:
        value = record.to_text()
    except Exception:
        value = str(record)
    return value.replace("\x00", "")[:MAX_TEXT]


def _resolve_type(resolver: dns.resolver.Resolver, name: str, record_type: str) -> dict:
    started = time.perf_counter()
    try:
        answer = resolver.resolve(name, record_type, lifetime=2.5, search=False)
        records = [_record_text(r) for r in list(answer)[:MAX_RECORDS_PER_TYPE]]
        ttl = int(answer.rrset.ttl) if answer.rrset is not None else None
        return {"ok": True, "records": records, "ttl": ttl, "latency_ms": int((time.perf_counter() - started) * 1000)}
    except dns.resolver.NXDOMAIN:
        return {"ok": False, "records": [], "error": "NXDOMAIN", "latency_ms": int((time.perf_counter() - started) * 1000)}
    except dns.resolver.NoAnswer:
        return {"ok": True, "records": [], "latency_ms": int((time.perf_counter() - started) * 1000)}
    except dns.resolver.NoNameservers:
        return {"ok": False, "records": [], "error": "no nameservers available", "latency_ms": int((time.perf_counter() - started) * 1000)}
    except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
        return {"ok": False, "records": [], "error": "timeout", "latency_ms": int((time.perf_counter() - started) * 1000)}
    except dns.exception.DNSException as exc:
        return {"ok": False, "records": [], "error": str(exc)[:160], "latency_ms": int((time.perf_counter() - started) * 1000)}


def dns_inventory(domain: str) -> dict:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 1.5
    resolver.lifetime = 2.5
    records = {record_type: _resolve_type(resolver, domain, record_type) for record_type in RECORD_TYPES}
    dmarc = _resolve_type(resolver, f"_dmarc.{domain}", "TXT")
    mail = {
        "mx_present": bool(records["MX"].get("records")),
        "dmarc_present": any("v=DMARC1" in item.upper() for item in dmarc.get("records", [])),
        "dmarc": dmarc,
    }
    populated = sum(1 for value in records.values() if value.get("records"))
    return {
        "domain": domain,
        "record_types": records,
        "mail_posture": mail,
        "summary": {"queried": len(RECORD_TYPES), "populated": populated},
    }


def register_dns_routes(app):
    @app.get("/api/dns/inventory")
    @role_required("admin", "operator", "viewer")
    def api_dns_inventory():
        domain = request.args.get("domain", "").lower().strip()
        if not DOMAIN_RE.match(domain) or not _registered_site(domain) or not can_manage_domain(domain):
            return jsonify(ok=False, error="site not allowed"), 403
        return jsonify(ok=True, **dns_inventory(domain))
