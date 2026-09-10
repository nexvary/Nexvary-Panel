from __future__ import annotations

from flask import jsonify, request, session

from .config import DOMAIN_RE
from .core import audit, db
from .hosting_policy import feature_allowed
from .ops_client import ops_call
from .security import role_required, step_up_required


def _owner_role(conn, owner: str) -> str:
    if owner == "admin":
        return "admin"
    row = conn.execute("SELECT role FROM users WHERE username=?", (owner,)).fetchone()
    return str(row["role"]) if row else "operator"


def _context(conn, domain: str):
    site = conn.execute("SELECT domain,owner FROM sites WHERE domain=?", (domain,)).fetchone()
    if not site:
        return None, None
    owner = str(site["owner"])
    if session.get("role") != "admin" and owner != str(session.get("user", "")):
        return None, None
    if not feature_allowed("domains.zone_editor", username=owner, role=_owner_role(conn, owner), connection=conn):
        return site, None
    target = conn.execute(
        """SELECT b.target_id,t.provider,t.endpoint,t.secret_id,t.enabled
           FROM dns_zone_bindings b JOIN integration_targets t ON t.id=b.target_id
           WHERE b.domain=? AND t.enabled=1 AND t.provider IN ('cloudflare','powerdns')""",
        (domain,),
    ).fetchone()
    return site, target


def _payload(target) -> dict:
    return {
        "provider": str(target["provider"]),
        "endpoint": str(target["endpoint"]),
        "secret_id": str(target["secret_id"]),
    }


def register_dnssec_routes(app):
    @app.get("/api/domains/dnssec")
    @role_required("admin", "operator")
    def dnssec_status():
        domain = str(request.args.get("domain", "")).strip().lower().rstrip(".")
        if not DOMAIN_RE.fullmatch(domain):
            return jsonify(ok=False, error="invalid domain"), 400
        with db() as conn:
            site, target = _context(conn, domain)
            if not site:
                return jsonify(ok=False, error="domain outside your scope"), 403
            if target is None:
                owner = str(site["owner"])
                if not feature_allowed("domains.zone_editor", username=owner, role=_owner_role(conn, owner), connection=conn):
                    return jsonify(ok=False, error="domains.zone_editor disabled by hosting policy"), 403
                return jsonify(ok=False, error="DNS zone has no active Cloudflare/PowerDNS binding"), 409
            provider = str(target["provider"])
            payload = _payload(target)
        result = ops_call({"action": "dnssec-status", **payload}, timeout=20)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "DNSSEC provider unavailable"))[:180]), 503
        result["domain"] = domain
        result["provider"] = provider
        return jsonify(result)

    @app.post("/api/domains/dnssec")
    @role_required("admin", "operator")
    @step_up_required
    def dnssec_set():
        data = request.get_json(silent=True) or {}
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        enabled = data.get("enabled")
        if not DOMAIN_RE.fullmatch(domain) or not isinstance(enabled, bool):
            return jsonify(ok=False, error="invalid DNSSEC request"), 400
        with db() as conn:
            site, target = _context(conn, domain)
            if not site:
                return jsonify(ok=False, error="domain outside your scope"), 403
            if target is None:
                owner = str(site["owner"])
                if not feature_allowed("domains.zone_editor", username=owner, role=_owner_role(conn, owner), connection=conn):
                    return jsonify(ok=False, error="domains.zone_editor disabled by hosting policy"), 403
                return jsonify(ok=False, error="DNS zone has no active Cloudflare/PowerDNS binding"), 409
            provider = str(target["provider"])
            payload = _payload(target)
        result = ops_call({"action": "dnssec-set", "enabled": enabled, **payload}, timeout=35)
        if not result.get("ok"):
            error = str(result.get("error", "DNSSEC provider rejected change"))[:180]
            status = 409 if error == "powerdns-dnssec-disable-requires-controlled-key-rollover" else 503
            return jsonify(ok=False, error=error), status
        audit("dnssec-set", f"domain={domain} provider={provider} enabled={int(enabled)}")
        result["domain"] = domain
        result["provider"] = provider
        return jsonify(result)
