from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
import sqlite3
import time

from flask import jsonify, request, session

from .config import DOMAIN_RE
from .core import audit, db
from .hosting_policy import feature_allowed
from .ops_client import ops_call
from .security import role_required, step_up_required

DDNS_TOKEN_RE = re.compile(r"^nvp_ddns_[A-Za-z0-9_-]{32,96}$")
DDNS_UPDATE_MIN_SECONDS = 10


def _owner_role(conn, owner: str) -> str:
    if owner == "admin":
        return "admin"
    row = conn.execute("SELECT role FROM users WHERE username=? AND enabled=1", (owner,)).fetchone()
    return str(row["role"]) if row else "viewer"


def _site_scope(conn, domain: str):
    row = conn.execute("SELECT domain,owner,enabled FROM sites WHERE domain=?", (domain,)).fetchone()
    if not row or not row["enabled"]:
        return None
    if session.get("role") == "admin" or str(row["owner"]) == str(session.get("user", "")):
        return row
    return None


def _hostname(domain: str, value: object) -> str:
    raw = str(value or "").strip().lower().rstrip(".")
    if raw == "@":
        return domain
    if "." not in raw:
        raw = f"{raw}.{domain}"
    if not DOMAIN_RE.fullmatch(raw):
        raise ValueError("invalid dynamic DNS hostname")
    if raw != domain and not raw.endswith("." + domain):
        raise ValueError("dynamic DNS hostname must remain inside the managed zone")
    return raw


def _address(value: object, record_type: str) -> str:
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError as exc:
        raise ValueError("invalid public IP address") from exc
    expected = 4 if record_type == "A" else 6
    if address.version != expected:
        raise ValueError(f"{record_type} requires IPv{expected}")
    if not address.is_global or address.is_multicast or address.is_unspecified:
        raise ValueError("dynamic DNS requires a public unicast address")
    return str(address)


def _ttl(value: object) -> int:
    try:
        ttl = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid TTL") from exc
    if not 60 <= ttl <= 86400:
        raise ValueError("TTL must be between 60 and 86400 seconds")
    return ttl


def _target(conn, domain: str):
    return conn.execute(
        """SELECT b.target_id,t.provider,t.endpoint,t.secret_id,t.enabled
           FROM dns_zone_bindings b JOIN integration_targets t ON t.id=b.target_id
           WHERE b.domain=? AND t.provider IN ('cloudflare','powerdns')""",
        (domain,),
    ).fetchone()


def _provider_payload(row, target, operation: str, address: str) -> dict:
    return {
        "action": "dns-apply",
        "provider": str(target["provider"]),
        "endpoint": str(target["endpoint"]),
        "secret_id": str(target["secret_id"]),
        "domain": str(row["domain"]),
        "operation": operation,
        "record_type": str(row["record_type"]),
        "record_name": str(row["hostname"]),
        "record_value": address,
        "ttl": int(row["ttl"]),
        "priority": 0,
        "provider_record_id": str(row["provider_record_id"] or ""),
    }


def _rollback(target, snapshot: object) -> None:
    if not isinstance(snapshot, dict):
        return
    ops_call(
        {
            "action": "dns-rollback",
            "provider": str(target["provider"]),
            "endpoint": str(target["endpoint"]),
            "secret_id": str(target["secret_id"]),
            "snapshot": snapshot,
        },
        timeout=35,
    )


def _new_token() -> str:
    return "nvp_ddns_" + secrets.token_urlsafe(32)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _token_from_request() -> str:
    header = str(request.headers.get("Authorization", ""))
    if not header.startswith("Bearer "):
        return ""
    token = header[7:].strip()
    return token if DDNS_TOKEN_RE.fullmatch(token) else ""


def _token_audit(owner: str, record_id: int, hostname: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO audit(ts,actor,action,detail,ip) VALUES(?,?,?,?,?)",
            (int(time.time()), owner[:64], "dynamic-dns-update", f"record_id={record_id} hostname={hostname}"[:700], ""),
        )


def register_dynamic_dns_routes(app):
    @app.get("/api/dynamic-dns/records")
    @role_required("admin", "operator", "viewer")
    def dynamic_dns_list():
        domain = str(request.args.get("domain", "")).strip().lower().rstrip(".")
        if not DOMAIN_RE.fullmatch(domain):
            return jsonify(ok=False, error="invalid domain"), 400
        with db() as conn:
            site = _site_scope(conn, domain)
            if not site:
                return jsonify(ok=False, error="domain outside your scope"), 403
            owner = str(site["owner"])
            if not feature_allowed("domains.dynamic_dns", username=owner, role=_owner_role(conn, owner), connection=conn):
                return jsonify(ok=False, error="domains.dynamic_dns disabled by hosting policy"), 403
            rows = conn.execute(
                """SELECT id,domain,hostname,record_type,target_id,provider_record_id,ttl,last_address,last_update,
                          enabled,owner,created_at,updated_at
                   FROM dynamic_dns_records WHERE domain=? ORDER BY hostname,record_type""",
                (domain,),
            ).fetchall()
        return jsonify(ok=True, domain=domain, records=[dict(row) for row in rows], update_path="/api/dynamic-dns/update/{record_id}")

    @app.post("/api/dynamic-dns/records")
    @role_required("admin", "operator")
    @step_up_required
    def dynamic_dns_create():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        record_type = str(data.get("record_type", "A")).upper()
        if record_type not in {"A", "AAAA"} or not DOMAIN_RE.fullmatch(domain):
            return jsonify(ok=False, error="dynamic DNS supports managed A/AAAA records only"), 400
        try:
            hostname = _hostname(domain, data.get("hostname", "@"))
            address = _address(data.get("address"), record_type)
            ttl = _ttl(data.get("ttl", 300))
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        with db() as conn:
            site = _site_scope(conn, domain)
            if not site:
                return jsonify(ok=False, error="domain outside your scope"), 403
            owner = str(site["owner"])
            role = _owner_role(conn, owner)
            if not feature_allowed("domains.dynamic_dns", username=owner, role=role, connection=conn):
                return jsonify(ok=False, error="domains.dynamic_dns disabled by hosting policy"), 403
            target = _target(conn, domain)
            if not target or not target["enabled"]:
                return jsonify(ok=False, error="DNS zone has no active Cloudflare/PowerDNS binding"), 409
            if conn.execute("SELECT 1 FROM dynamic_dns_records WHERE domain=? AND hostname=? AND record_type=?", (domain, hostname, record_type)).fetchone():
                return jsonify(ok=False, error="dynamic DNS record already exists"), 409
        transient = {
            "domain": domain,
            "hostname": hostname,
            "record_type": record_type,
            "ttl": ttl,
            "provider_record_id": "",
        }
        result = ops_call(_provider_payload(transient, target, "create", address), timeout=35)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "DNS provider rejected dynamic record"))[:180]), 503
        token = _new_token()
        now = int(time.time())
        provider_record_id = str(result.get("provider_record_id", ""))[:160]
        try:
            with db() as conn:
                cur = conn.execute(
                    """INSERT INTO dynamic_dns_records
                       (domain,hostname,record_type,target_id,provider_record_id,token_hash,ttl,last_address,last_update,enabled,owner,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?)""",
                    (domain, hostname, record_type, int(target["target_id"]), provider_record_id, _token_hash(token), ttl, address, now, owner, now, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError:
            _rollback(target, result.get("snapshot"))
            return jsonify(ok=False, error="dynamic DNS record already exists"), 409
        audit("dynamic-dns-create", f"record_id={record_id} hostname={hostname} type={record_type} owner={owner}")
        return jsonify(ok=True, id=record_id, hostname=hostname, record_type=record_type, address=address, ttl=ttl, token=token, shown_once=True), 201

    @app.post("/api/dynamic-dns/records/<int:record_id>/rotate-token")
    @role_required("admin", "operator")
    @step_up_required
    def dynamic_dns_rotate(record_id: int):
        with db() as conn:
            row = conn.execute("SELECT id,domain,hostname,owner FROM dynamic_dns_records WHERE id=?", (record_id,)).fetchone()
            if not row or not _site_scope(conn, str(row["domain"])):
                return jsonify(ok=False, error="dynamic DNS record not found"), 404
            token = _new_token()
            conn.execute("UPDATE dynamic_dns_records SET token_hash=?,updated_at=? WHERE id=?", (_token_hash(token), int(time.time()), record_id))
        audit("dynamic-dns-token-rotate", f"record_id={record_id} hostname={row['hostname']} owner={row['owner']}")
        return jsonify(ok=True, id=record_id, token=token, shown_once=True)

    @app.delete("/api/dynamic-dns/records/<int:record_id>")
    @role_required("admin", "operator")
    @step_up_required
    def dynamic_dns_delete(record_id: int):
        with db() as conn:
            row = conn.execute("SELECT * FROM dynamic_dns_records WHERE id=?", (record_id,)).fetchone()
            if not row or not _site_scope(conn, str(row["domain"])):
                return jsonify(ok=False, error="dynamic DNS record not found"), 404
            target = _target(conn, str(row["domain"]))
            if not target or int(target["target_id"]) != int(row["target_id"]):
                return jsonify(ok=False, error="DNS provider binding changed; rebind before deleting this record"), 409
        result = ops_call(_provider_payload(row, target, "delete", str(row["last_address"])), timeout=35)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "DNS provider rejected delete"))[:180]), 503
        try:
            with db() as conn:
                conn.execute("DELETE FROM dynamic_dns_records WHERE id=?", (record_id,))
        except sqlite3.Error:
            _rollback(target, result.get("snapshot"))
            return jsonify(ok=False, error="dynamic DNS metadata delete failed; provider state restored"), 500
        audit("dynamic-dns-delete", f"record_id={record_id} hostname={row['hostname']} owner={row['owner']}")
        return jsonify(ok=True, id=record_id, deleted=True)

    @app.post("/api/dynamic-dns/update/<int:record_id>")
    def dynamic_dns_update(record_id: int):
        token = _token_from_request()
        if not token:
            return jsonify(ok=False, error="dynamic DNS bearer token required"), 401
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        now = int(time.time())
        with db() as conn:
            row = conn.execute("SELECT * FROM dynamic_dns_records WHERE id=? AND enabled=1", (record_id,)).fetchone()
            if not row or not hmac.compare_digest(str(row["token_hash"]), _token_hash(token)):
                return jsonify(ok=False, error="invalid dynamic DNS token"), 401
            owner = str(row["owner"])
            role = _owner_role(conn, owner)
            if role == "viewer" and owner != "admin":
                return jsonify(ok=False, error="dynamic DNS owner is inactive"), 403
            if not feature_allowed("domains.dynamic_dns", username=owner, role=role, connection=conn):
                return jsonify(ok=False, error="domains.dynamic_dns disabled by hosting policy"), 403
            if now - int(row["last_update"] or 0) < DDNS_UPDATE_MIN_SECONDS:
                return jsonify(ok=False, error="dynamic DNS update rate limited", retry_after=DDNS_UPDATE_MIN_SECONDS), 429
            target = _target(conn, str(row["domain"]))
            if not target or int(target["target_id"]) != int(row["target_id"]) or not target["enabled"]:
                return jsonify(ok=False, error="dynamic DNS provider binding is unavailable"), 409
            try:
                address = _address(data.get("address"), str(row["record_type"]))
            except ValueError as exc:
                return jsonify(ok=False, error=str(exc)), 400
            if hmac.compare_digest(address, str(row["last_address"])):
                conn.execute("UPDATE dynamic_dns_records SET last_update=?,updated_at=? WHERE id=?", (now, now, record_id))
                _token_audit(owner, record_id, str(row["hostname"]))
                return jsonify(ok=True, id=record_id, hostname=row["hostname"], address=address, changed=False)
        result = ops_call(_provider_payload(row, target, "update", address), timeout=35)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "DNS provider rejected dynamic update"))[:180]), 503
        try:
            with db() as conn:
                conn.execute(
                    "UPDATE dynamic_dns_records SET provider_record_id=?,last_address=?,last_update=?,updated_at=? WHERE id=?",
                    (str(result.get("provider_record_id", row["provider_record_id"]))[:160], address, now, now, record_id),
                )
        except sqlite3.Error:
            _rollback(target, result.get("snapshot"))
            return jsonify(ok=False, error="dynamic DNS metadata update failed; provider state restored"), 500
        _token_audit(owner, record_id, str(row["hostname"]))
        return jsonify(ok=True, id=record_id, hostname=row["hostname"], address=address, changed=True, updated_at=now)
