from __future__ import annotations

import ipaddress
import socket
import ssl
import time

from flask import jsonify, request

from .config import DOMAIN_RE
from .core import can_manage_domain, db, role_required


def _registered_site(domain: str) -> bool:
    with db() as conn:
        row = conn.execute("SELECT 1 FROM sites WHERE domain=? LIMIT 1", (domain,)).fetchone()
    return bool(row)


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(ip.is_global and not ip.is_multicast and not ip.is_unspecified)


def _resolve(domain: str) -> tuple[list[str], list[str], int]:
    started = time.perf_counter()
    infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    seen: set[str] = set()
    public: list[str] = []
    blocked: list[str] = []
    for info in infos:
        ip = str(info[4][0])
        if ip in seen:
            continue
        seen.add(ip)
        (public if _is_public_ip(ip) else blocked).append(ip)
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return public[:12], blocked[:12], elapsed_ms


def _tls_probe(domain: str, ip: str) -> dict:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    address = (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443)
    context = ssl.create_default_context()
    started = time.perf_counter()
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(4.0)
    try:
        raw.connect(address)
        with context.wrap_socket(raw, server_hostname=domain) as tls:
            cert = tls.getpeercert() or {}
            expires_text = str(cert.get("notAfter") or "")
            expires_epoch = int(ssl.cert_time_to_seconds(expires_text)) if expires_text else 0
            days_left = int((expires_epoch - time.time()) // 86400) if expires_epoch else None
            subject_parts = cert.get("subject") or ()
            subject = ""
            for part in subject_parts:
                for key, value in part:
                    if key == "commonName":
                        subject = str(value)
                        break
                if subject:
                    break
            cipher = tls.cipher() or ("", "", 0)
            return {
                "ok": True,
                "ip": ip,
                "latency_ms": int((time.perf_counter() - started) * 1000),
                "protocol": tls.version() or "",
                "cipher": str(cipher[0] or ""),
                "subject": subject,
                "expires": expires_text,
                "days_left": days_left,
            }
    except (OSError, ssl.SSLError, ValueError) as exc:
        try:
            raw.close()
        except OSError:
            pass
        return {
            "ok": False,
            "ip": ip,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "error": str(exc)[:240],
        }


def register_health_routes(app):
    @app.get("/api/site-health")
    @role_required("admin", "operator", "viewer")
    def site_health():
        domain = request.args.get("domain", "").lower().strip()
        if not DOMAIN_RE.match(domain) or not _registered_site(domain) or not can_manage_domain(domain):
            return jsonify(ok=False, error="site not allowed"), 403
        try:
            public, blocked, dns_ms = _resolve(domain)
        except socket.gaierror as exc:
            return jsonify(ok=True, domain=domain, dns={"ok": False, "addresses": [], "blocked": [], "latency_ms": 0, "error": str(exc)[:180]}, tls={"ok": False, "error": "DNS resolution failed"})
        dns = {"ok": bool(public or blocked), "addresses": public, "blocked": blocked, "latency_ms": dns_ms}
        if not public:
            tls = {"ok": False, "error": "TLS probe blocked: no verified public IP address"}
        else:
            tls = _tls_probe(domain, public[0])
        return jsonify(ok=True, domain=domain, dns=dns, tls=tls)
