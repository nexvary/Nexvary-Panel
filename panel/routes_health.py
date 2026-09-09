from __future__ import annotations

import ipaddress
import socket
import ssl
import time

from flask import jsonify, request

from .config import DOMAIN_RE
from .core import can_manage_domain, db, role_required

MAX_HEAD_BYTES = 16 * 1024


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


def _parse_http_head(raw: bytes) -> dict:
    text = raw.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    status = 0
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key and key not in headers:
            headers[key] = value[:500]
    return {
        "status": status,
        "server": headers.get("server", "")[:120],
        "hsts": bool(headers.get("strict-transport-security")),
        "location": headers.get("location", "")[:500],
        "content_type": headers.get("content-type", "")[:180],
    }


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
            tls_elapsed = int((time.perf_counter() - started) * 1000)
            http_started = time.perf_counter()
            request_bytes = (
                f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Nexvary-Panel-Health/0.6\r\n"
                "Accept: */*\r\nConnection: close\r\n\r\n"
            ).encode("ascii")
            tls.sendall(request_bytes)
            buf = bytearray()
            while len(buf) < MAX_HEAD_BYTES and b"\r\n\r\n" not in buf:
                chunk = tls.recv(min(4096, MAX_HEAD_BYTES - len(buf)))
                if not chunk:
                    break
                buf.extend(chunk)
            http = _parse_http_head(bytes(buf))
            http["latency_ms"] = int((time.perf_counter() - http_started) * 1000)
            return {
                "ok": True,
                "ip": ip,
                "latency_ms": tls_elapsed,
                "protocol": tls.version() or "",
                "cipher": str(cipher[0] or ""),
                "subject": subject,
                "expires": expires_text,
                "days_left": days_left,
                "http": http,
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
            "http": {"status": 0, "server": "", "hsts": False, "location": "", "content_type": "", "latency_ms": 0},
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
            return jsonify(ok=True, domain=domain, dns={"ok": False, "addresses": [], "blocked": [], "latency_ms": 0, "error": str(exc)[:180]}, tls={"ok": False, "error": "DNS resolution failed", "http": {"status": 0}})
        dns = {"ok": bool(public or blocked), "addresses": public, "blocked": blocked, "latency_ms": dns_ms}
        if not public:
            tls = {"ok": False, "error": "TLS probe blocked: no verified public IP address", "http": {"status": 0}}
        else:
            tls = _tls_probe(domain, public[0])
        return jsonify(ok=True, domain=domain, dns=dns, tls=tls)
