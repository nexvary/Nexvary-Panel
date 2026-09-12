from __future__ import annotations

import ipaddress
import socket
import ssl
import time

from flask import jsonify, request, session

from .config import DOMAIN_RE
from .core import agent_call, audit, can_manage_domain, db, role_required
from .security import step_up_required

MAX_HEAD_BYTES = 16 * 1024
REMEDIATION_SERVICES = {
    "Service: nginx": "nginx",
    "Service: mariadb": "mariadb",
    "Service: fail2ban": "fail2ban",
    "Docker engine": "docker",
}


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
                f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Nexvary-Panel-Health/0.7\r\n"
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


def _doctor_snapshot() -> tuple[dict, dict]:
    result = agent_call({"action": "doctor"}, timeout=45)
    report = result.get("checks") if isinstance(result.get("checks"), dict) else {}
    return result, report


def _check_by_name(report: dict, name: str) -> dict | None:
    for item in report.get("checks", []):
        if isinstance(item, dict) and str(item.get("name", "")) == name:
            return item
    return None


def _doctor_plan(report: dict) -> list[dict]:
    nginx_config = _check_by_name(report, "NGINX configuration")
    plan: list[dict] = []
    for item in report.get("checks", []):
        if not isinstance(item, dict) or item.get("ok"):
            continue
        name = str(item.get("name", ""))
        service = REMEDIATION_SERVICES.get(name)
        safe = bool(service)
        reason = "Restart the allow-listed service and verify Doctor again."
        if name == "Service: nginx" and nginx_config and not nginx_config.get("ok"):
            safe = False
            reason = "NGINX configuration is invalid; automatic restart is blocked until configuration is repaired."
        elif not service:
            reason = "This diagnostic needs an explicit administrator decision; no automatic fix is permitted."
        plan.append(
            {
                "check": name,
                "severity": str(item.get("severity", "warning")),
                "detail": str(item.get("detail", ""))[:500],
                "safe": safe,
                "action": "restart-service" if safe else "manual",
                "service": service or "",
                "reason": reason,
                "rollback": "not-applicable: service restart changes no panel configuration or stored data" if safe else "manual",
            }
        )
    return plan


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

    @app.get("/api/doctor/remediation-preview")
    @role_required("admin", "operator")
    def doctor_remediation_preview():
        result, report = _doctor_snapshot()
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "Doctor unavailable"))[:240]), 503
        return jsonify(ok=True, report=report, remediation=_doctor_plan(report))

    @app.get("/api/doctor/remediations")
    @role_required("admin")
    def doctor_remediation_history():
        with db() as conn:
            rows = [dict(row) for row in conn.execute(
                "SELECT id,check_name,service_name,before_ok,before_detail,after_ok,after_detail,status,actor,created_at,updated_at FROM doctor_remediations ORDER BY id DESC LIMIT 50"
            ).fetchall()]
        return jsonify(ok=True, remediations=rows)

    @app.post("/api/doctor/remediate")
    @role_required("admin")
    @step_up_required
    def doctor_remediate():
        data = request.get_json(silent=True) or {}
        check_name = str(data.get("check", ""))[:120]
        service = REMEDIATION_SERVICES.get(check_name)
        if not service:
            return jsonify(ok=False, error="diagnostic has no allow-listed automatic remediation"), 400

        before_result, before_report = _doctor_snapshot()
        if not before_result.get("ok"):
            return jsonify(ok=False, error="Doctor preflight failed"), 503
        before = _check_by_name(before_report, check_name)
        if not before:
            return jsonify(ok=False, error="diagnostic is not present in current Doctor report"), 409
        if before.get("ok"):
            return jsonify(ok=True, already_healthy=True, check=before)
        if check_name == "Service: nginx":
            nginx_config = _check_by_name(before_report, "NGINX configuration")
            if nginx_config and not nginx_config.get("ok"):
                return jsonify(ok=False, error="automatic NGINX restart blocked because nginx -t is failing"), 409

        action = agent_call({"action": "service-restart", "name": service}, timeout=40)
        after_result, after_report = _doctor_snapshot()
        after = _check_by_name(after_report, check_name) if after_result.get("ok") else None
        verified = bool(action.get("ok") and after and after.get("ok"))
        now = int(time.time())
        with db() as conn:
            cur = conn.execute(
                """INSERT INTO doctor_remediations(check_name,service_name,before_ok,before_detail,after_ok,after_detail,status,actor,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    check_name,
                    service,
                    1 if before.get("ok") else 0,
                    str(before.get("detail", ""))[:500],
                    None if after is None else (1 if after.get("ok") else 0),
                    str((after or {}).get("detail", action.get("error", "")))[:500],
                    "verified" if verified else ("applied" if action.get("ok") else "failed"),
                    str(session.get("user", "admin"))[:64],
                    now,
                    now,
                ),
            )
            remediation_id = int(cur.lastrowid)
        audit("doctor-remediation", f"id={remediation_id} check={check_name} service={service} verified={int(verified)}")
        return jsonify(
            ok=verified,
            id=remediation_id,
            check=check_name,
            service=service,
            verified=verified,
            action={"ok": bool(action.get("ok")), "error": str(action.get("error", ""))[:240]},
            before=before,
            after=after or {},
        ), (200 if verified else 503)
