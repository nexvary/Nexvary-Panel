#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import socket
import urllib.parse
from pathlib import Path

import hosting_ops_agent as core

POSTGRES_SOCK = Path(os.environ.get("NVP_POSTGRES_SOCK", "/run/nexvary-panel-postgres/postgres.sock"))
BASE_DISPATCH = core.dispatch
BASE_STATUS = core._status
MAX_AUTOSSL_NAMES = 25
MAX_PROBE_BYTES = 32 * 1024


def postgres_call(payload: dict, timeout: int = 40) -> dict:
    if not POSTGRES_SOCK.exists() or POSTGRES_SOCK.is_symlink():
        return {"ok": False, "error": "postgres-provider-offline"}
    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) > 16 * 1024:
        return {"ok": False, "error": "postgres-request-too-large"}
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(str(POSTGRES_SOCK))
        client.sendall(raw)
        response = b""
        while not response.endswith(b"\n") and len(response) <= 32 * 1024:
            chunk = client.recv(4096)
            if not chunk:
                break
            response += chunk
    except (OSError, TimeoutError):
        return {"ok": False, "error": "postgres-provider-offline"}
    finally:
        client.close()
    if not response.endswith(b"\n") or len(response) > 32 * 1024:
        return {"ok": False, "error": "postgres-provider-invalid-response"}
    try:
        body = json.loads(response.decode("utf-8"))
    except Exception:
        return {"ok": False, "error": "postgres-provider-invalid-response"}
    return body if isinstance(body, dict) else {"ok": False, "error": "postgres-provider-invalid-response"}


def _ssl_names(data: dict) -> list[str]:
    primary = core._domain(data.get("domain"))
    raw = data.get("domains", [])
    if raw in (None, ""):
        raw = []
    if not isinstance(raw, list) or len(raw) > MAX_AUTOSSL_NAMES:
        raise ValueError("invalid-autossl-domain-set")
    names = [primary]
    for value in raw:
        name = core._domain(value)
        if name not in names:
            names.append(name)
    if len(names) > MAX_AUTOSSL_NAMES:
        raise ValueError("autossl-domain-limit-exceeded")
    return names


def _configured_server_names(primary: str) -> set[str]:
    text = core._nginx_conf(primary).read_text(encoding="utf-8")
    names: set[str] = set()
    for group in re.findall(r"\bserver_name\s+([^;]+);", text):
        for value in group.split():
            value = value.strip().lower().rstrip(".")
            if core.DOMAIN_RE.fullmatch(value):
                names.add(value)
    return names


def _resolve_public(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, 80, type=socket.SOCK_STREAM)
    except OSError:
        return []
    found: list[str] = []
    for info in infos:
        value = str(info[4][0])
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if not address.is_global or address.is_multicast or address.is_unspecified:
            continue
        if value not in found:
            found.append(value)
    return found[:8]


def _probe_http(host: str, ip: str, path: str, token: str) -> dict:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    client = socket.socket(family, socket.SOCK_STREAM)
    client.settimeout(6)
    try:
        client.connect((ip, 80))
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: Nexvary-AutoSSL/0.7\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        client.sendall(request)
        raw = b""
        while len(raw) < MAX_PROBE_BYTES:
            chunk = client.recv(min(4096, MAX_PROBE_BYTES - len(raw)))
            if not chunk:
                break
            raw += chunk
    except OSError:
        return {"ok": False, "status": 0, "error": "http-challenge-unreachable"}
    finally:
        client.close()
    head, _, body = raw.partition(b"\r\n\r\n")
    first = head.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})\b", first)
    status = int(match.group(1)) if match else 0
    verified = status == 200 and token.encode("ascii") in body
    return {"ok": verified, "status": status, "error": "" if verified else "http-challenge-not-served"}


def _autossl_preflight(data: dict) -> dict:
    names = _ssl_names(data)
    primary = names[0]
    root = core._site_root(primary)
    configured = _configured_server_names(primary)
    challenge_parent = root / ".well-known"
    challenge_dir = challenge_parent / "acme-challenge"
    for path in (challenge_parent, challenge_dir):
        if path.exists() and path.is_symlink():
            raise ValueError("unsafe-acme-challenge-path")
    challenge_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    token = "nexvary-autossl-" + secrets.token_hex(16)
    challenge = challenge_dir / token
    challenge.write_text(token, encoding="ascii")
    os.chmod(challenge, 0o644)
    path = f"/.well-known/acme-challenge/{token}"
    checks: list[dict] = []
    try:
        for name in names:
            if name not in configured:
                checks.append({"domain": name, "ready": False, "dns": [], "http_status": 0, "reason": "domain-not-bound-to-managed-nginx-site"})
                continue
            addresses = _resolve_public(name)
            if not addresses:
                checks.append({"domain": name, "ready": False, "dns": [], "http_status": 0, "reason": "no-public-dns-address"})
                continue
            probe = {"ok": False, "status": 0, "error": "http-challenge-unreachable"}
            for address in addresses:
                probe = _probe_http(name, address, path, token)
                if probe.get("ok"):
                    break
            checks.append({
                "domain": name,
                "ready": bool(probe.get("ok")),
                "dns": addresses,
                "http_status": int(probe.get("status", 0) or 0),
                "reason": str(probe.get("error", ""))[:96],
            })
    finally:
        challenge.unlink(missing_ok=True)
    ready = bool(checks) and all(bool(item.get("ready")) for item in checks)
    return {"ok": True, "ready": ready, "domain": primary, "domains": names, "checks": checks, "challenge": "http-01-webroot"}


def _ssl_status_with_names(domain: str) -> dict:
    domain = core._domain(domain)
    result = core._ssl_status(domain)
    if not result.get("ok") or not result.get("installed"):
        result["names"] = []
        return result
    cert = Path("/etc/letsencrypt/live") / domain / "fullchain.pem"
    try:
        proc = core._run(["openssl", "x509", "-in", str(cert), "-noout", "-ext", "subjectAltName"], 15)
        names = sorted({m.lower().rstrip(".") for m in re.findall(r"DNS:([^,\s]+)", proc.stdout) if core.DOMAIN_RE.fullmatch(m.lower().rstrip("."))})
    except Exception:
        names = []
    result["names"] = names
    return result


def _ssl_issue_with_names(data: dict, preflight: dict | None = None) -> dict:
    names = _ssl_names(data)
    primary = names[0]
    email = str(data.get("email", "")).strip().lower()
    if not core.EMAIL_RE.fullmatch(email):
        raise ValueError("invalid-contact-email")
    preflight = preflight or _autossl_preflight(data)
    if not preflight.get("ready"):
        return {"ok": False, "error": "autossl-preflight-failed", "preflight": preflight}
    root = core._site_root(primary)
    args = ["certbot", "certonly", "--webroot", "-w", str(root), "--cert-name", primary]
    for name in names:
        args.extend(["-d", name])
    args.extend(["--non-interactive", "--agree-tos", "--email", email, "--keep-until-expiring"])
    if (Path("/etc/letsencrypt/live") / primary / "fullchain.pem").is_file():
        args.append("--force-renewal")
    core._run(args, 240)
    core._bind_ssl(primary)
    result = _ssl_status_with_names(primary)
    result["preflight"] = preflight
    return result


def _ssl_renew_with_preflight(data: dict, preflight: dict | None = None) -> dict:
    names = _ssl_names(data)
    primary = names[0]
    preflight = preflight or _autossl_preflight(data)
    if not preflight.get("ready"):
        return {"ok": False, "error": "autossl-preflight-failed", "preflight": preflight}
    core._run(["certbot", "renew", "--cert-name", primary, "--non-interactive"], 240)
    core._bind_ssl(primary)
    result = _ssl_status_with_names(primary)
    result["preflight"] = preflight
    return result


def _dnssec_status(data: dict) -> dict:
    provider = str(data.get("provider", "")).strip().lower()
    endpoint = str(data.get("endpoint", "")).strip()
    secret_id = str(data.get("secret_id", "")).strip()
    if provider == "cloudflare":
        base = core._cloudflare_target(endpoint)
        token = core._secret(secret_id, "cloudflare")
        body = core._http(
            f"{base}/dnssec",
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            allow_host="api.cloudflare.com",
        )
        if body.get("success") is not True or not isinstance(body.get("result"), dict):
            raise RuntimeError("dnssec-provider-rejected-status")
        item = body["result"]
        return {
            "ok": True,
            "provider": "cloudflare",
            "enabled": str(item.get("status", "")) in {"active", "pending"},
            "status": str(item.get("status", "unknown"))[:32],
            "algorithm": str(item.get("algorithm", ""))[:32],
            "digest_algorithm": str(item.get("digest_algorithm", ""))[:32],
            "digest_type": str(item.get("digest_type", ""))[:32],
            "key_tag": str(item.get("key_tag", ""))[:32],
            "digest": str(item.get("digest", ""))[:256],
            "ds": str(item.get("ds", ""))[:1024],
            "modified_on": str(item.get("modified_on", ""))[:64],
        }
    if provider == "powerdns":
        parts, _ = core._public_https(endpoint)
        zone_url = urllib.parse.urlunsplit(parts).rstrip("/")
        key = core._secret(secret_id, "powerdns")
        headers = {"X-API-Key": key, "Content-Type": "application/json"}
        zone = core._http(zone_url, headers=headers)
        enabled = bool(zone.get("dnssec")) if isinstance(zone, dict) else False
        public_keys: list[dict] = []
        if enabled:
            raw_keys = core._http(zone_url + "/cryptokeys", headers=headers).get("data", [])
            if isinstance(raw_keys, list):
                for item in raw_keys[:20]:
                    if not isinstance(item, dict):
                        continue
                    public_keys.append({
                        "id": int(item.get("id", 0) or 0),
                        "keytype": str(item.get("keytype", ""))[:16],
                        "active": bool(item.get("active")),
                        "published": bool(item.get("published")),
                        "algorithm": str(item.get("algorithm", ""))[:48],
                        "bits": int(item.get("bits", 0) or 0),
                        "dnskey": str(item.get("dnskey", ""))[:2048],
                        "ds": [str(v)[:1024] for v in (item.get("ds") or [])[:8]],
                    })
        return {"ok": True, "provider": "powerdns", "enabled": enabled, "status": "active" if enabled else "disabled", "keys": public_keys}
    raise ValueError("dnssec-provider-not-supported")


def _dnssec_set(data: dict) -> dict:
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        raise ValueError("dnssec-enabled-must-be-boolean")
    provider = str(data.get("provider", "")).strip().lower()
    endpoint = str(data.get("endpoint", "")).strip()
    secret_id = str(data.get("secret_id", "")).strip()
    if provider == "cloudflare":
        base = core._cloudflare_target(endpoint)
        token = core._secret(secret_id, "cloudflare")
        body = core._http(
            f"{base}/dnssec",
            "PATCH",
            {"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            {"status": "active" if enabled else "disabled"},
            allow_host="api.cloudflare.com",
        )
        if body.get("success") is not True:
            raise RuntimeError("dnssec-provider-rejected-change")
        return _dnssec_status(data)
    if provider == "powerdns":
        if not enabled:
            return {"ok": False, "error": "powerdns-dnssec-disable-requires-controlled-key-rollover"}
        current = _dnssec_status(data)
        if current.get("enabled"):
            return current
        parts, _ = core._public_https(endpoint)
        zone_url = urllib.parse.urlunsplit(parts).rstrip("/")
        key = core._secret(secret_id, "powerdns")
        headers = {"X-API-Key": key, "Content-Type": "application/json"}
        core._http(
            zone_url + "/cryptokeys",
            "POST",
            headers,
            {"keytype": "csk", "active": True, "published": True},
        )
        return _dnssec_status(data)
    raise ValueError("dnssec-provider-not-supported")


def composed_status() -> dict:
    body = BASE_STATUS()
    pg = postgres_call({"action": "status"}, timeout=8)
    capabilities = body.setdefault("capabilities", {})
    capabilities["postgres"] = bool(pg.get("ok") and pg.get("available"))
    capabilities["dnssec"] = True
    capabilities["autossl_preflight"] = True
    return body


def composed_dispatch(data: dict) -> dict:
    action = str(data.get("action", ""))
    if action == "status":
        return composed_status()
    if action == "postgres-create":
        return postgres_call({"action": "create", "db_name": data.get("db_name", ""), "db_user": data.get("db_user", ""), "password": data.get("password", "")})
    if action == "postgres-delete":
        return postgres_call({"action": "delete", "db_name": data.get("db_name", ""), "db_user": data.get("db_user", "")})
    if action == "dnssec-status":
        return _dnssec_status(data)
    if action == "dnssec-set":
        return _dnssec_set(data)
    if action == "ssl-preflight":
        return _autossl_preflight(data)
    if action == "ssl-status":
        return _ssl_status_with_names(str(data.get("domain", "")))
    if action == "ssl-issue":
        preflight = _autossl_preflight(data)
        return _ssl_issue_with_names(data, preflight)
    if action == "ssl-renew":
        preflight = _autossl_preflight(data)
        return _ssl_renew_with_preflight(data, preflight)
    return BASE_DISPATCH(data)


core.dispatch = composed_dispatch
core._status = composed_status

if __name__ == "__main__":
    core.main()
