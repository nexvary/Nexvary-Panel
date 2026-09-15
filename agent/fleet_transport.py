from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from secret_vault import SecretVault

FLEET_TOKEN_RE = re.compile(r"^nvp_fleet_[A-Za-z0-9_-]{40,180}$")
FLEET_REQUEST_RE = re.compile(r"^[a-f0-9]{32}$")
FLEET_OPERATIONS = {"restart-nginx", "restart-mariadb", "enable-ntp", "system-updates"}
FLEET_PORTS = {443, 8443}
MAX_RESPONSE = 64 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _resolve_public(host: str, port: int) -> tuple[str, ...]:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not literal.is_global:
            raise ValueError("fleet endpoint must use a public address")
        return (str(literal),)
    if host == "localhost" or host.endswith((".localhost", ".local")):
        raise ValueError("fleet endpoint must use a public host")
    if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9.-]+", host):
        raise ValueError("invalid fleet endpoint host")
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("fleet endpoint hostname could not be resolved") from exc
    addresses = sorted({str(answer[4][0]).split("%", 1)[0] for answer in answers if answer and answer[4]})
    if not addresses:
        raise ValueError("fleet endpoint hostname has no usable address")
    for address in addresses:
        try:
            if not ipaddress.ip_address(address).is_global:
                raise ValueError("fleet endpoint resolves to a private/local address")
        except ValueError as exc:
            if str(exc) == "fleet endpoint resolves to a private/local address":
                raise
            raise ValueError("fleet endpoint resolved to an invalid address") from exc
    return tuple(addresses)


def normalize_endpoint(value: str) -> str:
    try:
        parts = urlsplit(str(value).strip())
    except ValueError as exc:
        raise ValueError("invalid fleet endpoint") from exc
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("fleet endpoint must be public HTTPS without credentials, query or fragment")
    try:
        port = int(parts.port or 443)
    except ValueError as exc:
        raise ValueError("invalid fleet endpoint port") from exc
    if port not in FLEET_PORTS:
        raise ValueError("fleet endpoint port must be 443 or 8443")
    host = parts.hostname.rstrip(".").lower()
    _resolve_public(host, port)
    path = (parts.path or "").rstrip("/")
    if len(path) > 180 or ".." in path.split("/"):
        raise ValueError("invalid fleet endpoint path")
    host_for_url = f"[{host}]" if ":" in host else host
    netloc = host_for_url if port == 443 else f"{host_for_url}:{port}"
    return urlunsplit(("https", netloc, path, "", ""))


def send_apply(
    vault: SecretVault,
    *,
    endpoint: str,
    secret_id: str,
    operation: str,
    request_id: str,
    issued_at: int,
    payload: dict,
) -> dict:
    if operation not in FLEET_OPERATIONS:
        return {"ok": False, "error": "fleet operation not allowed"}
    if not FLEET_REQUEST_RE.fullmatch(request_id):
        return {"ok": False, "error": "invalid fleet request id"}
    if abs(int(time.time()) - int(issued_at or 0)) > 300:
        return {"ok": False, "error": "fleet request timestamp outside allowed window"}
    raw_payload = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(raw_payload) > 4096:
        return {"ok": False, "error": "fleet operation payload too large"}
    try:
        target = normalize_endpoint(endpoint)
        credential = vault.credential_path(secret_id, "fleet")
        token = Path(credential).read_text(encoding="utf-8").strip()
        if not FLEET_TOKEN_RE.fullmatch(token):
            raise ValueError("fleet credential has invalid format")
    except (OSError, UnicodeError, ValueError) as exc:
        return {"ok": False, "error": str(exc), "code": "fleet-contract-invalid"}

    body = json.dumps(
        {"operation": operation, "request_id": request_id, "issued_at": int(issued_at), "payload": payload},
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        target.rstrip("/") + "/api/fleet/v1/apply",
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": request_id,
            "User-Agent": "Nexvary-Fleet/0.8",
        },
        method="POST",
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=1900 if operation == "system-updates" else 60) as response:
            status = int(getattr(response, "status", 200))
            raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            return {"ok": False, "error": "fleet response too large"}
        decoded = json.loads(raw.decode("utf-8")) if raw else {}
        if not isinstance(decoded, dict):
            return {"ok": False, "error": "invalid fleet response"}
        if status < 200 or status >= 300 or not decoded.get("ok"):
            return {"ok": False, "error": str(decoded.get("error", f"remote fleet status {status}"))[:240], "remote_status": status}
        result = decoded.get("result") if isinstance(decoded.get("result"), dict) else {}
        safe_result = {
            str(key)[:64]: value
            for key, value in list(result.items())[:32]
            if isinstance(value, (str, int, float, bool, type(None)))
        }
        return {
            "ok": True,
            "request_id": request_id,
            "operation": operation,
            "status": str(decoded.get("status", "applied"))[:32],
            "remote_status": status,
            "result": safe_result,
        }
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(16 * 1024)
            decoded = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            decoded = {}
        return {"ok": False, "error": str(decoded.get("error", f"remote fleet HTTP {exc.code}"))[:240], "remote_status": int(exc.code)}
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
        return {"ok": False, "error": "fleet remote apply failed", "code": "fleet-remote-failed"}
