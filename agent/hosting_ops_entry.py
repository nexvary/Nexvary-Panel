#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import socket
import urllib.parse
from pathlib import Path

import hosting_ops_agent as core

POSTGRES_SOCK = Path(os.environ.get("NVP_POSTGRES_SOCK", "/run/nexvary-panel-postgres/postgres.sock"))
BASE_DISPATCH = core.dispatch
BASE_STATUS = core._status


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
    return BASE_DISPATCH(data)


core.dispatch = composed_dispatch
core._status = composed_status

if __name__ == "__main__":
    core.main()
