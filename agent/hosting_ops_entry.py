#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import socket
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


def composed_status() -> dict:
    body = BASE_STATUS()
    pg = postgres_call({"action": "status"}, timeout=8)
    body.setdefault("capabilities", {})["postgres"] = bool(pg.get("ok") and pg.get("available"))
    return body


def composed_dispatch(data: dict) -> dict:
    action = str(data.get("action", ""))
    if action == "status":
        return composed_status()
    if action == "postgres-create":
        return postgres_call({"action": "create", "db_name": data.get("db_name", ""), "db_user": data.get("db_user", ""), "password": data.get("password", "")})
    if action == "postgres-delete":
        return postgres_call({"action": "delete", "db_name": data.get("db_name", ""), "db_user": data.get("db_user", "")})
    return BASE_DISPATCH(data)


core.dispatch = composed_dispatch
core._status = composed_status

if __name__ == "__main__":
    core.main()
