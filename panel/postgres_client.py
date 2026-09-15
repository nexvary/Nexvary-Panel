from __future__ import annotations

import json
import os
import socket
from pathlib import Path

POSTGRES_SOCK = Path(os.environ.get("NVP_POSTGRES_SOCK", "/run/nexvary-panel-postgres/postgres.sock"))
MAX_REQUEST = 16 * 1024
MAX_REPLY = 64 * 1024


def postgres_call(payload: dict, timeout: int = 45) -> dict:
    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) > MAX_REQUEST:
        return {"ok": False, "error": "postgres-request-too-large"}
    if not POSTGRES_SOCK.exists() or POSTGRES_SOCK.is_symlink():
        return {"ok": False, "error": "postgres-provider-offline"}
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(str(POSTGRES_SOCK))
        client.sendall(raw)
        response = b""
        while not response.endswith(b"\n") and len(response) <= MAX_REPLY:
            chunk = client.recv(8192)
            if not chunk:
                break
            response += chunk
    except (OSError, TimeoutError):
        return {"ok": False, "error": "postgres-provider-offline"}
    finally:
        client.close()
    if not response.endswith(b"\n") or len(response) > MAX_REPLY:
        return {"ok": False, "error": "postgres-provider-invalid-response"}
    try:
        body = json.loads(response.decode("utf-8"))
    except Exception:
        return {"ok": False, "error": "postgres-provider-invalid-response"}
    return body if isinstance(body, dict) else {"ok": False, "error": "postgres-provider-invalid-response"}
