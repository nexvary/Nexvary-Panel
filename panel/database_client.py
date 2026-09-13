from __future__ import annotations

import json
import os
import socket
from pathlib import Path

DATABASE_SOCK = Path(os.environ.get("NVP_DATABASE_SOCK", "/run/nexvary-panel/database.sock"))
MAX_REQUEST = 64 * 1024
MAX_REPLY = 128 * 1024


def database_call(payload: dict, timeout: int = 30) -> dict:
    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) > MAX_REQUEST:
        return {"ok": False, "error": "database-request-too-large"}
    if not DATABASE_SOCK.exists() or DATABASE_SOCK.is_symlink():
        return {"ok": False, "error": "database-provider-offline"}
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(str(DATABASE_SOCK))
        client.sendall(raw)
        response = b""
        while not response.endswith(b"\n") and len(response) <= MAX_REPLY:
            chunk = client.recv(8192)
            if not chunk:
                break
            response += chunk
    except (OSError, TimeoutError):
        return {"ok": False, "error": "database-provider-offline"}
    finally:
        client.close()
    if not response.endswith(b"\n") or len(response) > MAX_REPLY:
        return {"ok": False, "error": "database-provider-invalid-response"}
    try:
        body = json.loads(response.decode("utf-8"))
    except Exception:
        return {"ok": False, "error": "database-provider-invalid-response"}
    return body if isinstance(body, dict) else {"ok": False, "error": "database-provider-invalid-response"}
