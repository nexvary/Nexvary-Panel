from __future__ import annotations

import json
import os
import socket
from pathlib import Path

WORDPRESS_SOCK = Path(os.environ.get("NVP_WORDPRESS_SOCK", "/run/nexvary-panel/wordpress.sock"))
MAX_REQUEST = 64 * 1024
MAX_REPLY = 512 * 1024


def wordpress_call(payload: dict, timeout: int = 45) -> dict:
    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) > MAX_REQUEST:
        return {"ok": False, "error": "wordpress-request-too-large"}
    if not WORDPRESS_SOCK.exists() or WORDPRESS_SOCK.is_symlink():
        return {"ok": False, "error": "wordpress-provider-offline"}
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(str(WORDPRESS_SOCK))
        client.sendall(raw)
        response = b""
        while not response.endswith(b"\n") and len(response) <= MAX_REPLY:
            chunk = client.recv(8192)
            if not chunk:
                break
            response += chunk
    except (OSError, TimeoutError):
        return {"ok": False, "error": "wordpress-provider-offline"}
    finally:
        client.close()
    if not response.endswith(b"\n") or len(response) > MAX_REPLY:
        return {"ok": False, "error": "wordpress-provider-invalid-response"}
    try:
        body = json.loads(response.decode("utf-8"))
    except Exception:
        return {"ok": False, "error": "wordpress-provider-invalid-response"}
    return body if isinstance(body, dict) else {"ok": False, "error": "wordpress-provider-invalid-response"}
