from __future__ import annotations

import json
import socket

from .config import MAIL_SOCK


def mail_call(payload: dict, timeout: int = 30) -> dict:
    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
    data = b""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(MAIL_SOCK)
            sock.sendall(raw)
            while not data.endswith(b"\n") and len(data) < 1024 * 1024:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data += chunk
    except (OSError, TimeoutError):
        return {"ok": False, "error": "mail-provider-unavailable"}
    try:
        result = json.loads(data.decode()) if data else {}
    except Exception:
        result = {}
    if not isinstance(result, dict):
        return {"ok": False, "error": "invalid-mail-provider-response"}
    return result
