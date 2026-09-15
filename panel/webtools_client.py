from __future__ import annotations

import json
import socket

from .config import WEBTOOLS_SOCK

MAX_RESPONSE = 2 * 1024 * 1024


def webtools_call(payload: dict, timeout: int = 45) -> dict:
    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) >= 1024 * 1024:
        return {"ok": False, "error": "webtools request too large"}
    data = b""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(WEBTOOLS_SOCK)
            sock.sendall(raw)
            while not data.endswith(b"\n") and len(data) < MAX_RESPONSE:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data += chunk
    except (OSError, TimeoutError):
        return {"ok": False, "error": "webtools agent unavailable"}
    if not data or len(data) >= MAX_RESPONSE:
        return {"ok": False, "error": "invalid webtools agent response"}
    try:
        result = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"ok": False, "error": "invalid webtools agent response"}
    return result if isinstance(result, dict) else {"ok": False, "error": "invalid webtools agent response"}
