from __future__ import annotations

import json
import os
import socket

PHPINI_SOCK = os.environ.get("NVP_PHPINI_SOCK", "/run/nexvary-panel/phpini.sock")
MAX_RESPONSE = 128 * 1024


def php_ini_call(payload: dict, timeout: int = 15) -> dict:
    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) > 32 * 1024:
        return {"ok": False, "error": "php ini request too large"}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(PHPINI_SOCK)
            sock.sendall(raw)
            data = b""
            while not data.endswith(b"\n") and len(data) <= MAX_RESPONSE:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
    except (OSError, TimeoutError):
        return {"ok": False, "error": "php ini provider unavailable"}
    if not data or len(data) > MAX_RESPONSE:
        return {"ok": False, "error": "invalid php ini provider response"}
    try:
        body = json.loads(data.decode("utf-8"))
    except Exception:
        return {"ok": False, "error": "invalid php ini provider response"}
    return body if isinstance(body, dict) else {"ok": False, "error": "invalid php ini provider response"}
