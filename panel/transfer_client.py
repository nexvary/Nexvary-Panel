from __future__ import annotations

import json
import socket

from .config import TRANSFER_SOCK


def transfer_call(payload: dict, timeout: int = 35) -> dict:
    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
    data = b""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(TRANSFER_SOCK)
            sock.sendall(raw)
            while not data.endswith(b"\n") and len(data) < 1024 * 1024:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data += chunk
    except (OSError, TimeoutError):
        return {"ok": False, "error": "transfer-provider-unavailable"}
    try:
        result = json.loads(data.decode()) if data else {}
    except Exception:
        return {"ok": False, "error": "invalid-transfer-provider-response"}
    return result if isinstance(result, dict) else {"ok": False, "error": "invalid-transfer-provider-response"}
