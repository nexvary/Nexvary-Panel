from __future__ import annotations

import json
import os
import socket

PROVIDER_SOCK = os.environ.get("NVP_PROVIDER_SOCK", "/run/nexvary-panel/provider.sock")
MAX_RESPONSE_BYTES = 256 * 1024


def provider_call(payload: dict, timeout: int = 1810) -> dict:
    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) > 32 * 1024:
        return {"ok": False, "error": "provider request too large"}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(PROVIDER_SOCK)
            sock.sendall(raw)
            data = b""
            while not data.endswith(b"\n") and len(data) <= MAX_RESPONSE_BYTES:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data += chunk
    except (OSError, TimeoutError) as exc:
        return {"ok": False, "error": f"provider agent unavailable: {exc}"}
    if not data or len(data) > MAX_RESPONSE_BYTES:
        return {"ok": False, "error": "invalid provider response"}
    try:
        result = json.loads(data.decode("utf-8"))
        return result if isinstance(result, dict) else {"ok": False, "error": "invalid provider response"}
    except Exception:
        return {"ok": False, "error": "invalid provider response"}
