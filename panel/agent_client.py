from __future__ import annotations

import json
import socket
from .config import AGENT_SOCK


def agent_call(payload: dict, timeout: int = 130) -> dict:
    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(AGENT_SOCK)
            sock.sendall(raw)
            data = b""
            while not data.endswith(b"\n") and len(data) < 1024 * 1024:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data += chunk
    except (OSError, TimeoutError) as exc:
        return {"ok": False, "error": f"agent unavailable: {exc}"}
    if not data:
        return {"ok": False, "error": "agent unavailable"}
    try:
        result = json.loads(data.decode())
        return result if isinstance(result, dict) else {"ok": False, "error": "invalid agent response"}
    except Exception:
        return {"ok": False, "error": "invalid agent response"}
