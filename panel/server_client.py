from __future__ import annotations

import json
import os
import socket

SERVER_SOCK = os.environ.get("NVP_SERVER_SOCK", "/run/nexvary-panel/server.sock")
MAX_RESPONSE = 512 * 1024


def server_call(payload: dict, timeout: int = 30) -> dict:
    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
    if len(raw) > 16 * 1024:
        return {"ok": False, "error": "server request too large"}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(SERVER_SOCK)
            sock.sendall(raw)
            data = b""
            while not data.endswith(b"\n") and len(data) <= MAX_RESPONSE:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data += chunk
    except (OSError, TimeoutError):
        return {"ok": False, "error": "server lifecycle provider unavailable"}
    if not data or len(data) > MAX_RESPONSE:
        return {"ok": False, "error": "invalid server lifecycle response"}
    try:
        body = json.loads(data.decode("utf-8"))
    except Exception:
        return {"ok": False, "error": "invalid server lifecycle response"}
    return body if isinstance(body, dict) else {"ok": False, "error": "invalid server lifecycle response"}
