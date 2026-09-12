from __future__ import annotations

import json
import os
import socket

VAULT_SOCK = os.environ.get("NVP_VAULT_SOCK", "/run/nexvary-panel/vault.sock")
MAX_RESPONSE_BYTES = 256 * 1024


def vault_call(payload: dict, timeout: int = 8) -> dict:
    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) > 24 * 1024:
        return {"ok": False, "error": "vault request too large"}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(VAULT_SOCK)
            sock.sendall(raw)
            data = b""
            while not data.endswith(b"\n") and len(data) <= MAX_RESPONSE_BYTES:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data += chunk
    except (OSError, TimeoutError) as exc:
        return {"ok": False, "error": f"vault unavailable: {exc}"}
    if not data or len(data) > MAX_RESPONSE_BYTES:
        return {"ok": False, "error": "invalid vault response"}
    try:
        result = json.loads(data.decode("utf-8"))
        return result if isinstance(result, dict) else {"ok": False, "error": "invalid vault response"}
    except Exception:
        return {"ok": False, "error": "invalid vault response"}
