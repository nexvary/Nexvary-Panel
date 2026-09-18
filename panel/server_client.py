from __future__ import annotations

import json
import os
import socket

from .privileged_policy import operation_policy

SERVER_SOCK = os.environ.get("NVP_SERVER_SOCK", "/run/nexvary-panel/server.sock")
MAX_RESPONSE = 512 * 1024
MAX_REQUEST = 16 * 1024


def server_call(payload: dict, timeout: int | None = None) -> dict:
    """Call only a registered privileged operation using its bounded policy timeout.

    The browser/control plane cannot create new privileged action IDs.  Unknown
    operations fail closed before the Unix socket is opened, and callers cannot
    silently extend an operation beyond the timeout declared by policy.
    """
    if not isinstance(payload, dict):
        return {"ok": False, "error": "invalid server lifecycle request"}
    action = str(payload.get("action", "")).strip()
    try:
        policy = operation_policy(action)
    except KeyError:
        return {"ok": False, "error": "privileged operation not registered"}

    policy_timeout = int(policy.get("timeout", 30) or 30)
    if policy_timeout < 1:
        return {"ok": False, "error": "invalid privileged operation policy"}
    effective_timeout = policy_timeout if timeout is None else min(max(int(timeout), 1), policy_timeout)

    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
    if len(raw) > MAX_REQUEST:
        return {"ok": False, "error": "server request too large"}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(effective_timeout)
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
