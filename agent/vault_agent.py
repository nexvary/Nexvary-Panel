#!/usr/bin/env python3
from __future__ import annotations

import grp
import json
import os
import socket
from pathlib import Path

from secret_vault import SecretVault

SOCK = Path(os.environ.get("NVP_VAULT_SOCK", "/run/nexvary-panel/vault.sock"))
MAX_REQUEST_BYTES = 24 * 1024
VAULT = SecretVault(Path(os.environ.get("NVP_VAULT_DIR", "/etc/nexvary-panel/credentials")))


def _reply(conn: socket.socket, payload: dict) -> None:
    conn.sendall((json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8"))


def handle(req: dict) -> dict:
    action = req.get("action")
    try:
        if action == "metadata":
            return {"ok": True, "entries": VAULT.list_metadata()}
        if action == "put":
            meta = VAULT.put(req.get("id", ""), req.get("kind", ""), req.get("value", ""))
            return {"ok": True, "entry": meta}
        if action == "delete":
            deleted = VAULT.delete(req.get("id", ""), req.get("kind", ""))
            return {"ok": True, "deleted": deleted}
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": False, "error": "action not allowed"}


def main() -> None:
    VAULT.ensure()
    SOCK.parent.mkdir(parents=True, exist_ok=True)
    if SOCK.exists() or SOCK.is_symlink():
        SOCK.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(SOCK))
    gid = grp.getgrnam("nexvary-panel").gr_gid
    os.chown(SOCK, 0, gid)
    os.chmod(SOCK, 0o660)
    server.listen(16)
    while True:
        conn, _ = server.accept()
        with conn:
            try:
                data = b""
                while not data.endswith(b"\n") and len(data) <= MAX_REQUEST_BYTES:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                if not data.endswith(b"\n") or len(data) > MAX_REQUEST_BYTES:
                    raise ValueError("request too large or incomplete")
                req = json.loads(data.decode("utf-8"))
                if not isinstance(req, dict):
                    raise ValueError("object required")
                _reply(conn, handle(req))
            except Exception:
                _reply(conn, {"ok": False, "error": "bad request"})


if __name__ == "__main__":
    main()
