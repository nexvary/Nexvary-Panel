#!/usr/bin/env python3
from __future__ import annotations

import grp
import json
import os
import socket
from pathlib import Path

from domain_ops import sync_domain_aliases
from webtools import site_metrics, sync_error_pages, sync_redirects

SOCK = Path(os.environ.get("NVP_WEBTOOLS_SOCK", "/run/nexvary-panel/webtools.sock"))
MAX_REQUEST = 1024 * 1024


def reply(conn: socket.socket, obj: dict) -> None:
    conn.sendall((json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8"))


def handle(req: dict) -> dict:
    action = req.get("action")
    if action == "redirect-sync":
        return sync_redirects(req.get("domain", ""), req.get("rules", []))
    if action == "error-page-sync":
        return sync_error_pages(req.get("domain", ""), req.get("pages", []))
    if action == "domain-alias-sync":
        return sync_domain_aliases(req.get("domain", ""), req.get("aliases", []))
    if action == "site-metrics":
        try:
            return site_metrics(req.get("domain", ""))
        except (ValueError, OSError):
            return {"ok": False, "error": "metrics request failed"}
    return {"ok": False, "error": "action not allowed"}


def main() -> None:
    SOCK.parent.mkdir(parents=True, exist_ok=True)
    if SOCK.exists() or SOCK.is_symlink():
        SOCK.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(SOCK))
    gid = grp.getgrnam("nexvary-panel").gr_gid
    os.chown(SOCK, 0, gid)
    os.chmod(SOCK, 0o660)
    server.listen(32)
    while True:
        conn, _ = server.accept()
        with conn:
            try:
                data = b""
                while not data.endswith(b"\n") and len(data) < MAX_REQUEST:
                    chunk = conn.recv(8192)
                    if not chunk:
                        break
                    data += chunk
                if len(data) >= MAX_REQUEST:
                    raise ValueError("request too large")
                req = json.loads(data.decode("utf-8"))
                if not isinstance(req, dict):
                    raise ValueError("object required")
                reply(conn, handle(req))
            except Exception:
                reply(conn, {"ok": False, "error": "bad request"})


if __name__ == "__main__":
    main()
