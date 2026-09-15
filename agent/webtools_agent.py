#!/usr/bin/env python3
from __future__ import annotations

import grp
import json
import os
import socket
from pathlib import Path

from domain_ops import sync_domain_aliases
from resource_usage import site_resource_usage
from site_controls import raw_access, sync_directory_privacy, sync_hotlink, sync_indexing, sync_mime_overrides
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
    if action == "site-resource-usage":
        try:
            return site_resource_usage(req.get("domain", ""))
        except (ValueError, OSError):
            return {"ok": False, "error": "resource usage request failed"}
    if action == "site-control-privacy":
        return sync_directory_privacy(
            req.get("domain", ""),
            enabled=bool(req.get("enabled")),
            path=req.get("path", "/"),
            username=req.get("username"),
            password=req.get("password"),
        )
    if action == "site-control-hotlink":
        return sync_hotlink(req.get("domain", ""), enabled=bool(req.get("enabled")), extensions=req.get("extensions", []))
    if action == "site-control-indexing":
        return sync_indexing(req.get("domain", ""), mode=req.get("mode", "off"))
    if action == "site-control-mime":
        return sync_mime_overrides(req.get("domain", ""), mappings=req.get("mappings", {}))
    if action == "site-control-raw-access":
        return raw_access(req.get("domain", ""), lines=req.get("lines", 200))
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
