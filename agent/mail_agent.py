#!/usr/bin/env python3
from __future__ import annotations

import grp
import json
import os
import re
import socket
import subprocess
from pathlib import Path

import mail_backend as _backend


def _validated_mail_reload() -> None:
    """Validate only what this provider mutates before reloading services.

    Mailbox/forwarder operations change Nexvary-managed lookup maps, not Postfix
    main.cf/master.cf. postmap validates/builds those maps; postconf -n parses the
    active Postfix configuration without the writable-system-tree requirements
    of `postfix check`, preserving the hardened service boundary.
    """
    for path in (_backend.DOMAINS_FILE, _backend.VMAILBOX_FILE, _backend.VIRTUAL_FILE):
        _backend._postmap(path)
    check = subprocess.run(
        ["postconf", "-n"], capture_output=True, text=True, timeout=20, check=False,
        env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    if check.returncode != 0:
        raise RuntimeError("postfix-validation-failed")
    dove = subprocess.run(
        ["dovecot", "-n"], capture_output=True, text=True, timeout=20, check=False,
        env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    if dove.returncode != 0:
        raise RuntimeError("dovecot-validation-failed")
    for svc in ("postfix", "dovecot"):
        proc = subprocess.run(
            ["systemctl", "reload", svc], capture_output=True, text=True, timeout=20, check=False,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        )
        if proc.returncode != 0:
            raise RuntimeError("mail-service-reload-failed")


_backend._reload = _validated_mail_reload

from mail_backend import forwarder_delete, forwarder_upsert, mailbox_delete, mailbox_upsert, provider_status, queue_delete
from mail_sieve import sieve_sync

SOCKET_PATH = Path(os.environ.get("NVP_MAIL_SOCK", "/run/nexvary-panel/mail.sock"))
MAX_REQUEST = 64 * 1024
ACTIONS = {"status", "mailbox-upsert", "mailbox-delete", "forwarder-upsert", "forwarder-delete", "queue-delete", "sieve-sync"}
SAFE_ERROR_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,79}$")


def _dispatch(data: dict) -> dict:
    action = str(data.get("action", ""))
    if action not in ACTIONS:
        return {"ok": False, "error": "mail-action-not-allowed"}
    if action == "status":
        return provider_status()
    if action == "mailbox-upsert":
        return mailbox_upsert(str(data.get("address", "")), str(data.get("password", "")))
    if action == "mailbox-delete":
        return mailbox_delete(str(data.get("address", "")))
    if action == "forwarder-upsert":
        return forwarder_upsert(str(data.get("source", "")), str(data.get("destination", "")))
    if action == "forwarder-delete":
        return forwarder_delete(str(data.get("source", "")))
    if action == "queue-delete":
        return queue_delete(str(data.get("queue_id", "")))
    return sieve_sync(
        str(data.get("address", "")),
        data.get("autoresponder", {}),
        data.get("filters", []),
        data.get("spam", {}),
    )


def _safe_error(exc: Exception) -> str:
    code = str(exc).strip().lower()
    return code if SAFE_ERROR_RE.fullmatch(code) else "mail-provider-operation-failed"


def _serve_client(conn: socket.socket) -> None:
    data = b""
    while not data.endswith(b"\n") and len(data) <= MAX_REQUEST:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    if len(data) > MAX_REQUEST:
        result = {"ok": False, "error": "mail-request-too-large"}
    else:
        try:
            payload = json.loads(data.decode("utf-8")) if data else {}
            if not isinstance(payload, dict):
                raise ValueError("invalid-mail-request")
            result = _dispatch(payload)
        except (ValueError, RuntimeError) as exc:
            result = {"ok": False, "error": _safe_error(exc)}
        except Exception:
            result = {"ok": False, "error": "mail-provider-operation-failed"}
    conn.sendall((json.dumps(result, separators=(",", ":")) + "\n").encode("utf-8"))


def main() -> None:
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if SOCKET_PATH.exists() or SOCKET_PATH.is_symlink():
        SOCKET_PATH.unlink()
    old_umask = os.umask(0o117)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(SOCKET_PATH))
    finally:
        os.umask(old_umask)
    group = grp.getgrnam("nexvary-panel").gr_gid
    os.chown(SOCKET_PATH, 0, group)
    os.chmod(SOCKET_PATH, 0o660)
    server.listen(32)
    try:
        while True:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(40)
                _serve_client(conn)
    finally:
        server.close()
        try:
            SOCKET_PATH.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()
