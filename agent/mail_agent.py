#!/usr/bin/env python3
from __future__ import annotations

import grp
import json
import os
import re
import socket
import stat
import subprocess
from pathlib import Path

import mail_backend as _backend


def _validated_mail_reload() -> None:
    """Validate only what this provider mutates before reloading services."""
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
from mail_default import default_address_sync
from mail_sieve import sieve_sync

SOCKET_PATH = Path(os.environ.get("NVP_MAIL_SOCK", "/run/nexvary-panel/mail.sock"))
MAX_REQUEST = 64 * 1024
MAX_LOG_READ = 4 * 1024 * 1024
MAX_TRACE_LINES = 6000
MAX_TRACE_EVENTS = 200
MAIL_LOG = Path(os.environ.get("NVP_MAIL_LOG", "/var/log/mail.log"))
ACTIONS = {
    "status", "mailbox-upsert", "mailbox-delete", "forwarder-upsert", "forwarder-delete",
    "default-address-sync", "routing-sync", "queue-delete", "sieve-sync", "delivery-trace",
}
SAFE_ERROR_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,79}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
EMAIL_RE = re.compile(r"<?([A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253})>?")
QUEUE_RE = re.compile(r"postfix/(?P<component>[A-Za-z0-9_-]+)\[\d+\]:\s+(?P<queue>[A-Z0-9]{5,32}):")
FROM_RE = re.compile(r"\bfrom=<([^<>\r\n]{0,320})>")
TO_RE = re.compile(r"\bto=<([^<>\r\n]{0,320})>")
STATUS_RE = re.compile(r"\bstatus=([a-zA-Z0-9_-]{1,32})")
DSN_RE = re.compile(r"\bdsn=([0-9.]{1,24})")
RELAY_RE = re.compile(r"\brelay=([^,\s]{1,180})")
DETAIL_RE = re.compile(r"\bstatus=[a-zA-Z0-9_-]+\s*\(([^\r\n]{0,240})\)")
BASE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


def _valid_trace_domain(value: object) -> str:
    domain = str(value or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("invalid-mail-domain")
    return domain


def _routing_sync(domain: object, mode: object) -> dict:
    domain = _valid_trace_domain(domain)
    mode = str(mode or "").strip().lower()
    if mode not in {"local", "remote"}:
        raise ValueError("invalid-mail-routing-mode")

    snapshot = _backend._snapshot()
    state = {name: dict(values) for name, values in snapshot.items()}
    suffix = f"@{domain}"
    if mode == "remote":
        has_mailboxes = any(str(key).lower().endswith(suffix) for key in state["boxes"])
        has_users = any(str(key).lower().endswith(suffix) for key in state["users"])
        has_aliases = any(
            str(key).lower() == suffix or str(key).lower().endswith(suffix)
            for key in state["aliases"]
        )
        if has_mailboxes or has_users or has_aliases:
            raise RuntimeError("routing-conflict-local-resources")
        state["domains"].pop(domain, None)
    else:
        state["domains"][domain] = "OK"

    try:
        _backend._write_state(state)
        _backend._reload()
    except Exception:
        _backend._rollback(snapshot)
        raise
    return {"ok": True, "domain": domain, "mode": mode}


def _regular_log(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError("mail-log-unsafe")
    return True


def _mail_log_lines() -> tuple[str, list[str]]:
    if _regular_log(MAIL_LOG):
        try:
            size = MAIL_LOG.stat().st_size
            with MAIL_LOG.open("rb") as handle:
                if size > MAX_LOG_READ:
                    handle.seek(size - MAX_LOG_READ)
                    handle.readline()
                raw = handle.read(MAX_LOG_READ)
            return "mail.log", raw.decode("utf-8", errors="replace").splitlines()[-MAX_TRACE_LINES:]
        except OSError as exc:
            raise RuntimeError("mail-log-unavailable") from exc
    try:
        proc = subprocess.run(
            ["journalctl", "--no-pager", "-u", "postfix", "-n", str(MAX_TRACE_LINES), "-o", "short-iso"],
            capture_output=True, text=True, timeout=10, check=False, env=BASE_ENV,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("mail-log-unavailable") from exc
    if proc.returncode != 0:
        raise RuntimeError("mail-log-unavailable")
    return "journalctl", proc.stdout.splitlines()[-MAX_TRACE_LINES:]


def _address_domain(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().lower().rstrip(".")


def _clean(value: str, limit: int) -> str:
    return "".join(ch for ch in value if ch >= " " and ch != "\x7f")[:limit]


def _delivery_trace(domain: object, limit: object = 100) -> dict:
    domain = _valid_trace_domain(domain)
    try:
        requested = int(limit)
    except (TypeError, ValueError):
        requested = 100
    requested = min(MAX_TRACE_EVENTS, max(1, requested))
    source, lines = _mail_log_lines()

    relevant_ids: set[str] = set()
    for line in lines:
        match = QUEUE_RE.search(line)
        if not match:
            continue
        addresses = [item.lower() for item in EMAIL_RE.findall(line)]
        if any(_address_domain(address) == domain for address in addresses):
            relevant_ids.add(match.group("queue"))

    events: list[dict] = []
    for line in reversed(lines):
        match = QUEUE_RE.search(line)
        if not match or match.group("queue") not in relevant_ids:
            continue
        sender_match = FROM_RE.search(line)
        recipient_match = TO_RE.search(line)
        status_match = STATUS_RE.search(line)
        dsn_match = DSN_RE.search(line)
        relay_match = RELAY_RE.search(line)
        detail_match = DETAIL_RE.search(line)
        sender = _clean(sender_match.group(1), 320) if sender_match else ""
        recipient = _clean(recipient_match.group(1), 320) if recipient_match else ""
        # Return only structured delivery lifecycle data. Never expose a raw log line.
        events.append({
            "queue_id": match.group("queue"),
            "component": match.group("component")[:32],
            "timestamp": _clean(line[:32], 32),
            "sender": sender,
            "recipient": recipient,
            "status": status_match.group(1).lower() if status_match else "",
            "dsn": dsn_match.group(1) if dsn_match else "",
            "relay": _clean(relay_match.group(1), 180) if relay_match else "",
            "detail": _clean(detail_match.group(1), 220) if detail_match else "",
        })
        if len(events) >= requested:
            break
    return {"ok": True, "domain": domain, "source": source, "count": len(events), "events": events}


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
    if action == "default-address-sync":
        return default_address_sync(data.get("domain", ""), data.get("mode", "reject"), data.get("destination", ""))
    if action == "routing-sync":
        return _routing_sync(data.get("domain", ""), data.get("mode", "local"))
    if action == "queue-delete":
        return queue_delete(str(data.get("queue_id", "")))
    if action == "delivery-trace":
        return _delivery_trace(data.get("domain", ""), data.get("limit", 100))
    return sieve_sync(
        str(data.get("address", "")),
        data.get("autoresponder", {}),
        data.get("filters", []),
        data.get("spam", {}),
        data.get("global_filters", []),
        data.get("global_domains", []),
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
