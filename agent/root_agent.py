#!/usr/bin/env python3
from __future__ import annotations

import grp
import json
import os
import re
import socket
import subprocess
from pathlib import Path

SOCK = Path(os.environ.get("NVP_AGENT_SOCK", "/run/nexvary-panel/agent.sock"))
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
TARGET_RE = re.compile(r"^https?://[A-Za-z0-9.\-:\[\]]+(?:/.*)?$")
DB_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9_@%+=:.,!$#?-]{14,128}$")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
ALLOWED_SERVICES = {"nginx", "mariadb", "fail2ban", "docker"}


def reply(conn, obj):
    conn.sendall((json.dumps(obj, separators=(",", ":")) + "\n").encode())


def valid_domain(value):
    return isinstance(value, str) and bool(DOMAIN_RE.match(value))


def run(args, timeout=120, stdin=None):
    proc = subprocess.run(args, capture_output=True, text=True, input=stdin, timeout=timeout,
        env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
    if proc.returncode:
        return {"ok": False, "error": (proc.stderr or proc.stdout or "operation failed")[-4000:]}
    return {"ok": True, "output": (proc.stdout or "")[-12000:]}


def handle(req):
    action = req.get("action")
    if action == "site-create":
        domain, kind, target, port = req.get("domain", ""), req.get("kind", ""), req.get("target", ""), req.get("app_port")
        if not valid_domain(domain) or kind not in {"static", "php", "node", "python", "reverse"}:
            return {"ok": False, "error": "invalid arguments"}
        args = ["/usr/local/sbin/nvpctl", "site-create", domain, kind]
        if kind == "reverse":
            if not isinstance(target, str) or not TARGET_RE.match(target):
                return {"ok": False, "error": "invalid reverse target"}
            args.append(target)
        elif kind in {"node", "python"}:
            if not isinstance(port, int) or not 1024 <= port <= 65535:
                return {"ok": False, "error": "invalid application port"}
            args.append(str(port))
        return run(args, timeout=45)
    if action == "site-toggle":
        domain, desired = req.get("domain", ""), req.get("desired", "")
        if not valid_domain(domain) or desired not in {"enable", "disable"}:
            return {"ok": False, "error": "invalid arguments"}
        return run(["/usr/local/sbin/nvpctl", "site-toggle", domain, desired], timeout=25)
    if action == "ssl":
        domain, email = req.get("domain", ""), req.get("email", "")
        if not valid_domain(domain) or not isinstance(email, str) or not EMAIL_RE.match(email):
            return {"ok": False, "error": "invalid arguments"}
        return run(["/usr/local/sbin/nvpctl", "ssl", domain, email], timeout=140)
    if action == "db-create":
        db_name, db_user, password = req.get("db_name", ""), req.get("db_user", ""), req.get("password", "")
        if not isinstance(db_name, str) or not DB_RE.match(db_name) or not isinstance(db_user, str) or not DB_RE.match(db_user):
            return {"ok": False, "error": "invalid database identifiers"}
        if not isinstance(password, str) or not PASSWORD_RE.match(password):
            return {"ok": False, "error": "invalid database password"}
        return run(["/usr/local/sbin/nvpctl", "db-create", db_name, db_user], timeout=30, stdin=password + "\n")
    if action == "backup-site":
        domain, db_name = req.get("domain", ""), req.get("db_name", "")
        if not valid_domain(domain) or (db_name and (not isinstance(db_name, str) or not DB_RE.match(db_name))):
            return {"ok": False, "error": "invalid backup request"}
        args = ["/usr/local/sbin/nvpctl", "backup-site", domain] + ([db_name] if db_name else [])
        result = run(args, timeout=130)
        if result.get("ok"):
            try:
                result["meta"] = json.loads(result.get("output", "{}").strip().splitlines()[-1])
            except Exception:
                pass
        return result
    if action == "site-logs":
        domain = req.get("domain", "")
        return run(["/usr/local/sbin/nvpctl", "site-logs", domain], timeout=20) if valid_domain(domain) else {"ok": False, "error": "invalid domain"}
    if action == "service-restart":
        name = req.get("name", "")
        return run(["/usr/local/sbin/nvpctl", "service-restart", name], timeout=40) if name in ALLOWED_SERVICES else {"ok": False, "error": "service not allowed"}
    if action == "doctor":
        result = run(["/usr/local/sbin/nvpctl", "doctor"], timeout=50)
        if result.get("ok"):
            try:
                result["checks"] = json.loads(result.get("output", "{}"))
            except Exception:
                return {"ok": False, "error": "doctor returned invalid data"}
        return result
    if action == "docker-list":
        result = run(["/usr/local/sbin/nvpctl", "docker-list"], timeout=20)
        if result.get("ok"):
            rows = []
            for line in result.get("output", "").splitlines():
                parts = line.split("\t", 4)
                if len(parts) == 5:
                    rows.append(dict(id=parts[0], name=parts[1], image=parts[2], status=parts[3], ports=parts[4]))
            result["containers"] = rows
        return result
    if action == "docker-control":
        container, desired = req.get("container", ""), req.get("desired", "")
        if not isinstance(container, str) or not CONTAINER_RE.match(container) or desired not in {"start", "stop", "restart"}:
            return {"ok": False, "error": "invalid docker request"}
        return run(["/usr/local/sbin/nvpctl", "docker-control", container, desired], timeout=40)
    return {"ok": False, "error": "action not allowed"}


def main():
    SOCK.parent.mkdir(parents=True, exist_ok=True)
    if SOCK.exists():
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
                while not data.endswith(b"\n") and len(data) < 1024 * 1024:
                    chunk = conn.recv(8192)
                    if not chunk:
                        break
                    data += chunk
                req = json.loads(data.decode())
                if not isinstance(req, dict):
                    raise ValueError("object required")
                reply(conn, handle(req))
            except Exception:
                reply(conn, {"ok": False, "error": "bad request"})

if __name__ == "__main__":
    main()
