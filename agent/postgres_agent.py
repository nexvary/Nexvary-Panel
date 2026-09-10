#!/usr/bin/env python3
from __future__ import annotations

import grp
import json
import os
import re
import shutil
import socket
import subprocess
from pathlib import Path

SOCK = Path(os.environ.get("NVP_POSTGRES_SOCK", "/run/nexvary-panel-postgres/postgres.sock"))
MAX_REQUEST = 16 * 1024
DB_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9_@%+=:.,!$#?-]{14,128}$")
ACTIONS = {"status", "create", "delete"}
ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "HOME": "/var/lib/postgresql",
    "PGHOST": "/var/run/postgresql",
    "PGUSER": "postgres",
}


def _run(args: list[str], timeout: int = 30, stdin: str | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(args, capture_output=True, text=True, input=stdin, timeout=timeout, env=ENV, check=False)
    if proc.returncode != 0:
        command = Path(args[0]).name[:48]
        detail = "" if stdin is not None else (proc.stderr or proc.stdout or "").strip().replace("\n", " ")[-160:]
        suffix = f":{detail}" if detail else ""
        raise RuntimeError(f"postgres-command-failed:{command}:{proc.returncode}{suffix}")
    return proc


def _name(value: object) -> str:
    value = str(value or "").strip()
    if not DB_RE.fullmatch(value):
        raise ValueError("invalid-postgres-identifier")
    return value


def _available() -> bool:
    return all(shutil.which(x) for x in ("psql", "createuser", "createdb", "dropuser", "dropdb"))


def _exists(kind: str, value: str) -> bool:
    if kind == "role":
        query = f"SELECT 1 FROM pg_roles WHERE rolname='{value}'"
    elif kind == "database":
        query = f"SELECT 1 FROM pg_database WHERE datname='{value}'"
    else:
        raise ValueError("invalid-postgres-object")
    return _run(["psql", "-X", "-tAc", query, "-d", "postgres"], 15).stdout.strip() == "1"


def _create(data: dict) -> dict:
    name = _name(data.get("db_name"))
    user = _name(data.get("db_user"))
    password = str(data.get("password", ""))
    if not PASSWORD_RE.fullmatch(password):
        raise ValueError("invalid-database-password")
    if not _available():
        return {"ok": False, "error": "postgresql-not-installed"}
    if _exists("role", user) or _exists("database", name):
        return {"ok": False, "error": "postgres-resource-conflict"}
    role_created = False
    db_created = False
    try:
        _run(["createuser", "--no-password", "--login", "--", user], 30)
        role_created = True
        _run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", "postgres"], 30,
             f"ALTER ROLE \"{user}\" WITH LOGIN PASSWORD '{password}';\n")
        _run(["createdb", "-O", user, "--", name], 30)
        db_created = True
    except Exception:
        if db_created:
            try:
                _run(["dropdb", "--if-exists", "--", name], 20)
            except Exception:
                pass
        if role_created:
            try:
                _run(["dropuser", "--if-exists", "--", user], 20)
            except Exception:
                pass
        raise
    return {"ok": True, "db_name": name, "db_user": user}


def _delete(data: dict) -> dict:
    name = _name(data.get("db_name"))
    user = _name(data.get("db_user"))
    if not _available():
        return {"ok": False, "error": "postgresql-not-installed"}
    _run(["dropdb", "--if-exists", "--", name], 30)
    _run(["dropuser", "--if-exists", "--", user], 30)
    return {"ok": True, "deleted": True}


def _dispatch(data: dict) -> dict:
    action = str(data.get("action", ""))
    if action not in ACTIONS:
        return {"ok": False, "error": "postgres-action-not-allowed"}
    if action == "status":
        return {"ok": True, "engine": "postgresql", "available": _available()}
    if action == "create":
        return _create(data)
    return _delete(data)


def _serve(conn: socket.socket) -> None:
    raw = b""
    while not raw.endswith(b"\n") and len(raw) <= MAX_REQUEST:
        chunk = conn.recv(4096)
        if not chunk:
            break
        raw += chunk
    try:
        if not raw.endswith(b"\n") or len(raw) > MAX_REQUEST:
            raise ValueError("postgres-request-too-large")
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("postgres-object-required")
        result = _dispatch(data)
    except ValueError as exc:
        result = {"ok": False, "error": str(exc)[:120]}
    except RuntimeError as exc:
        result = {"ok": False, "error": str(exc)[:160]}
    except Exception:
        result = {"ok": False, "error": "postgres-provider-operation-failed"}
    conn.sendall((json.dumps(result, separators=(",", ":")) + "\n").encode("utf-8"))


def main() -> None:
    SOCK.parent.mkdir(parents=True, exist_ok=True)
    if SOCK.exists() or SOCK.is_symlink():
        SOCK.unlink()
    old_umask = os.umask(0o117)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(SOCK))
    finally:
        os.umask(old_umask)
    os.chown(SOCK, os.getuid(), grp.getgrnam("nexvary-panel").gr_gid)
    os.chmod(SOCK, 0o660)
    server.listen(16)
    try:
        while True:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(45)
                _serve(conn)
    finally:
        server.close()
        SOCK.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
