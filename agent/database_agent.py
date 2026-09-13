#!/usr/bin/env python3
from __future__ import annotations

import grp
import json
import os
import re
import socket
import subprocess
from pathlib import Path

SOCK = Path(os.environ.get("NVP_DATABASE_SOCK", "/run/nexvary-panel/database.sock"))
MAX_REQUEST = 64 * 1024
MAX_REPLY = 128 * 1024
DB_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9_@%+=:.,!$#?-]{14,128}$")
ALLOWED_PRIVILEGES = {
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "CREATE",
    "DROP",
    "INDEX",
    "ALTER",
    "REFERENCES",
    "CREATE TEMPORARY TABLES",
    "LOCK TABLES",
    "EXECUTE",
    "CREATE VIEW",
    "SHOW VIEW",
    "TRIGGER",
}


def _run(sql: str, timeout: int = 25) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["mariadb", "--protocol=socket", "--batch", "--skip-column-names"],
            input=sql,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError):
        return False, "database-control-failed"
    if proc.returncode:
        return False, "database-control-rejected"
    return True, (proc.stdout or "")[-MAX_REPLY:]


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not DB_RE.fullmatch(value):
        raise ValueError("invalid-database-identifier")
    return value


def _password(value: object) -> str:
    if not isinstance(value, str) or not PASSWORD_RE.fullmatch(value):
        raise ValueError("invalid-database-password")
    return value


def _privileges(value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > len(ALLOWED_PRIVILEGES):
        raise ValueError("invalid-database-privileges")
    out: list[str] = []
    for item in value:
        name = str(item).strip().upper()
        if name not in ALLOWED_PRIVILEGES:
            raise ValueError("invalid-database-privileges")
        if name not in out:
            out.append(name)
    return out


def _exists(kind: str, name: str) -> bool:
    if kind == "database":
        ok, out = _run(f"SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='{name}';")
    else:
        ok, out = _run(f"SELECT COUNT(*) FROM mysql.user WHERE User='{name}' AND Host='localhost';")
    return ok and out.strip().splitlines()[-1:] == ["1"]


def status() -> dict:
    ok, out = _run("SELECT VERSION();")
    return {"ok": ok, "engine": "mariadb", "version": out.strip().splitlines()[-1] if ok and out.strip() else ""}


def user_create(data: dict) -> dict:
    username = _identifier(data.get("username"))
    password = _password(data.get("password"))
    if _exists("user", username):
        return {"ok": False, "error": "database-user-already-exists"}
    ok, _ = _run(f"CREATE USER '{username}'@'localhost' IDENTIFIED BY '{password}';")
    return {"ok": ok, "error": "" if ok else "database-user-create-failed"}


def user_rotate(data: dict) -> dict:
    username = _identifier(data.get("username"))
    password = _password(data.get("password"))
    if not _exists("user", username):
        return {"ok": False, "error": "database-user-not-found"}
    ok, _ = _run(f"ALTER USER '{username}'@'localhost' IDENTIFIED BY '{password}';")
    return {"ok": ok, "error": "" if ok else "database-user-password-rotate-failed"}


def grant_replace(data: dict) -> dict:
    db_name = _identifier(data.get("db_name"))
    username = _identifier(data.get("username"))
    privileges = _privileges(data.get("privileges"))
    previous = _privileges(data.get("previous_privileges", []))
    if not _exists("database", db_name):
        return {"ok": False, "error": "database-not-found"}
    if not _exists("user", username):
        return {"ok": False, "error": "database-user-not-found"}

    revoke = f"REVOKE ALL PRIVILEGES ON `{db_name}`.* FROM '{username}'@'localhost';"
    ok, _ = _run(revoke)
    if not ok:
        return {"ok": False, "error": "database-grant-revoke-failed"}
    if not privileges:
        return {"ok": True, "privileges": []}

    grant = f"GRANT {', '.join(privileges)} ON `{db_name}`.* TO '{username}'@'localhost';"
    ok, _ = _run(grant)
    if ok:
        return {"ok": True, "privileges": privileges}

    # Reapply the last panel-known grant set if replacement failed.
    if previous:
        _run(f"GRANT {', '.join(previous)} ON `{db_name}`.* TO '{username}'@'localhost';")
    return {"ok": False, "error": "database-grant-apply-failed"}


def user_drop(data: dict) -> dict:
    username = _identifier(data.get("username"))
    if not _exists("user", username):
        return {"ok": False, "error": "database-user-not-found"}
    ok, out = _run(f"SHOW GRANTS FOR '{username}'@'localhost';")
    if not ok:
        return {"ok": False, "error": "database-user-grants-unavailable"}
    for line in out.splitlines():
        upper = line.upper()
        if "GRANT USAGE ON *.*" in upper:
            continue
        if "GRANT" in upper and " ON " in upper:
            return {"ok": False, "error": "database-user-still-has-grants"}
    ok, _ = _run(f"DROP USER '{username}'@'localhost';")
    return {"ok": ok, "error": "" if ok else "database-user-drop-failed"}


def dispatch(req: dict) -> dict:
    action = req.get("action")
    data = req.get("data") if isinstance(req.get("data"), dict) else req
    try:
        if action == "status":
            return status()
        if action == "user-create":
            return user_create(data)
        if action == "user-rotate":
            return user_rotate(data)
        if action == "grant-replace":
            return grant_replace(data)
        if action == "user-drop":
            return user_drop(data)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": False, "error": "database-action-not-allowed"}


def reply(conn: socket.socket, obj: dict) -> None:
    conn.sendall((json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8"))


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
                raw = b""
                while not raw.endswith(b"\n") and len(raw) < MAX_REQUEST:
                    chunk = conn.recv(8192)
                    if not chunk:
                        break
                    raw += chunk
                if len(raw) >= MAX_REQUEST:
                    raise ValueError("database-request-too-large")
                body = json.loads(raw.decode("utf-8"))
                if not isinstance(body, dict):
                    raise ValueError("database-request-object-required")
                reply(conn, dispatch(body))
            except Exception:
                reply(conn, {"ok": False, "error": "database-bad-request"})


if __name__ == "__main__":
    main()
