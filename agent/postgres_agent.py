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
ACTIONS = {"status", "create", "delete", "role-create", "role-rotate", "role-drop", "grant-profile"}
GRANT_PROFILES = {"none", "readonly", "readwrite", "developer"}
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
    if not DB_RE.fullmatch(value): raise ValueError("invalid-postgres-identifier")
    return value


def _password(value: object) -> str:
    value = str(value or "")
    if not PASSWORD_RE.fullmatch(value): raise ValueError("invalid-database-password")
    return value


def _qi(value: str) -> str: return '"' + _name(value) + '"'


def _available() -> bool:
    return all(shutil.which(x) for x in ("psql", "createuser", "createdb", "dropuser", "dropdb"))


def _exists(kind: str, value: str) -> bool:
    value = _name(value)
    if kind == "role": query = f"SELECT 1 FROM pg_roles WHERE rolname='{value}'"
    elif kind == "database": query = f"SELECT 1 FROM pg_database WHERE datname='{value}'"
    else: raise ValueError("invalid-postgres-object")
    return _run(["psql", "-X", "-tAc", query, "-d", "postgres"], 15).stdout.strip() == "1"


def _database_owner(name: str) -> str:
    name = _name(name)
    query = f"SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='{name}'"
    owner = _run(["psql", "-X", "-tAc", query, "-d", "postgres"], 15).stdout.strip()
    if not owner or not DB_RE.fullmatch(owner): raise RuntimeError("postgres-database-owner-unavailable")
    return owner


def _lock_down_database(name: str) -> None:
    dbq = _qi(name)
    sql = (
        "BEGIN;\n"
        f"REVOKE CONNECT,TEMPORARY ON DATABASE {dbq} FROM PUBLIC;\n"
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC;\n"
        "COMMIT;\n"
    )
    _run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", name], 30, sql)


def _create(data: dict) -> dict:
    name = _name(data.get("db_name")); user = _name(data.get("db_user")); password = _password(data.get("password"))
    if not _available(): return {"ok": False, "error": "postgresql-not-installed"}
    if _exists("role", user) or _exists("database", name): return {"ok": False, "error": "postgres-resource-conflict"}
    role_created = False; db_created = False
    try:
        _run(["createuser", "--no-password", "--login", "--", user], 30); role_created = True
        _run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", "postgres"], 30,
             f"ALTER ROLE {_qi(user)} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS PASSWORD '{password}';\n")
        _run(["createdb", "-O", user, "--", name], 30); db_created = True
        _lock_down_database(name)
    except Exception:
        if db_created:
            try: _run(["dropdb", "--if-exists", "--", name], 20)
            except Exception: pass
        if role_created:
            try: _run(["dropuser", "--if-exists", "--", user], 20)
            except Exception: pass
        raise
    return {"ok": True, "db_name": name, "db_user": user}


def _delete(data: dict) -> dict:
    name = _name(data.get("db_name")); user = _name(data.get("db_user"))
    if not _available(): return {"ok": False, "error": "postgresql-not-installed"}
    _run(["dropdb", "--if-exists", "--", name], 30); _run(["dropuser", "--if-exists", "--", user], 30)
    return {"ok": True, "deleted": True}


def _role_create(data: dict) -> dict:
    user = _name(data.get("username")); password = _password(data.get("password"))
    if not _available(): return {"ok": False, "error": "postgresql-not-installed"}
    if _exists("role", user): return {"ok": False, "error": "postgres-role-conflict"}
    sql = f"CREATE ROLE {_qi(user)} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 20 PASSWORD '{password}';\n"
    _run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", "postgres"], 25, sql)
    return {"ok": True, "username": user}


def _role_rotate(data: dict) -> dict:
    user = _name(data.get("username")); password = _password(data.get("password"))
    if not _exists("role", user): return {"ok": False, "error": "postgres-role-not-found"}
    sql = f"ALTER ROLE {_qi(user)} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 20 PASSWORD '{password}';\n"
    _run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", "postgres"], 25, sql)
    return {"ok": True, "username": user}


def _profile_sql(db_name: str, user: str, owner: str, profile: str) -> str:
    if profile not in GRANT_PROFILES: raise ValueError("invalid-postgres-grant-profile")
    dbq, userq, ownerq = _qi(db_name), _qi(user), _qi(owner)
    sql = [
        "BEGIN;",
        f"REVOKE CONNECT,TEMPORARY ON DATABASE {dbq} FROM PUBLIC;",
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC;",
        f"REVOKE ALL PRIVILEGES ON DATABASE {dbq} FROM {userq};",
        f"REVOKE ALL PRIVILEGES ON SCHEMA public FROM {userq};",
        f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {userq};",
        f"REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM {userq};",
        f"ALTER DEFAULT PRIVILEGES FOR ROLE {ownerq} IN SCHEMA public REVOKE ALL PRIVILEGES ON TABLES FROM {userq};",
        f"ALTER DEFAULT PRIVILEGES FOR ROLE {ownerq} IN SCHEMA public REVOKE ALL PRIVILEGES ON SEQUENCES FROM {userq};",
    ]
    if profile == "readonly":
        sql.extend([
            f"GRANT CONNECT ON DATABASE {dbq} TO {userq};",
            f"GRANT USAGE ON SCHEMA public TO {userq};",
            f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {userq};",
            f"GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO {userq};",
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {ownerq} IN SCHEMA public GRANT SELECT ON TABLES TO {userq};",
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {ownerq} IN SCHEMA public GRANT SELECT ON SEQUENCES TO {userq};",
        ])
    elif profile == "readwrite":
        sql.extend([
            f"GRANT CONNECT,TEMPORARY ON DATABASE {dbq} TO {userq};",
            f"GRANT USAGE ON SCHEMA public TO {userq};",
            f"GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO {userq};",
            f"GRANT USAGE,SELECT,UPDATE ON ALL SEQUENCES IN SCHEMA public TO {userq};",
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {ownerq} IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO {userq};",
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {ownerq} IN SCHEMA public GRANT USAGE,SELECT,UPDATE ON SEQUENCES TO {userq};",
        ])
    elif profile == "developer":
        sql.extend([
            f"GRANT CONNECT,TEMPORARY ON DATABASE {dbq} TO {userq};",
            f"GRANT USAGE,CREATE ON SCHEMA public TO {userq};",
            f"GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON ALL TABLES IN SCHEMA public TO {userq};",
            f"GRANT USAGE,SELECT,UPDATE ON ALL SEQUENCES IN SCHEMA public TO {userq};",
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {ownerq} IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON TABLES TO {userq};",
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {ownerq} IN SCHEMA public GRANT USAGE,SELECT,UPDATE ON SEQUENCES TO {userq};",
        ])
    sql.append("COMMIT;")
    return "\n".join(sql) + "\n"


def _grant_profile(data: dict) -> dict:
    db_name = _name(data.get("db_name")); user = _name(data.get("username")); profile = str(data.get("profile", "")).strip().lower()
    if profile not in GRANT_PROFILES: raise ValueError("invalid-postgres-grant-profile")
    if not _exists("database", db_name): return {"ok": False, "error": "postgres-database-not-found"}
    if not _exists("role", user): return {"ok": False, "error": "postgres-role-not-found"}
    owner = _database_owner(db_name)
    if owner == user: return {"ok": False, "error": "postgres-database-owner-profile-is-managed-by-ownership"}
    _run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", db_name], 55, _profile_sql(db_name, user, owner, profile))
    return {"ok": True, "db_name": db_name, "username": user, "profile": profile}


def _role_drop(data: dict) -> dict:
    user = _name(data.get("username"))
    if not _exists("role", user): return {"ok": False, "error": "postgres-role-not-found"}
    owned = _run(["psql", "-X", "-tAc", f"SELECT COUNT(*) FROM pg_database WHERE datdba=(SELECT oid FROM pg_roles WHERE rolname='{user}')", "-d", "postgres"], 15).stdout.strip()
    if owned not in {"", "0"}: return {"ok": False, "error": "postgres-role-owns-database"}
    try: _run(["dropuser", "--", user], 30)
    except RuntimeError: return {"ok": False, "error": "postgres-role-has-dependent-privileges-or-objects"}
    return {"ok": True, "username": user, "deleted": True}


def _dispatch(data: dict) -> dict:
    action = str(data.get("action", ""))
    if action not in ACTIONS: return {"ok": False, "error": "postgres-action-not-allowed"}
    if action == "status": return {"ok": True, "engine": "postgresql", "available": _available(), "grant_profiles": sorted(GRANT_PROFILES - {"none"})}
    if action == "create": return _create(data)
    if action == "delete": return _delete(data)
    if action == "role-create": return _role_create(data)
    if action == "role-rotate": return _role_rotate(data)
    if action == "grant-profile": return _grant_profile(data)
    return _role_drop(data)


def _serve(conn: socket.socket) -> None:
    raw = b""
    while not raw.endswith(b"\n") and len(raw) <= MAX_REQUEST:
        chunk = conn.recv(4096)
        if not chunk: break
        raw += chunk
    try:
        if not raw.endswith(b"\n") or len(raw) > MAX_REQUEST: raise ValueError("postgres-request-too-large")
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict): raise ValueError("postgres-object-required")
        result = _dispatch(data)
    except ValueError as exc: result = {"ok": False, "error": str(exc)[:120]}
    except RuntimeError as exc: result = {"ok": False, "error": str(exc)[:160]}
    except Exception: result = {"ok": False, "error": "postgres-provider-operation-failed"}
    conn.sendall((json.dumps(result, separators=(",", ":")) + "\n").encode("utf-8"))


def main() -> None:
    SOCK.parent.mkdir(parents=True, exist_ok=True)
    if SOCK.exists() or SOCK.is_symlink(): SOCK.unlink()
    old_umask = os.umask(0o117); server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try: server.bind(str(SOCK))
    finally: os.umask(old_umask)
    os.chown(SOCK, os.getuid(), grp.getgrnam("nexvary-panel").gr_gid); os.chmod(SOCK, 0o660); server.listen(16)
    try:
        while True:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(45); _serve(conn)
    finally:
        server.close(); SOCK.unlink(missing_ok=True)


if __name__ == "__main__": main()
