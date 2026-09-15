#!/usr/bin/env python3
from __future__ import annotations

import grp
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import tempfile
import time
from pathlib import Path

SOCK = Path(os.environ.get("NVP_DATABASE_SOCK", "/run/nexvary-panel/database.sock"))
SNAPSHOT_BASE = Path(os.environ.get("NVP_DATABASE_SNAPSHOT_DIR", "/var/backups/nexvary-panel/database-snapshots/mariadb"))
MAX_REQUEST = 64 * 1024
MAX_REPLY = 128 * 1024
DB_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9_@%+=:.,!$#?-]{14,128}$")
SNAPSHOT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}-\d{8}T\d{6}Z-[a-f0-9]{8}\.sql$")
ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
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
            env=ENV,
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


def _snapshot_path(value: object, *, required: bool = True) -> Path:
    archive = str(value or "").strip()
    if not SNAPSHOT_RE.fullmatch(archive) or Path(archive).name != archive:
        raise ValueError("invalid-database-snapshot")
    SNAPSHOT_BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(SNAPSHOT_BASE, 0o700)
    path = SNAPSHOT_BASE / archive
    if path.parent.resolve() != SNAPSHOT_BASE.resolve():
        raise ValueError("invalid-database-snapshot")
    if required:
        try:
            st = os.lstat(path)
        except FileNotFoundError as exc:
            raise ValueError("database-snapshot-not-found") from exc
        if not os.path.isfile(path) or os.path.islink(path) or st.st_nlink != 1:
            raise ValueError("unsafe-database-snapshot")
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dump_database(db_name: str) -> dict:
    db_name = _identifier(db_name)
    if not _exists("database", db_name):
        return {"ok": False, "error": "database-not-found"}
    if not shutil_which("mariadb-dump"):
        return {"ok": False, "error": "mariadb-dump-not-installed"}
    SNAPSHOT_BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(SNAPSHOT_BASE, 0o700)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    archive = f"{db_name}-{stamp}-{secrets.token_hex(4)}.sql"
    target = _snapshot_path(archive, required=False)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{db_name}.", suffix=".tmp", dir=str(SNAPSHOT_BASE))
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as out:
            proc = subprocess.run(
                [
                    "mariadb-dump", "--protocol=socket", "--single-transaction", "--skip-lock-tables",
                    "--routines", "--events", "--triggers", "--add-drop-table", "--skip-comments", db_name,
                ],
                stdout=out,
                stderr=subprocess.PIPE,
                timeout=300,
                env=ENV,
                check=False,
            )
            out.flush()
            os.fsync(out.fileno())
        if proc.returncode:
            return {"ok": False, "error": "database-snapshot-create-failed"}
        os.replace(tmp, target)
        os.chmod(target, 0o600)
        return {"ok": True, "archive": archive, "size_bytes": target.stat().st_size, "sha256": _sha256(target)}
    except (OSError, subprocess.SubprocessError):
        return {"ok": False, "error": "database-snapshot-create-failed"}
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def shutil_which(command: str) -> str | None:
    from shutil import which
    return which(command)


def _import_database(db_name: str, source: Path) -> bool:
    try:
        with source.open("rb") as handle:
            proc = subprocess.run(
                ["mariadb", "--protocol=socket", db_name],
                stdin=handle,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=360,
                env=ENV,
                check=False,
            )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def snapshot_create(data: dict) -> dict:
    return _dump_database(_identifier(data.get("db_name")))


def snapshot_restore(data: dict) -> dict:
    db_name = _identifier(data.get("db_name"))
    if not _exists("database", db_name):
        return {"ok": False, "error": "database-not-found"}
    source = _snapshot_path(data.get("archive"))
    if not source.name.startswith(db_name + "-"):
        return {"ok": False, "error": "snapshot-database-mismatch"}
    rollback = _dump_database(db_name)
    if not rollback.get("ok"):
        return {"ok": False, "error": "pre-restore-snapshot-failed"}
    if not _import_database(db_name, source):
        rollback_path = _snapshot_path(rollback.get("archive"))
        restored = _import_database(db_name, rollback_path)
        return {
            "ok": False,
            "error": "database-restore-failed-previous-state-restored" if restored else "database-restore-failed-rollback-failed",
        }
    return {
        "ok": True,
        "restored": True,
        "rollback_archive": rollback.get("archive", ""),
        "rollback_size_bytes": rollback.get("size_bytes", 0),
        "rollback_sha256": rollback.get("sha256", ""),
    }


def snapshot_delete(data: dict) -> dict:
    path = _snapshot_path(data.get("archive"))
    try:
        path.unlink()
    except OSError:
        return {"ok": False, "error": "database-snapshot-delete-failed"}
    return {"ok": True, "deleted": True}


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
        if action == "snapshot-create":
            return snapshot_create(data)
        if action == "snapshot-restore":
            return snapshot_restore(data)
        if action == "snapshot-delete":
            return snapshot_delete(data)
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
