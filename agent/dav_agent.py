#!/usr/bin/env python3
from __future__ import annotations

import grp
import json
import os
import re
import socket
import stat
import subprocess
import tempfile
from pathlib import Path

SOCKET_PATH = Path(os.environ.get("NVP_DAV_SOCK", "/run/nexvary-panel/dav.sock"))
USERS_FILE = Path(os.environ.get("NVP_DAV_USERS", "/etc/nexvary-panel-radicale/users"))
SERVICE = os.environ.get("NVP_DAV_SERVICE", "nexvary-panel-dav")
MAX_REQUEST = 32 * 1024
BASE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9_@%+=:.,!$#?~^&*()\-]{14,128}$")
SAFE_ERROR_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,79}$")


def _validate_username(value: object) -> str:
    username = str(value or "").strip().lower()
    if not EMAIL_RE.fullmatch(username) or ".." in username:
        raise ValueError("invalid-dav-username")
    return username


def _validate_password(value: object) -> str:
    password = str(value or "")
    if not PASSWORD_RE.fullmatch(password):
        raise ValueError("invalid-dav-password")
    return password


def _regular_users_file() -> bool:
    try:
        info = os.lstat(USERS_FILE)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError("dav-users-file-unsafe")
    return True


def _snapshot() -> bytes:
    if not _regular_users_file():
        return b""
    try:
        return USERS_FILE.read_bytes()
    except OSError as exc:
        raise RuntimeError("dav-users-file-unavailable") from exc


def _usernames(data: bytes) -> set[str]:
    names: set[str] = set()
    for raw in data.decode("utf-8", errors="strict").splitlines():
        if not raw or raw.startswith("#") or ":" not in raw:
            continue
        username = raw.split(":", 1)[0].strip().lower()
        if username:
            names.add(username)
    return names


def _install_bytes(data: bytes) -> None:
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix="users.", dir=str(USERS_FILE.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        gid = grp.getgrnam("radicale").gr_gid
        os.chown(tmp, 0, gid)
        os.chmod(tmp, 0o640)
        os.replace(tmp, USERS_FILE)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _restart_provider() -> None:
    proc = subprocess.run(
        ["systemctl", "restart", SERVICE], capture_output=True, text=True, timeout=25, check=False, env=BASE_ENV,
    )
    if proc.returncode != 0:
        raise RuntimeError("dav-service-restart-failed")
    check = subprocess.run(
        ["systemctl", "is-active", "--quiet", SERVICE], capture_output=True, text=True, timeout=10, check=False, env=BASE_ENV,
    )
    if check.returncode != 0:
        raise RuntimeError("dav-service-offline")


def _status() -> dict:
    proc = subprocess.run(
        ["systemctl", "is-active", "--quiet", SERVICE], capture_output=True, text=True, timeout=10, check=False, env=BASE_ENV,
    )
    data = _snapshot()
    return {
        "ok": True,
        "online": proc.returncode == 0,
        "engine": "radicale-caldav-carddav",
        "account_count": len(_usernames(data)),
    }


def _credential_sync(username_value: object, password_value: object, expected_present: object) -> dict:
    username = _validate_username(username_value)
    password = _validate_password(password_value)
    expected = bool(expected_present)
    snapshot = _snapshot()
    present = username in _usernames(snapshot)
    if present != expected:
        raise RuntimeError("dav-provider-conflict")

    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix="users.next.", dir=str(USERS_FILE.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(snapshot)
            handle.flush()
            os.fsync(handle.fileno())
        proc = subprocess.run(
            ["htpasswd", "-i", "-B", "-C", "10", str(tmp), username],
            input=password + "\n", capture_output=True, text=True, timeout=30, check=False, env=BASE_ENV,
        )
        password = ""
        if proc.returncode != 0:
            raise RuntimeError("dav-password-hash-failed")
        new_data = tmp.read_bytes()
        _install_bytes(new_data)
        try:
            _restart_provider()
        except Exception:
            _install_bytes(snapshot)
            try:
                _restart_provider()
            except Exception:
                pass
            raise
    finally:
        password = ""
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
    return {"ok": True, "username": username, "engine": "radicale-caldav-carddav"}


def _credential_delete(username_value: object) -> dict:
    username = _validate_username(username_value)
    snapshot = _snapshot()
    if username not in _usernames(snapshot):
        return {"ok": True, "username": username, "already_absent": True}
    kept = []
    for raw in snapshot.decode("utf-8", errors="strict").splitlines():
        if raw.split(":", 1)[0].strip().lower() == username:
            continue
        kept.append(raw)
    new_data = (("\n".join(kept) + "\n") if kept else "").encode("utf-8")
    _install_bytes(new_data)
    try:
        _restart_provider()
    except Exception:
        _install_bytes(snapshot)
        try:
            _restart_provider()
        except Exception:
            pass
        raise
    return {"ok": True, "username": username}


def _dispatch(data: dict) -> dict:
    action = str(data.get("action", ""))
    if action == "status":
        return _status()
    if action == "credential-sync":
        return _credential_sync(data.get("username", ""), data.get("password", ""), data.get("expected_present", False))
    if action == "credential-delete":
        return _credential_delete(data.get("username", ""))
    return {"ok": False, "error": "dav-action-not-allowed"}


def _safe_error(exc: Exception) -> str:
    code = str(exc).strip().lower()
    return code if SAFE_ERROR_RE.fullmatch(code) else "dav-provider-operation-failed"


def _serve_client(conn: socket.socket) -> None:
    data = b""
    while not data.endswith(b"\n") and len(data) <= MAX_REQUEST:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    if len(data) > MAX_REQUEST:
        result = {"ok": False, "error": "dav-request-too-large"}
    else:
        try:
            payload = json.loads(data.decode("utf-8")) if data else {}
            if not isinstance(payload, dict):
                raise ValueError("invalid-dav-request")
            result = _dispatch(payload)
        except (ValueError, RuntimeError) as exc:
            result = {"ok": False, "error": _safe_error(exc)}
        except Exception:
            result = {"ok": False, "error": "dav-provider-operation-failed"}
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
