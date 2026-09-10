#!/usr/bin/env python3
from __future__ import annotations

import base64
import grp
import json
import os
import pwd
import re
import secrets
import shutil
import socket
import subprocess
import sys
from pathlib import Path

SOCKET_PATH = Path(os.environ.get("NVP_TRANSFER_SOCK", "/run/nexvary-panel/transfer.sock"))
SITE_BASE = Path("/var/www")
CHROOT_BASE = Path("/srv/nexvary-sftp")
KEY_DIR = Path("/etc/nexvary-panel/sftp-keys")
TRACK_DIR = Path("/etc/nexvary-panel/sftp-mounts")
SSHD_SNIPPET = Path("/etc/ssh/sshd_config.d/90-nexvary-sftp.conf")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
SYSTEM_USER_RE = re.compile(r"^nvpt_[a-f0-9]{10}$")
KEY_TYPES = {"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}
MAX_REQUEST = 24 * 1024
ACTIONS = {"status", "account-create", "account-delete", "key-update"}
ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": "/root"}


def _run(args: list[str], timeout: int = 25, ok_codes: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess:
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=ENV, check=False)
    if proc.returncode not in ok_codes:
        command = Path(args[0]).name[:40]
        tail = (proc.stderr or proc.stdout or "").strip().replace("\n", " ")[-240:]
        print(f"transfer command failed: {command} rc={proc.returncode} detail={tail}", file=sys.stderr, flush=True)
        raise RuntimeError(f"transfer-provider-command-failed:{command}:{proc.returncode}")
    return proc


def _random_login_hash() -> str:
    if shutil.which("openssl") is None:
        raise RuntimeError("openssl-not-installed")
    secret = secrets.token_urlsafe(48)
    proc = subprocess.run(
        ["openssl", "passwd", "-6", "-stdin"],
        input=secret + "\n",
        capture_output=True,
        text=True,
        timeout=10,
        env=ENV,
        check=False,
    )
    password_hash = proc.stdout.strip()
    if proc.returncode != 0 or not password_hash.startswith("$6$") or len(password_hash) > 255:
        raise RuntimeError("transfer-password-hash-failed")
    return password_hash


def _valid_domain(domain: str) -> str:
    value = str(domain).strip().lower()
    if not DOMAIN_RE.fullmatch(value):
        raise ValueError("invalid-domain")
    return value


def _valid_system_user(value: str) -> str:
    value = str(value).strip()
    if not SYSTEM_USER_RE.fullmatch(value):
        raise ValueError("invalid-transfer-user")
    return value


def _public_key(value: str) -> str:
    if not isinstance(value, str) or not 40 <= len(value) <= 16384 or any(c in value for c in "\r\n\x00"):
        raise ValueError("invalid-public-key")
    parts = value.strip().split(maxsplit=2)
    if len(parts) < 2 or parts[0] not in KEY_TYPES:
        raise ValueError("unsupported-public-key")
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except Exception as exc:
        raise ValueError("invalid-public-key") from exc
    if not 32 <= len(raw) <= 8192:
        raise ValueError("invalid-public-key")
    return f"{parts[0]} {parts[1]}"


def _site_root(domain: str) -> Path:
    domain = _valid_domain(domain)
    root = SITE_BASE / domain
    if not root.exists() or not root.is_dir() or root.is_symlink():
        raise ValueError("site-root-not-found")
    try:
        if os.path.commonpath((str(SITE_BASE), str(root.resolve()))) != str(SITE_BASE):
            raise ValueError("unsafe-site-root")
    except OSError as exc:
        raise ValueError("unsafe-site-root") from exc
    return root


def _ensure_dirs() -> None:
    for path, mode in ((CHROOT_BASE, 0o755), (KEY_DIR, 0o700), (TRACK_DIR, 0o700)):
        if path.exists() and path.is_symlink():
            raise RuntimeError("unsafe-transfer-boundary")
        path.mkdir(parents=True, exist_ok=True)
        os.chown(path, 0, 0)
        os.chmod(path, mode)


def _atomic_key(system_user: str, public_key: str) -> None:
    _ensure_dirs()
    path = KEY_DIR / system_user
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise RuntimeError("unsafe-transfer-key-boundary")
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (public_key + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chown(tmp, 0, 0)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _tracking_path(system_user: str) -> Path:
    return TRACK_DIR / system_user


def _write_tracking(system_user: str, domain: str) -> None:
    _ensure_dirs()
    path = _tracking_path(system_user)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (domain + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chown(tmp, 0, 0)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _read_tracking(system_user: str) -> str:
    path = _tracking_path(system_user)
    if path.is_symlink() or not path.is_file():
        raise ValueError("transfer-account-not-tracked")
    return _valid_domain(path.read_text(encoding="utf-8").strip())


def _account_exists(system_user: str) -> bool:
    try:
        pwd.getpwnam(system_user)
        return True
    except KeyError:
        return False


def _mount_target(system_user: str) -> Path:
    return CHROOT_BASE / system_user / "site"


def _is_mountpoint(path: Path) -> bool:
    proc = subprocess.run(["mountpoint", "-q", "--", str(path)], capture_output=True, text=True, timeout=8, env=ENV, check=False)
    return proc.returncode == 0


def _mount_site(site: Path, target: Path) -> None:
    if _is_mountpoint(target):
        return
    _run(["mount", "--bind", "--", str(site), str(target)], timeout=20)
    if not _is_mountpoint(target):
        raise RuntimeError("transfer-mount-did-not-activate")


def _unmount_site(target: Path) -> None:
    if not _is_mountpoint(target):
        return
    _run(["umount", "--", str(target)], timeout=20)
    if _is_mountpoint(target):
        raise RuntimeError("transfer-unmount-did-not-complete")


def _apply_acl(system_user: str, site: Path) -> None:
    _run(["setfacl", "-Rm", f"u:{system_user}:rwX", "--", str(site)], timeout=45)
    _run(["setfacl", "-Rdm", f"u:{system_user}:rwx", "--", str(site)], timeout=45)


def _remove_acl(system_user: str, site: Path) -> None:
    subprocess.run(["setfacl", "-Rx", f"u:{system_user}", "--", str(site)], env=ENV, capture_output=True, timeout=45, check=False)
    subprocess.run(["setfacl", "-Rx", f"d:u:{system_user}", "--", str(site)], env=ENV, capture_output=True, timeout=45, check=False)


def _ensure_mount(system_user: str, domain: str) -> None:
    site = _site_root(domain)
    chroot = CHROOT_BASE / system_user
    target = chroot / "site"
    for path in (chroot, target):
        if path.exists() and path.is_symlink():
            raise RuntimeError("unsafe-transfer-chroot")
        path.mkdir(parents=True, exist_ok=True)
        os.chown(path, 0, 0)
        os.chmod(path, 0o755)
    _apply_acl(system_user, site)
    _mount_site(site, target)


def provider_status() -> dict:
    required = ["sshd", "mount", "umount", "mountpoint", "setfacl", "useradd", "userdel", "openssl"]
    if any(shutil.which(name) is None for name in required):
        return {"ok": False, "error": "sftp-provider-not-installed"}
    try:
        grp.getgrnam("nexvary-sftp")
    except KeyError:
        return {"ok": False, "error": "sftp-provider-not-configured"}
    if not SSHD_SNIPPET.is_file() or SSHD_SNIPPET.is_symlink():
        return {"ok": False, "error": "sftp-provider-not-configured"}
    active = subprocess.run(["systemctl", "is-active", "ssh"], capture_output=True, text=True, timeout=5, env=ENV, check=False)
    if active.stdout.strip() != "active":
        return {"ok": False, "error": "sftp-provider-inactive"}
    return {"ok": True, "engine": "openssh-internal-sftp", "auth": "public-key", "shell": False}


def account_create(system_user: str, domain: str, public_key: str) -> dict:
    system_user = _valid_system_user(system_user)
    domain = _valid_domain(domain)
    public_key = _public_key(public_key)
    if not provider_status().get("ok"):
        return {"ok": False, "error": "sftp-provider-unavailable"}
    _site_root(domain)
    if _account_exists(system_user) or _tracking_path(system_user).exists():
        return {"ok": False, "error": "transfer-user-conflict"}
    created_user = False
    try:
        password_hash = _random_login_hash()
        _run(["useradd", "--system", "--gid", "nexvary-sftp", "--no-create-home", "--home-dir", "/site", "--shell", "/usr/sbin/nologin", "--password", password_hash, "--", system_user])
        created_user = True
        _atomic_key(system_user, public_key)
        _write_tracking(system_user, domain)
        _ensure_mount(system_user, domain)
    except Exception:
        target = _mount_target(system_user)
        try:
            _unmount_site(target)
        except Exception:
            pass
        try:
            _remove_acl(system_user, _site_root(domain))
        except Exception:
            pass
        if created_user:
            subprocess.run(["userdel", "--", system_user], env=ENV, capture_output=True, timeout=15, check=False)
        (KEY_DIR / system_user).unlink(missing_ok=True)
        _tracking_path(system_user).unlink(missing_ok=True)
        shutil.rmtree(CHROOT_BASE / system_user, ignore_errors=True)
        raise
    return {"ok": True, "system_user": system_user, "domain": domain, "path": "/site", "shell": False}


def key_update(system_user: str, public_key: str) -> dict:
    system_user = _valid_system_user(system_user)
    public_key = _public_key(public_key)
    if not _account_exists(system_user):
        return {"ok": False, "error": "transfer-account-not-found"}
    _read_tracking(system_user)
    _atomic_key(system_user, public_key)
    return {"ok": True, "system_user": system_user}


def account_delete(system_user: str, domain: str) -> dict:
    system_user = _valid_system_user(system_user)
    domain = _valid_domain(domain)
    tracked = _read_tracking(system_user)
    if tracked != domain:
        return {"ok": False, "error": "transfer-domain-mismatch"}
    target = _mount_target(system_user)
    _unmount_site(target)
    try:
        _remove_acl(system_user, _site_root(domain))
    except ValueError:
        pass
    if _account_exists(system_user):
        _run(["userdel", "--", system_user], timeout=20)
    (KEY_DIR / system_user).unlink(missing_ok=True)
    _tracking_path(system_user).unlink(missing_ok=True)
    shutil.rmtree(CHROOT_BASE / system_user, ignore_errors=True)
    return {"ok": True, "system_user": system_user}


def _reconcile_mounts() -> None:
    _ensure_dirs()
    for path in TRACK_DIR.iterdir():
        if path.is_symlink() or not path.is_file() or not SYSTEM_USER_RE.fullmatch(path.name):
            continue
        try:
            domain = _valid_domain(path.read_text(encoding="utf-8").strip())
            if _account_exists(path.name):
                _ensure_mount(path.name, domain)
        except Exception as exc:
            print(f"transfer reconcile skipped {path.name}: {type(exc).__name__}", file=sys.stderr, flush=True)


def _dispatch(data: dict) -> dict:
    action = str(data.get("action", ""))
    if action not in ACTIONS:
        return {"ok": False, "error": "transfer-action-not-allowed"}
    if action == "status":
        return provider_status()
    if action == "account-create":
        return account_create(str(data.get("system_user", "")), str(data.get("domain", "")), str(data.get("public_key", "")))
    if action == "account-delete":
        return account_delete(str(data.get("system_user", "")), str(data.get("domain", "")))
    return key_update(str(data.get("system_user", "")), str(data.get("public_key", "")))


def _serve_client(conn: socket.socket) -> None:
    data = b""
    while not data.endswith(b"\n") and len(data) <= MAX_REQUEST:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    if len(data) > MAX_REQUEST:
        result = {"ok": False, "error": "transfer-request-too-large"}
    else:
        try:
            payload = json.loads(data.decode("utf-8")) if data else {}
            if not isinstance(payload, dict):
                raise ValueError
            result = _dispatch(payload)
        except ValueError as exc:
            result = {"ok": False, "error": str(exc)[:100] or "invalid-transfer-request"}
        except RuntimeError as exc:
            result = {"ok": False, "error": str(exc)[:120] or "transfer-provider-operation-failed"}
        except Exception as exc:
            print(f"transfer provider operation failed: {type(exc).__name__}", file=sys.stderr, flush=True)
            result = {"ok": False, "error": "transfer-provider-operation-failed"}
    conn.sendall((json.dumps(result, separators=(",", ":")) + "\n").encode())


def main() -> None:
    _reconcile_mounts()
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
                conn.settimeout(50)
                _serve_client(conn)
    finally:
        server.close()
        SOCKET_PATH.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
