from __future__ import annotations

import grp
import os
import pwd
import re
import shutil
import subprocess
import time
from pathlib import Path

MAIL_CONFIG = Path("/etc/nexvary-panel/mail")
MAIL_ROOT = Path("/var/mail/vhosts")
USERS_FILE = MAIL_CONFIG / "users"
DOMAINS_FILE = MAIL_CONFIG / "domains"
VMAILBOX_FILE = MAIL_CONFIG / "vmailbox"
VIRTUAL_FILE = MAIL_CONFIG / "virtual"
ADDRESS_RE = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._+-]{0,62}[A-Za-z0-9])?)@((?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})$")


def _address(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or len(value) > 320:
        raise ValueError("invalid-address")
    match = ADDRESS_RE.fullmatch(value.strip().lower())
    if not match or ".." in match.group(1) or ".." in match.group(2):
        raise ValueError("invalid-address")
    return match.group(1), match.group(2)


def _safe_file(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError("unsafe-mail-config-boundary")
    if path.exists() and not path.is_file():
        raise RuntimeError("unsafe-mail-config-boundary")


def _service_group(path: Path) -> int:
    name = "dovecot" if path == USERS_FILE else "postfix"
    return int(grp.getgrnam(name).gr_gid)


def _atomic_write(path: Path, text: str, mode: int = 0o640) -> None:
    MAIL_CONFIG.mkdir(parents=True, exist_ok=True)
    if MAIL_CONFIG.is_symlink():
        raise RuntimeError("unsafe-mail-config-boundary")
    _safe_file(path)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, text.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, mode)
    os.chown(tmp, 0, _service_group(path))
    os.replace(tmp, path)


def _read_map(path: Path) -> dict[str, str]:
    _safe_file(path)
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition(" ")
        if sep and key and value.strip():
            out[key] = value.strip()
    return out


def _write_map(path: Path, values: dict[str, str], mode: int = 0o640) -> None:
    text = "".join(f"{key} {values[key]}\n" for key in sorted(values))
    _atomic_write(path, text, mode)


def _read_users() -> dict[str, str]:
    _safe_file(USERS_FILE)
    if not USERS_FILE.exists():
        return {}
    out: dict[str, str] = {}
    for raw in USERS_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition(":")
        if sep and key and value:
            out[key] = value
    return out


def _write_users(values: dict[str, str]) -> None:
    text = "".join(f"{key}:{values[key]}\n" for key in sorted(values))
    _atomic_write(USERS_FILE, text, 0o640)


def _hash_password(password: str) -> str:
    if not isinstance(password, str) or not 14 <= len(password) <= 128 or "\x00" in password or "\n" in password:
        raise ValueError("invalid-password")
    proc = subprocess.run(
        ["openssl", "passwd", "-6", "-stdin"], input=password + "\n", capture_output=True,
        text=True, timeout=10, check=False,
    )
    value = proc.stdout.strip()
    if proc.returncode != 0 or not value.startswith("$6$") or len(value) > 240:
        raise RuntimeError("password-hash-failed")
    return "{SHA512-CRYPT}" + value


def _postmap(path: Path) -> None:
    proc = subprocess.run(["postmap", str(path)], capture_output=True, text=True, timeout=15, check=False)
    if proc.returncode != 0:
        raise RuntimeError("mail-map-validation-failed")
    db_path = Path(str(path) + ".db")
    if db_path.exists() and not db_path.is_symlink():
        os.chown(db_path, 0, grp.getgrnam("postfix").gr_gid)
        os.chmod(db_path, 0o640)


def _reload() -> None:
    for path in (DOMAINS_FILE, VMAILBOX_FILE, VIRTUAL_FILE):
        _postmap(path)
    check = subprocess.run(["postfix", "check"], capture_output=True, text=True, timeout=20, check=False)
    if check.returncode != 0:
        raise RuntimeError("postfix-validation-failed")
    dove = subprocess.run(["dovecot", "-n"], capture_output=True, text=True, timeout=20, check=False)
    if dove.returncode != 0:
        raise RuntimeError("dovecot-validation-failed")
    for svc in ("postfix", "dovecot"):
        proc = subprocess.run(["systemctl", "reload", svc], capture_output=True, text=True, timeout=20, check=False)
        if proc.returncode != 0:
            raise RuntimeError("mail-service-reload-failed")


def _vmail_identity() -> tuple[int, int]:
    account = pwd.getpwnam("vmail")
    return int(account.pw_uid), int(account.pw_gid)


def provider_status() -> dict:
    required = ["postmap", "postfix", "dovecot", "openssl"]
    if any(shutil.which(name) is None for name in required):
        return {"ok": False, "error": "mail-provider-not-installed"}
    try:
        _vmail_identity()
        grp.getgrnam("postfix")
        grp.getgrnam("dovecot")
    except KeyError:
        return {"ok": False, "error": "mail-provider-not-configured"}
    active = {}
    for svc in ("postfix", "dovecot"):
        proc = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True, timeout=5, check=False)
        active[svc] = proc.stdout.strip() == "active"
    if not all(active.values()):
        return {"ok": False, "error": "mail-provider-inactive", "services": active}
    return {"ok": True, "engine": "postfix-dovecot", "services": active}


def mailbox_upsert(address: str, password: str) -> dict:
    localpart, domain = _address(address)
    if not provider_status().get("ok"):
        return {"ok": False, "error": "mail-provider-unavailable"}
    users = _read_users()
    domains = _read_map(DOMAINS_FILE)
    boxes = _read_map(VMAILBOX_FILE)
    aliases = _read_map(VIRTUAL_FILE)
    key = address.lower()
    users[key] = _hash_password(password)
    domains[domain] = "OK"
    boxes[key] = f"{domain}/{localpart}/"
    aliases.pop(key, None)
    _write_users(users)
    _write_map(DOMAINS_FILE, domains, 0o640)
    _write_map(VMAILBOX_FILE, boxes, 0o640)
    _write_map(VIRTUAL_FILE, aliases, 0o640)
    uid, gid = _vmail_identity()
    domain_dir = MAIL_ROOT / domain
    mailbox_dir = domain_dir / localpart
    mailbox_dir.mkdir(parents=True, exist_ok=True)
    os.chown(domain_dir, uid, gid)
    os.chown(mailbox_dir, uid, gid)
    os.chmod(domain_dir, 0o750)
    os.chmod(mailbox_dir, 0o700)
    _reload()
    return {"ok": True, "address": key}


def mailbox_delete(address: str) -> dict:
    localpart, domain = _address(address)
    users = _read_users()
    domains = _read_map(DOMAINS_FILE)
    boxes = _read_map(VMAILBOX_FILE)
    aliases = _read_map(VIRTUAL_FILE)
    key = address.lower()
    users.pop(key, None)
    boxes.pop(key, None)
    _write_users(users)
    _write_map(DOMAINS_FILE, domains, 0o640)
    _write_map(VMAILBOX_FILE, boxes, 0o640)
    _write_map(VIRTUAL_FILE, aliases, 0o640)
    source = MAIL_ROOT / domain / localpart
    if source.exists() and source.is_dir() and not source.is_symlink():
        quarantine = MAIL_ROOT / ".deleted"
        quarantine.mkdir(parents=True, exist_ok=True)
        target = quarantine / f"{int(time.time())}-{domain}-{localpart}"
        source.rename(target)
    _reload()
    return {"ok": True, "address": key, "data": "quarantined"}


def forwarder_upsert(source: str, destination: str) -> dict:
    _, domain = _address(source)
    _address(destination)
    if not provider_status().get("ok"):
        return {"ok": False, "error": "mail-provider-unavailable"}
    domains = _read_map(DOMAINS_FILE)
    boxes = _read_map(VMAILBOX_FILE)
    aliases = _read_map(VIRTUAL_FILE)
    if source.lower() in boxes:
        return {"ok": False, "error": "source-is-a-mailbox"}
    domains[domain] = "OK"
    aliases[source.lower()] = destination.lower()
    _write_map(DOMAINS_FILE, domains, 0o640)
    _write_map(VMAILBOX_FILE, boxes, 0o640)
    _write_map(VIRTUAL_FILE, aliases, 0o640)
    _reload()
    return {"ok": True, "source": source.lower(), "destination": destination.lower()}


def forwarder_delete(source: str) -> dict:
    _address(source)
    domains = _read_map(DOMAINS_FILE)
    boxes = _read_map(VMAILBOX_FILE)
    aliases = _read_map(VIRTUAL_FILE)
    aliases.pop(source.lower(), None)
    _write_map(DOMAINS_FILE, domains, 0o640)
    _write_map(VMAILBOX_FILE, boxes, 0o640)
    _write_map(VIRTUAL_FILE, aliases, 0o640)
    _reload()
    return {"ok": True, "source": source.lower()}
