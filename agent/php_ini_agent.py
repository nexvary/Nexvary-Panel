#!/usr/bin/env python3
from __future__ import annotations

import grp
import json
import os
import re
import socket
import stat
import tempfile
from pathlib import Path

SOCK = Path(os.environ.get("NVP_PHPINI_SOCK", "/run/nexvary-panel/phpini.sock"))
SITE_BASE = Path(os.environ.get("NVP_SITE_BASE", "/var/www"))
MAX_REQUEST = 32 * 1024
MAX_INI_SIZE = 64 * 1024
BEGIN = "; NEXVARY-MANAGED-PHP-BEGIN"
END = "; NEXVARY-MANAGED-PHP-END"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
SIZE_RE = re.compile(r"^([1-9][0-9]{0,4})M$")
ACTIONS = {"status", "get", "set"}

LIMITS = {
    "memory_limit": (64, 4096),
    "upload_max_filesize": (1, 2048),
    "post_max_size": (1, 4096),
}
INT_LIMITS = {
    "max_execution_time": (10, 900),
    "max_input_time": (10, 900),
    "max_input_vars": (100, 20000),
}
BOOL_KEYS = {"display_errors", "log_errors"}
ALLOWED_KEYS = tuple((*LIMITS.keys(), *INT_LIMITS.keys(), *BOOL_KEYS))
DEFAULTS = {
    "memory_limit": "256M",
    "upload_max_filesize": "64M",
    "post_max_size": "64M",
    "max_execution_time": "60",
    "max_input_time": "60",
    "max_input_vars": "1000",
    "display_errors": "Off",
    "log_errors": "On",
}


def _domain(value: object) -> str:
    domain = str(value or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("invalid-domain")
    return domain


def _site_root(domain: object) -> Path:
    value = _domain(domain)
    root = SITE_BASE / value
    try:
        info = os.lstat(root)
    except FileNotFoundError as exc:
        raise ValueError("site-root-not-found") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError("unsafe-site-root")
    resolved = root.resolve()
    base = SITE_BASE.resolve()
    if os.path.commonpath((str(base), str(resolved))) != str(base):
        raise ValueError("unsafe-site-root")
    return root


def _ini_path(domain: object) -> Path:
    root = _site_root(domain)
    path = root / ".user.ini"
    if path.exists() or path.is_symlink():
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ValueError("unsafe-user-ini")
        if info.st_size > MAX_INI_SIZE:
            raise ValueError("user-ini-too-large")
    return path


def _normalize(settings: object) -> dict[str, str]:
    if not isinstance(settings, dict) or set(settings) - set(ALLOWED_KEYS):
        raise ValueError("invalid-php-ini-settings")
    output = dict(DEFAULTS)
    for key, raw in settings.items():
        if key in LIMITS:
            value = str(raw or "").strip().upper()
            match = SIZE_RE.fullmatch(value)
            if not match:
                raise ValueError(f"invalid-php-ini-{key}")
            number = int(match.group(1))
            low, high = LIMITS[key]
            if not low <= number <= high:
                raise ValueError(f"invalid-php-ini-{key}")
            output[key] = f"{number}M"
        elif key in INT_LIMITS:
            try:
                number = int(raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid-php-ini-{key}") from exc
            low, high = INT_LIMITS[key]
            if not low <= number <= high:
                raise ValueError(f"invalid-php-ini-{key}")
            output[key] = str(number)
        elif key in BOOL_KEYS:
            if isinstance(raw, bool):
                output[key] = "On" if raw else "Off"
            elif str(raw).strip().lower() in {"on", "1", "true"}:
                output[key] = "On"
            elif str(raw).strip().lower() in {"off", "0", "false"}:
                output[key] = "Off"
            else:
                raise ValueError(f"invalid-php-ini-{key}")
    upload = int(output["upload_max_filesize"][:-1])
    post = int(output["post_max_size"][:-1])
    memory = int(output["memory_limit"][:-1])
    if post < upload or memory < post:
        raise ValueError("invalid-php-ini-size-order")
    return output


def _managed_block(settings: dict[str, str]) -> str:
    lines = [BEGIN]
    for key in ALLOWED_KEYS:
        lines.append(f"{key} = {settings[key]}")
    lines.append(END)
    return "\n".join(lines)


def _split(text: str) -> tuple[str, str, str] | None:
    starts = [m.start() for m in re.finditer(re.escape(BEGIN), text)]
    ends = [m.start() for m in re.finditer(re.escape(END), text)]
    if not starts and not ends:
        return None
    if len(starts) != 1 or len(ends) != 1 or ends[0] <= starts[0]:
        raise ValueError("malformed-managed-php-ini")
    end_pos = ends[0] + len(END)
    return text[:starts[0]], text[starts[0]:end_pos], text[end_pos:]


def _parse_managed(block: str) -> dict[str, str]:
    settings: dict[str, str] = {}
    for raw in block.splitlines():
        line = raw.strip()
        if not line or line.startswith(";") or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key in ALLOWED_KEYS:
            settings[key] = value
    return _normalize(settings)


def get_settings(domain: object) -> dict:
    value = _domain(domain)
    path = _ini_path(value)
    if not path.exists():
        return {"ok": True, "domain": value, "managed": False, "settings": dict(DEFAULTS), "allowed": list(ALLOWED_KEYS)}
    text = path.read_text(encoding="utf-8", errors="strict")
    parts = _split(text)
    if parts is None:
        return {"ok": True, "domain": value, "managed": False, "settings": dict(DEFAULTS), "allowed": list(ALLOWED_KEYS)}
    return {"ok": True, "domain": value, "managed": True, "settings": _parse_managed(parts[1]), "allowed": list(ALLOWED_KEYS)}


def _atomic_replace(path: Path, text: str, uid: int, gid: int, mode: int) -> None:
    fd, tmp_name = tempfile.mkstemp(prefix=".nvp-user-ini-", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def set_settings(domain: object, settings: object) -> dict:
    value = _domain(domain)
    path = _ini_path(value)
    root = path.parent
    root_info = os.stat(root, follow_symlinks=False)
    old_text = ""
    old_mode = 0o644
    old_uid, old_gid = root_info.st_uid, root_info.st_gid
    if path.exists():
        info = os.stat(path, follow_symlinks=False)
        old_text = path.read_text(encoding="utf-8", errors="strict")
        old_mode = stat.S_IMODE(info.st_mode)
        old_uid, old_gid = info.st_uid, info.st_gid
    normalized = _normalize(settings)
    block = _managed_block(normalized)
    parts = _split(old_text)
    if parts is None:
        prefix = old_text
        if prefix and not prefix.endswith("\n"):
            prefix += "\n"
        new_text = prefix + block + "\n"
    else:
        new_text = parts[0] + block + parts[2]
        if not new_text.endswith("\n"):
            new_text += "\n"
    if len(new_text.encode("utf-8")) > MAX_INI_SIZE:
        raise ValueError("user-ini-too-large")
    try:
        _atomic_replace(path, new_text, old_uid, old_gid, old_mode)
        check = get_settings(value)
        if check["settings"] != normalized or not check["managed"]:
            raise RuntimeError("php-ini-verification-failed")
    except Exception:
        if path.exists() and not path.is_symlink():
            if old_text:
                _atomic_replace(path, old_text, old_uid, old_gid, old_mode)
            else:
                path.unlink(missing_ok=True)
        raise
    return {"ok": True, "domain": value, "managed": True, "settings": normalized, "allowed": list(ALLOWED_KEYS)}


def dispatch(data: dict) -> dict:
    action = str(data.get("action", ""))
    if action not in ACTIONS:
        return {"ok": False, "error": "php-ini-action-not-allowed"}
    if action == "status":
        return {"ok": True, "engine": "nexvary-php-ini", "settings": list(ALLOWED_KEYS)}
    if action == "get":
        return get_settings(data.get("domain", ""))
    return set_settings(data.get("domain", ""), data.get("settings"))


def _serve(conn: socket.socket) -> None:
    raw = b""
    while not raw.endswith(b"\n") and len(raw) <= MAX_REQUEST:
        chunk = conn.recv(4096)
        if not chunk:
            break
        raw += chunk
    try:
        if not raw.endswith(b"\n") or len(raw) > MAX_REQUEST:
            raise ValueError("php-ini-request-too-large")
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("php-ini-object-required")
        result = dispatch(payload)
    except (ValueError, RuntimeError, UnicodeError) as exc:
        result = {"ok": False, "error": str(exc)[:160] or "php-ini-operation-failed"}
    except Exception:
        result = {"ok": False, "error": "php-ini-operation-failed"}
    conn.sendall((json.dumps(result, separators=(",", ":")) + "\n").encode("utf-8"))


def main() -> None:
    SOCK.parent.mkdir(parents=True, exist_ok=True)
    if SOCK.exists() or SOCK.is_symlink():
        SOCK.unlink()
    old = os.umask(0o117)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(SOCK))
    finally:
        os.umask(old)
    os.chown(SOCK, 0, grp.getgrnam("nexvary-panel").gr_gid)
    os.chmod(SOCK, 0o660)
    server.listen(32)
    try:
        while True:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(15)
                _serve(conn)
    finally:
        server.close()
        SOCK.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
