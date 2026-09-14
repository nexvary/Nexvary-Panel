from __future__ import annotations

import grp
import os
import re
import stat
import subprocess
from pathlib import Path

from webtools import (
    LOG_BASE,
    _atomic_write,
    _ensure_managed_include,
    _managed_dir,
    _run,
    _safe_regular,
    _site_root,
    _valid_domain,
)

SAFE_PATH_RE = re.compile(r"^/(?:[A-Za-z0-9._~-]+/)*[A-Za-z0-9._~-]*$")
SAFE_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SAFE_EXT_RE = re.compile(r"^[a-z0-9]{1,12}$")
SAFE_MIME_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,95}$")
BLOCKED_MIME_EXTENSIONS = frozenset({
    "php", "phtml", "phar", "cgi", "pl", "py", "sh", "bash", "zsh", "fish",
    "env", "ini", "conf", "config", "key", "pem", "crt", "csr", "htaccess", "htpasswd",
    "sql", "sqlite", "db", "bak", "backup", "log", "old", "swp",
})
AUTH_BASE = Path("/etc/nginx/nexvary-auth")
MAX_RAW_BYTES = 512 * 1024
MAX_RAW_LINES = 500


def _apply_include(domain: str, name: str, content: bytes | None) -> dict:
    domain = _valid_domain(domain)
    _site_root(domain)
    managed = _managed_dir(domain)
    include = managed / f"{name}.conf"
    old_include = include.read_bytes() if _safe_regular(include, required=False) else None
    conf, old_conf = _ensure_managed_include(domain)
    try:
        if content is None:
            include.unlink(missing_ok=True)
        else:
            _atomic_write(include, content, 0o640)
        if not _run(["nginx", "-t"]).get("ok"):
            raise RuntimeError("nginx-validation-failed")
        if not _run(["systemctl", "reload", "nginx"]).get("ok"):
            raise RuntimeError("nginx-reload-failed")
        return {"ok": True}
    except (OSError, RuntimeError):
        if old_include is None:
            include.unlink(missing_ok=True)
        else:
            _atomic_write(include, old_include, 0o640)
        if old_conf is not None:
            _atomic_write(conf, old_conf, 0o644)
        _run(["nginx", "-t"])
        _run(["systemctl", "reload", "nginx"])
        return {"ok": False, "error": "site control rejected; previous NGINX state restored"}


def _privacy_path(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid privacy path")
    value = value.strip()
    if not value.startswith("/") or len(value) > 180 or not SAFE_PATH_RE.fullmatch(value):
        raise ValueError("invalid privacy path")
    if value != "/" and not value.endswith("/"):
        value += "/"
    return value


def _password_hash(password: str) -> str:
    if len(password) < 12 or len(password) > 256:
        raise ValueError("password length rejected")
    try:
        proc = subprocess.run(
            ["openssl", "passwd", "-6", "-stdin"],
            input=password + "\n",
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("password hashing unavailable") from exc
    value = proc.stdout.strip()
    if proc.returncode != 0 or not value.startswith("$6$") or len(value) > 200:
        raise ValueError("password hashing failed")
    return value


def sync_directory_privacy(domain: str, *, enabled: bool, path: object = "/", username: object = None, password: object = None) -> dict:
    domain = _valid_domain(domain)
    _site_root(domain)
    auth_file = AUTH_BASE / f"{domain}.htpasswd"
    old_auth = auth_file.read_bytes() if _safe_regular(auth_file, required=False) else None
    if not enabled:
        result = _apply_include(domain, "directory-privacy", None)
        if result.get("ok"):
            auth_file.unlink(missing_ok=True)
        return result
    try:
        privacy_path = _privacy_path(path)
        if not isinstance(username, str) or not SAFE_USER_RE.fullmatch(username):
            raise ValueError("invalid privacy username")
        if not isinstance(password, str):
            raise ValueError("privacy password required")
        hashed = _password_hash(password)
        AUTH_BASE.mkdir(parents=True, exist_ok=True, mode=0o750)
        try:
            gid = grp.getgrnam("www-data").gr_gid
            os.chown(AUTH_BASE, 0, gid)
        except KeyError:
            gid = 0
        os.chmod(AUTH_BASE, 0o750)
        _atomic_write(auth_file, f"{username}:{hashed}\n".encode(), 0o640)
        os.chown(auth_file, 0, gid)
        if privacy_path == "/":
            body = (
                "# Managed by Nexvary Panel Site Control Center.\n"
                "auth_basic \"Restricted by Nexvary Panel\";\n"
                f"auth_basic_user_file {auth_file};\n"
            )
        else:
            body = (
                "# Managed by Nexvary Panel Site Control Center.\n"
                f"location ^~ {privacy_path} {{\n"
                "  auth_basic \"Restricted by Nexvary Panel\";\n"
                f"  auth_basic_user_file {auth_file};\n"
                "}\n"
            )
        result = _apply_include(domain, "directory-privacy", body.encode())
        if not result.get("ok"):
            if old_auth is None:
                auth_file.unlink(missing_ok=True)
            else:
                _atomic_write(auth_file, old_auth, 0o640)
                os.chown(auth_file, 0, gid)
        return result
    except (OSError, ValueError):
        if old_auth is None:
            auth_file.unlink(missing_ok=True)
        else:
            _atomic_write(auth_file, old_auth, 0o640)
        return {"ok": False, "error": "directory privacy synchronization failed"}


def sync_hotlink(domain: str, *, enabled: bool, extensions: object) -> dict:
    domain = _valid_domain(domain)
    if not enabled:
        return _apply_include(domain, "hotlink-protection", None)
    if not isinstance(extensions, list) or not 1 <= len(extensions) <= 24:
        return {"ok": False, "error": "invalid hotlink extension set"}
    normalized: list[str] = []
    for item in extensions:
        value = str(item).strip().lower().lstrip(".")
        if not SAFE_EXT_RE.fullmatch(value):
            return {"ok": False, "error": "invalid hotlink extension"}
        if value not in normalized:
            normalized.append(value)
    pattern = "|".join(re.escape(value) for value in normalized)
    body = (
        "# Managed by Nexvary Panel Site Control Center.\n"
        f"location ~* \\.({pattern})$ {{\n"
        f"  valid_referers none blocked server_names {domain} *.{domain};\n"
        "  if ($invalid_referer) { return 403; }\n"
        "}\n"
    )
    return _apply_include(domain, "hotlink-protection", body.encode())


def sync_indexing(domain: str, *, mode: object) -> dict:
    domain = _valid_domain(domain)
    if mode not in {"on", "off"}:
        return {"ok": False, "error": "invalid indexing mode"}
    body = f"# Managed by Nexvary Panel Site Control Center.\nautoindex {mode};\n".encode()
    return _apply_include(domain, "directory-indexing", body)


def sync_mime_overrides(domain: str, *, mappings: object) -> dict:
    domain = _valid_domain(domain)
    if not isinstance(mappings, dict) or len(mappings) > 24:
        return {"ok": False, "error": "invalid MIME mapping set"}
    normalized: list[tuple[str, str]] = []
    for extension, mime in mappings.items():
        ext = str(extension).strip().lower().lstrip(".")
        mtype = str(mime).strip().lower()
        if not SAFE_EXT_RE.fullmatch(ext) or not SAFE_MIME_RE.fullmatch(mtype):
            return {"ok": False, "error": "invalid MIME mapping"}
        if ext in BLOCKED_MIME_EXTENSIONS:
            return {"ok": False, "error": "sensitive or executable extensions cannot be remapped"}
        normalized.append((ext, mtype))
    if not normalized:
        return _apply_include(domain, "mime-overrides", None)
    lines = ["# Managed by Nexvary Panel Site Control Center."]
    for ext, mtype in sorted(normalized):
        lines.extend([
            f"location ~* \\.{re.escape(ext)}$ {{",
            "  types { }",
            f"  default_type {mtype};",
            "}",
        ])
    return _apply_include(domain, "mime-overrides", ("\n".join(lines) + "\n").encode())


def raw_access(domain: str, *, lines: object = 200) -> dict:
    domain = _valid_domain(domain)
    _site_root(domain)
    try:
        limit = max(1, min(MAX_RAW_LINES, int(lines)))
    except (TypeError, ValueError):
        limit = 200
    path = LOG_BASE / f"{domain}.access.log"
    try:
        if not _safe_regular(path, required=False):
            return {"ok": True, "lines": [], "truncated": False}
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise OSError("unsafe log")
        size = st.st_size
        with path.open("rb") as handle:
            if size > MAX_RAW_BYTES:
                handle.seek(size - MAX_RAW_BYTES)
                handle.readline()
            data = handle.read(MAX_RAW_BYTES)
        rows = data.decode("utf-8", errors="replace").splitlines()[-limit:]
        return {"ok": True, "lines": rows, "truncated": size > MAX_RAW_BYTES or len(rows) >= limit}
    except OSError:
        return {"ok": False, "error": "raw access log unavailable"}
