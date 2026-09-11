#!/usr/bin/env python3
from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import re
import socket
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

SOCK = Path(os.environ.get("NVP_WORDPRESS_SOCK", "/run/nexvary-panel/wordpress.sock"))
SITE_BASE = Path(os.environ.get("NVP_SITE_BASE", "/var/www"))
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
VERSION_RE = re.compile(r"^[0-9]{1,2}\.[0-9]{1,2}(?:\.[0-9]{1,3})?$|^[0-9]{1,2}\.[0-9]{1,2}(?:\.[0-9]{1,3})?-[A-Za-z0-9.-]{1,20}$")
MAX_REQUEST = 64 * 1024
MAX_REPLY = 512 * 1024
MAX_HTTP = 3 * 1024 * 1024
MAX_CHECKSUM_FILES = 20000
MAX_ISSUES = 100
MAX_CORE_FILE = 32 * 1024 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _domain(value: object) -> str:
    domain = str(value or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("invalid-domain")
    return domain


def _wordpress_root(domain: str) -> Path:
    root = SITE_BASE / _domain(domain) / "public"
    try:
        resolved_base = SITE_BASE.resolve()
        resolved = root.resolve()
    except OSError as exc:
        raise ValueError("wordpress-root-unavailable") from exc
    if not root.is_dir() or root.is_symlink() or os.path.commonpath((str(resolved_base), str(resolved))) != str(resolved_base):
        raise ValueError("wordpress-root-unavailable")
    if not (root / "wp-includes" / "version.php").is_file() or (root / "wp-includes" / "version.php").is_symlink():
        raise ValueError("wordpress-not-detected")
    return root


def _read_text(path: Path, limit: int = 256 * 1024) -> str:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > limit:
        raise ValueError("unsafe-wordpress-file")
    return path.read_text(encoding="utf-8", errors="replace")


def _version(root: Path) -> str:
    text = _read_text(root / "wp-includes" / "version.php")
    match = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", text)
    version = match.group(1).strip() if match else ""
    if not VERSION_RE.fullmatch(version):
        raise ValueError("wordpress-version-not-detected")
    return version


def _component_inventory(base: Path, *, kind: str) -> list[dict]:
    if not base.is_dir() or base.is_symlink():
        return []
    rows: list[dict] = []
    for entry in sorted(base.iterdir(), key=lambda p: p.name.lower())[:500]:
        if entry.name.startswith(".") or entry.is_symlink():
            continue
        if entry.is_dir():
            name = entry.name[:120]
            version = ""
            if kind == "theme":
                header = entry / "style.css"
            else:
                header = entry / f"{entry.name}.php"
                if not header.is_file():
                    candidates = [p for p in entry.glob("*.php") if p.is_file() and not p.is_symlink()][:20]
                    header = candidates[0] if candidates else Path("")
            if header and header.is_file() and not header.is_symlink() and header.stat().st_size <= 512 * 1024:
                text = header.read_text(encoding="utf-8", errors="replace")[:32 * 1024]
                match = re.search(r"(?im)^\s*Version:\s*([^\r\n]+)", text)
                version = match.group(1).strip()[:80] if match else ""
            rows.append({"slug": name, "version": version})
        elif kind == "plugin" and entry.is_file() and entry.suffix == ".php" and entry.stat().st_size <= 512 * 1024:
            text = entry.read_text(encoding="utf-8", errors="replace")[:32 * 1024]
            match = re.search(r"(?im)^\s*Version:\s*([^\r\n]+)", text)
            rows.append({"slug": entry.stem[:120], "version": match.group(1).strip()[:80] if match else ""})
    return rows


def inventory(domain: str) -> dict:
    domain = _domain(domain)
    root = _wordpress_root(domain)
    version = _version(root)
    maintenance_path = root / ".maintenance"
    maintenance = maintenance_path.is_file() and not maintenance_path.is_symlink()
    config = root / "wp-config.php"
    plugins = _component_inventory(root / "wp-content" / "plugins", kind="plugin")
    themes = _component_inventory(root / "wp-content" / "themes", kind="theme")
    return {
        "ok": True,
        "domain": domain,
        "version": version,
        "maintenance": maintenance,
        "config_present": config.is_file() and not config.is_symlink(),
        "plugins": plugins,
        "themes": themes,
        "plugin_count": len(plugins),
        "theme_count": len(themes),
    }


def _wp_api(path: str, params: dict[str, str]) -> dict:
    if not path.startswith("/") or ".." in path:
        raise RuntimeError("wordpress-api-invalid-path")
    query = urllib.parse.urlencode(params)
    url = "https://api.wordpress.org" + path + ("?" + query if query else "")
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "Nexvary-Panel/0.7"})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=12) as response:
            parsed = urllib.parse.urlsplit(response.geturl())
            if response.status != 200 or parsed.scheme != "https" or parsed.hostname != "api.wordpress.org":
                raise RuntimeError("wordpress-api-unavailable")
            raw = response.read(MAX_HTTP + 1)
    except Exception as exc:
        raise RuntimeError("wordpress-api-unavailable") from exc
    if len(raw) > MAX_HTTP:
        raise RuntimeError("wordpress-api-response-too-large")
    try:
        body = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("wordpress-api-invalid-response") from exc
    if not isinstance(body, dict):
        raise RuntimeError("wordpress-api-invalid-response")
    return body


def _safe_checksum_path(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts or pure.parts[0] == "wp-content":
        raise ValueError("unsafe-checksum-path")
    target = root.joinpath(*pure.parts)
    if target.is_symlink():
        raise ValueError("wordpress-core-symlink-detected")
    try:
        resolved_root = root.resolve()
        resolved = target.resolve(strict=False)
        if os.path.commonpath((str(resolved_root), str(resolved))) != str(resolved_root):
            raise ValueError("unsafe-checksum-path")
    except OSError as exc:
        raise ValueError("unsafe-checksum-path") from exc
    return target


def _md5_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_CORE_FILE:
        raise ValueError("unsafe-wordpress-core-file")
    digest = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def integrity(domain: str) -> dict:
    domain = _domain(domain)
    root = _wordpress_root(domain)
    version = _version(root)
    body = _wp_api("/core/checksums/1.0/", {"version": version, "locale": "en_US"})
    checksums = body.get("checksums")
    if not isinstance(checksums, dict) or not checksums or len(checksums) > MAX_CHECKSUM_FILES:
        raise RuntimeError("wordpress-checksum-catalog-invalid")
    checked = 0
    missing: list[str] = []
    mismatched: list[str] = []
    for relative, expected in checksums.items():
        if not isinstance(relative, str) or not isinstance(expected, str) or not re.fullmatch(r"[a-fA-F0-9]{32}", expected):
            continue
        if relative.startswith("wp-content/"):
            continue
        target = _safe_checksum_path(root, relative)
        checked += 1
        if not target.is_file():
            if len(missing) < MAX_ISSUES:
                missing.append(relative[:300])
            continue
        try:
            digest = _md5_file(target)
        except ValueError:
            if len(mismatched) < MAX_ISSUES:
                mismatched.append(relative[:300])
            continue
        if digest.lower() != expected.lower() and len(mismatched) < MAX_ISSUES:
            mismatched.append(relative[:300])
    return {
        "ok": True,
        "domain": domain,
        "version": version,
        "checked": checked,
        "missing": missing,
        "mismatched": mismatched,
        "integrity_ok": not missing and not mismatched,
        "source": "api.wordpress.org/core/checksums",
    }


def maintenance(domain: str, enabled: bool) -> dict:
    domain = _domain(domain)
    if not isinstance(enabled, bool):
        raise ValueError("maintenance-enabled-must-be-boolean")
    root = _wordpress_root(domain)
    path = root / ".maintenance"
    if path.is_symlink():
        raise ValueError("unsafe-maintenance-file")
    if enabled:
        data = f"<?php $upgrading = {int(time.time())}; ?>\n".encode("utf-8")
        fd, tmp_name = tempfile.mkstemp(prefix=".nvp-maintenance-", dir=str(root))
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                account = pwd.getpwnam("www-data")
                os.chown(tmp, account.pw_uid, account.pw_gid)
            except KeyError:
                pass
            os.chmod(tmp, 0o640)
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)
    else:
        path.unlink(missing_ok=True)
    return {"ok": True, "domain": domain, "maintenance": enabled}


def dispatch(req: dict) -> dict:
    action = str(req.get("action", ""))
    if action == "status":
        return {"ok": True, "engine": "wordpress-lifecycle", "capabilities": {"inventory": True, "integrity": True, "maintenance": True}}
    if action == "inventory":
        return inventory(req.get("domain", ""))
    if action == "integrity":
        return integrity(req.get("domain", ""))
    if action == "maintenance":
        return maintenance(req.get("domain", ""), req.get("enabled"))
    return {"ok": False, "error": "action-not-allowed"}


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
    os.chown(SOCK, 0, grp.getgrnam("nexvary-panel").gr_gid)
    os.chmod(SOCK, 0o660)
    server.listen(24)
    while True:
        conn, _ = server.accept()
        with conn:
            conn.settimeout(45)
            try:
                raw = b""
                while not raw.endswith(b"\n") and len(raw) <= MAX_REQUEST:
                    chunk = conn.recv(8192)
                    if not chunk:
                        break
                    raw += chunk
                if not raw.endswith(b"\n") or len(raw) > MAX_REQUEST:
                    raise ValueError("request-too-large")
                req = json.loads(raw.decode("utf-8"))
                if not isinstance(req, dict):
                    raise ValueError("object-required")
                result = dispatch(req)
            except ValueError as exc:
                result = {"ok": False, "error": str(exc)[:180]}
            except Exception as exc:
                result = {"ok": False, "error": (str(exc) or "wordpress-operation-failed")[:180]}
            payload = (json.dumps(result, separators=(",", ":")) + "\n").encode("utf-8")
            if len(payload) > MAX_REPLY:
                payload = b'{"ok":false,"error":"response-too-large"}\n'
            conn.sendall(payload)


if __name__ == "__main__":
    main()
