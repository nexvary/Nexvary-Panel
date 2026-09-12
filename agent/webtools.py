from __future__ import annotations

import os
import pwd
import grp
import re
import stat
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
SOURCE_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!&'()*+,=:@%/\-]{0,200}$")
LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<date>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) [^"]+" (?P<status>\d{3}) (?P<bytes>\d+|-) '
)
ALLOWED_REDIRECT_CODES = {301, 302, 307, 308}
ALLOWED_ERROR_CODES = {400, 401, 403, 404, 405, 408, 410, 429, 500, 502, 503, 504}
NGINX_BASE = Path("/etc/nginx/sites-available")
MANAGED_BASE = Path("/etc/nginx/nexvary")
SITE_BASE = Path("/var/www")
LOG_BASE = Path("/var/log/nginx")
MAX_SITE_CONF = 1024 * 1024
MAX_ERROR_HTML = 64 * 1024
MAX_RULES = 100
MAX_LOG_READ = 4 * 1024 * 1024


def _valid_domain(domain: object) -> str:
    if not isinstance(domain, str) or not DOMAIN_RE.fullmatch(domain):
        raise ValueError("invalid domain")
    return domain


def _safe_regular(path: Path, *, required: bool = True) -> bool:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if required:
            raise ValueError("required file not found")
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ValueError("unsafe file type")
    return True


def _site_root(domain: str) -> Path:
    domain = _valid_domain(domain)
    root = SITE_BASE / domain
    try:
        st = os.lstat(root)
    except FileNotFoundError as exc:
        raise ValueError("site root not found") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise ValueError("unsafe site root")
    return root


def _run(args: list[str], timeout: int = 25) -> dict:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError):
        return {"ok": False, "error": "web configuration validation failed"}
    if proc.returncode:
        return {"ok": False, "error": "web configuration validation failed"}
    return {"ok": True}


def _atomic_write(path: Path, data: bytes, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        os.chmod(path, mode)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _restore_optional(path: Path, content: bytes | None, mode: int) -> None:
    if content is None:
        path.unlink(missing_ok=True)
    else:
        _atomic_write(path, content, mode)


def _managed_dir(domain: str) -> Path:
    domain = _valid_domain(domain)
    target = MANAGED_BASE / domain
    target.mkdir(parents=True, exist_ok=True, mode=0o750)
    try:
        st = os.lstat(target)
    except OSError as exc:
        raise ValueError("managed web directory unavailable") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise ValueError("unsafe managed web directory")
    os.chmod(target, 0o750)
    return target


def _ensure_managed_include(domain: str) -> tuple[Path, bytes | None]:
    domain = _valid_domain(domain)
    conf = NGINX_BASE / f"{domain}.conf"
    _safe_regular(conf)
    raw = conf.read_bytes()
    if len(raw) > MAX_SITE_CONF:
        raise ValueError("site configuration is unexpectedly large")
    include = f"include /etc/nginx/nexvary/{domain}/*.conf;".encode()
    if include in raw:
        return conf, None
    idx = raw.rfind(b"}")
    if idx < 0:
        raise ValueError("site configuration is malformed")
    updated = raw[:idx] + b"\n    # NEXVARY-MANAGED-INCLUDES\n    " + include + b"\n" + raw[idx:]
    _atomic_write(conf, updated, 0o644)
    return conf, raw


def _restore(path: Path, content: bytes | None) -> None:
    if content is not None:
        _atomic_write(path, content, 0o644)


def _rollback_nginx(conf: Path, old_conf: bytes | None, include_file: Path, old_include: bytes | None,
                    extra_restore=None) -> None:
    _restore(conf, old_conf)
    _restore_optional(include_file, old_include, 0o640)
    if extra_restore is not None:
        extra_restore()
    _run(["nginx", "-t"])
    _run(["systemctl", "reload", "nginx"])


def _safe_redirect_target(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid redirect target")
    value = value.strip()
    if not value or len(value) > 1200 or any(ch in value for ch in "\r\n\t ;{}\\\"'$"):
        raise ValueError("unsafe redirect target")
    if value.startswith("/"):
        if not SOURCE_PATH_RE.fullmatch(value):
            raise ValueError("invalid relative redirect target")
        return value
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise ValueError("invalid redirect target") from exc
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError("redirect target must be an HTTP(S) URL or absolute path")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", parts.hostname):
        raise ValueError("invalid redirect host")
    return value


def _validate_source(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid source path")
    value = value.strip()
    if not SOURCE_PATH_RE.fullmatch(value) or any(ch in value for ch in ";{}\\\"$"):
        raise ValueError("invalid source path")
    return value


def sync_redirects(domain: str, rules: object) -> dict:
    domain = _valid_domain(domain)
    _site_root(domain)
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        return {"ok": False, "error": "invalid redirect rule set"}
    normalized: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    try:
        for item in rules:
            if not isinstance(item, dict):
                raise ValueError("invalid redirect rule")
            source = _validate_source(item.get("source_path"))
            target = _safe_redirect_target(item.get("target"))
            code = int(item.get("status_code", 301))
            if code not in ALLOWED_REDIRECT_CODES or source in seen:
                raise ValueError("invalid or duplicate redirect rule")
            seen.add(source)
            normalized.append((source, target, code))
    except (ValueError, TypeError):
        return {"ok": False, "error": "redirect validation failed"}

    try:
        managed = _managed_dir(domain)
        include_file = managed / "redirects.conf"
        old_include = include_file.read_bytes() if _safe_regular(include_file, required=False) else None
        conf, old_conf = _ensure_managed_include(domain)
        lines = ["# Managed by Nexvary Panel. Do not edit manually."]
        for source, target, code in normalized:
            lines.append(f"location = {source} {{ return {code} {target}; }}")
        _atomic_write(include_file, ("\n".join(lines) + "\n").encode(), 0o640)
        test = _run(["nginx", "-t"])
        if not test.get("ok"):
            _rollback_nginx(conf, old_conf, include_file, old_include)
            return {"ok": False, "error": "redirect configuration rejected; previous configuration restored"}
        reload_result = _run(["systemctl", "reload", "nginx"])
        if not reload_result.get("ok"):
            _rollback_nginx(conf, old_conf, include_file, old_include)
            return {"ok": False, "error": "NGINX reload failed; previous redirect configuration restored"}
        return {"ok": True, "meta": {"rules": len(normalized)}}
    except (OSError, ValueError):
        return {"ok": False, "error": "redirect synchronization failed"}


def sync_error_pages(domain: str, pages: object) -> dict:
    domain = _valid_domain(domain)
    root = _site_root(domain)
    if not isinstance(pages, list) or len(pages) > len(ALLOWED_ERROR_CODES):
        return {"ok": False, "error": "invalid error page set"}
    normalized: dict[int, str] = {}
    try:
        for item in pages:
            if not isinstance(item, dict):
                raise ValueError("invalid error page")
            code = int(item.get("status_code"))
            html = item.get("html")
            if code not in ALLOWED_ERROR_CODES or not isinstance(html, str) or len(html.encode("utf-8")) > MAX_ERROR_HTML:
                raise ValueError("invalid error page")
            normalized[code] = html
    except (ValueError, TypeError):
        return {"ok": False, "error": "error page validation failed"}

    try:
        managed = _managed_dir(domain)
        include_file = managed / "error-pages.conf"
        old_include = include_file.read_bytes() if _safe_regular(include_file, required=False) else None
        conf, old_conf = _ensure_managed_include(domain)
        error_dir = root / ".nexvary-errors"
        if error_dir.exists() or error_dir.is_symlink():
            st = os.lstat(error_dir)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise ValueError("unsafe error page directory")
        else:
            error_dir.mkdir(mode=0o750)
        uid, gid = pwd.getpwnam("www-data").pw_uid, grp.getgrnam("www-data").gr_gid
        os.chown(error_dir, uid, gid)
        os.chmod(error_dir, 0o750)
        old_pages: dict[int, bytes | None] = {}
        for code in ALLOWED_ERROR_CODES:
            path = error_dir / f"{code}.html"
            old_pages[code] = path.read_bytes() if _safe_regular(path, required=False) else None

        def restore_pages() -> None:
            for restore_code, content in old_pages.items():
                path = error_dir / f"{restore_code}.html"
                _restore_optional(path, content, 0o640)
                if content is not None:
                    os.chown(path, uid, gid)

        for code in ALLOWED_ERROR_CODES:
            path = error_dir / f"{code}.html"
            if code in normalized:
                _atomic_write(path, normalized[code].encode("utf-8"), 0o640)
                os.chown(path, uid, gid)
            else:
                path.unlink(missing_ok=True)

        lines = ["# Managed by Nexvary Panel. Do not edit manually."]
        if normalized:
            lines.append(f"location ^~ /__nvp_errors/ {{ internal; alias /var/www/{domain}/.nexvary-errors/; }}")
            for code in sorted(normalized):
                lines.append(f"error_page {code} /__nvp_errors/{code}.html;")
        _atomic_write(include_file, ("\n".join(lines) + "\n").encode(), 0o640)
        test = _run(["nginx", "-t"])
        if not test.get("ok"):
            _rollback_nginx(conf, old_conf, include_file, old_include, restore_pages)
            return {"ok": False, "error": "error page configuration rejected; previous state restored"}
        reload_result = _run(["systemctl", "reload", "nginx"])
        if not reload_result.get("ok"):
            _rollback_nginx(conf, old_conf, include_file, old_include, restore_pages)
            return {"ok": False, "error": "NGINX reload failed; previous error-page state restored"}
        return {"ok": True, "meta": {"pages": len(normalized)}}
    except (OSError, ValueError):
        return {"ok": False, "error": "error page synchronization failed"}


def site_metrics(domain: str) -> dict:
    domain = _valid_domain(domain)
    _site_root(domain)
    log = LOG_BASE / f"{domain}.access.log"
    try:
        if not _safe_regular(log, required=False):
            return {"ok": True, "metrics": {"requests": 0, "visitors": 0, "bandwidth_bytes": 0, "status": {}, "methods": {}, "top_paths": []}}
        size = log.stat().st_size
        with log.open("rb") as handle:
            if size > MAX_LOG_READ:
                handle.seek(size - MAX_LOG_READ)
                handle.readline()
            raw = handle.read(MAX_LOG_READ)
    except OSError:
        return {"ok": False, "error": "metrics log unavailable"}

    visitors: set[str] = set()
    statuses: Counter[str] = Counter()
    methods: Counter[str] = Counter()
    paths: Counter[str] = Counter()
    bandwidth = 0
    requests = 0
    for line in raw.decode("utf-8", errors="replace").splitlines()[-20000:]:
        match = LOG_RE.match(line)
        if not match:
            continue
        requests += 1
        visitors.add(match.group("ip"))
        statuses[match.group("status")] += 1
        methods[match.group("method")[:10]] += 1
        path = match.group("path").split("?", 1)[0][:240]
        if path.startswith("/"):
            paths[path] += 1
        byte_text = match.group("bytes")
        if byte_text.isdigit():
            bandwidth += int(byte_text)
    return {
        "ok": True,
        "metrics": {
            "requests": requests,
            "visitors": len(visitors),
            "bandwidth_bytes": bandwidth,
            "status": dict(statuses.most_common()),
            "methods": dict(methods.most_common()),
            "top_paths": [{"path": path, "requests": count} for path, count in paths.most_common(10)],
            "sample_scope": "latest-log-window",
        },
    }
