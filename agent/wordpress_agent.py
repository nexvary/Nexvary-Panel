#!/usr/bin/env python3
from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import socket
import stat
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

SOCK = Path(os.environ.get("NVP_WORDPRESS_SOCK", "/run/nexvary-panel/wordpress.sock"))
SITE_BASE = Path(os.environ.get("NVP_SITE_BASE", "/var/www"))
BACKUP_BASE = Path(os.environ.get("NVP_WORDPRESS_BACKUP_BASE", "/var/backups/nexvary-panel/wordpress"))
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
VERSION_RE = re.compile(r"^[0-9]{1,2}\.[0-9]{1,2}(?:\.[0-9]{1,3})?$|^[0-9]{1,2}\.[0-9]{1,2}(?:\.[0-9]{1,3})?-[A-Za-z0-9.-]{1,20}$")
SNAPSHOT_RE = re.compile(r"^[0-9]{10}-[a-f0-9]{8}$")
MAX_REQUEST = 64 * 1024
MAX_REPLY = 512 * 1024
MAX_HTTP = 3 * 1024 * 1024
MAX_RELEASE = 120 * 1024 * 1024
MAX_EXTRACTED = 300 * 1024 * 1024
MAX_CHECKSUM_FILES = 20000
MAX_ARCHIVE_MEMBERS = 30000
MAX_ISSUES = 100
MAX_CORE_FILE = 32 * 1024 * 1024
TRUSTED_RELEASE_HOSTS = {"wordpress.org", "downloads.wordpress.org"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != "https" or parsed.hostname not in TRUSTED_RELEASE_HOSTS:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


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
    version_file = root / "wp-includes" / "version.php"
    if not version_file.is_file() or version_file.is_symlink():
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


def _checksum_catalog(version: str) -> dict[str, str]:
    body = _wp_api("/core/checksums/1.0/", {"version": version, "locale": "en_US"})
    checksums = body.get("checksums")
    if not isinstance(checksums, dict) or not checksums or len(checksums) > MAX_CHECKSUM_FILES:
        raise RuntimeError("wordpress-checksum-catalog-invalid")
    out: dict[str, str] = {}
    for relative, expected in checksums.items():
        if isinstance(relative, str) and isinstance(expected, str) and re.fullmatch(r"[a-fA-F0-9]{32}", expected):
            out[relative] = expected.lower()
    if not out:
        raise RuntimeError("wordpress-checksum-catalog-invalid")
    return out


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


def _integrity_with_catalog(domain: str, root: Path, version: str, checksums: dict[str, str]) -> dict:
    checked = 0
    missing: list[str] = []
    mismatched: list[str] = []
    missing_count = 0
    mismatched_count = 0
    for relative, expected in checksums.items():
        if relative.startswith("wp-content/"):
            continue
        target = _safe_checksum_path(root, relative)
        checked += 1
        if not target.is_file():
            missing_count += 1
            if len(missing) < MAX_ISSUES:
                missing.append(relative[:300])
            continue
        try:
            digest = _md5_file(target)
        except ValueError:
            digest = ""
        if digest.lower() != expected.lower():
            mismatched_count += 1
            if len(mismatched) < MAX_ISSUES:
                mismatched.append(relative[:300])
    return {
        "ok": True,
        "domain": domain,
        "version": version,
        "checked": checked,
        "missing": missing,
        "mismatched": mismatched,
        "missing_count": missing_count,
        "mismatched_count": mismatched_count,
        "truncated": missing_count > len(missing) or mismatched_count > len(mismatched),
        "integrity_ok": missing_count == 0 and mismatched_count == 0,
        "source": "api.wordpress.org/core/checksums",
    }


def integrity(domain: str) -> dict:
    domain = _domain(domain)
    root = _wordpress_root(domain)
    version = _version(root)
    return _integrity_with_catalog(domain, root, version, _checksum_catalog(version))


def _download_release(version: str, destination: Path) -> Path:
    if not VERSION_RE.fullmatch(version):
        raise ValueError("invalid-wordpress-version")
    url = f"https://wordpress.org/wordpress-{urllib.parse.quote(version, safe='.-')}.tar.gz"
    req = urllib.request.Request(url, headers={"Accept": "application/gzip,application/octet-stream", "User-Agent": "Nexvary-Panel/0.7"})
    opener = urllib.request.build_opener(_ReleaseRedirect())
    archive = destination / "wordpress.tar.gz"
    total = 0
    try:
        with opener.open(req, timeout=30) as response, archive.open("wb") as out:
            parsed = urllib.parse.urlsplit(response.geturl())
            if response.status != 200 or parsed.scheme != "https" or parsed.hostname not in TRUSTED_RELEASE_HOSTS:
                raise RuntimeError("wordpress-release-unavailable")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_RELEASE:
                    raise RuntimeError("wordpress-release-too-large")
                out.write(chunk)
    except Exception as exc:
        archive.unlink(missing_ok=True)
        raise RuntimeError("wordpress-release-unavailable") from exc
    if total < 1024:
        archive.unlink(missing_ok=True)
        raise RuntimeError("wordpress-release-invalid")
    return archive


def _extract_release(archive: Path, destination: Path) -> Path:
    extracted_total = 0
    count = 0
    try:
        with tarfile.open(archive, "r:gz") as tf:
            for member in tf.getmembers():
                count += 1
                if count > MAX_ARCHIVE_MEMBERS:
                    raise RuntimeError("wordpress-release-too-many-files")
                pure = PurePosixPath(member.name)
                if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] != "wordpress":
                    raise RuntimeError("wordpress-release-unsafe-path")
                if member.issym() or member.islnk() or member.isdev() or not (member.isdir() or member.isfile()):
                    raise RuntimeError("wordpress-release-unsafe-member")
                if member.isfile():
                    if member.size < 0 or member.size > MAX_CORE_FILE:
                        raise RuntimeError("wordpress-release-unsafe-file")
                    extracted_total += member.size
                    if extracted_total > MAX_EXTRACTED:
                        raise RuntimeError("wordpress-release-too-large")
            tf.extractall(destination, filter="data")
    except (tarfile.TarError, OSError) as exc:
        raise RuntimeError("wordpress-release-invalid") from exc
    root = destination / "wordpress"
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError("wordpress-release-invalid")
    return root


def _atomic_copy(source: Path, target: Path, *, mode: int, uid: int, gid: int) -> None:
    if not source.is_file() or source.is_symlink() or source.stat().st_size > MAX_CORE_FILE:
        raise ValueError("unsafe-wordpress-release-file")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        raise ValueError("wordpress-core-symlink-detected")
    fd, tmp_name = tempfile.mkstemp(prefix=".nvp-core-", dir=str(target.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as out, source.open("rb") as inp:
            shutil.copyfileobj(inp, out, length=1024 * 1024)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(tmp, mode & 0o777)
        os.chown(tmp, uid, gid)
        os.replace(tmp, target)
    finally:
        tmp.unlink(missing_ok=True)


def _snapshot_dir(domain: str) -> tuple[str, Path]:
    snapshot_id = f"{int(time.time()):010d}-{os.urandom(4).hex()}"
    base = BACKUP_BASE / _domain(domain)
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(base, 0o700)
    target = base / snapshot_id
    target.mkdir(mode=0o700)
    return snapshot_id, target


def _rollback_snapshot(root: Path, snapshot: Path, manifest: dict) -> None:
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise RuntimeError("wordpress-snapshot-invalid")
    for item in entries:
        if not isinstance(item, dict):
            raise RuntimeError("wordpress-snapshot-invalid")
        relative = str(item.get("path", ""))
        target = _safe_checksum_path(root, relative)
        existed = bool(item.get("existed"))
        if existed:
            source = snapshot / "files" / Path(*PurePosixPath(relative).parts)
            _atomic_copy(source, target, mode=int(item["mode"]), uid=int(item["uid"]), gid=int(item["gid"]))
        else:
            if target.is_symlink():
                raise RuntimeError("wordpress-core-symlink-detected")
            target.unlink(missing_ok=True)


def repair_core(domain: str) -> dict:
    domain = _domain(domain)
    root = _wordpress_root(domain)
    version = _version(root)
    checksums = _checksum_catalog(version)
    before = _integrity_with_catalog(domain, root, version, checksums)
    if before["integrity_ok"]:
        return {"ok": True, "domain": domain, "version": version, "repaired": 0, "snapshot_id": "", "integrity_ok": True, "detail": "core-already-clean"}
    if before["truncated"]:
        return {"ok": False, "error": "wordpress-core-has-too-many-integrity-issues"}
    issues = sorted(set(before["missing"] + before["mismatched"]))
    if not issues or len(issues) > MAX_ISSUES:
        return {"ok": False, "error": "wordpress-core-repair-scope-invalid"}

    snapshot_id, snapshot = _snapshot_dir(domain)
    manifest = {"domain": domain, "version": version, "created_at": int(time.time()), "entries": []}
    try:
        with tempfile.TemporaryDirectory(prefix="nvp-wp-release-") as tmp_name:
            tmp = Path(tmp_name)
            archive = _download_release(version, tmp)
            release_root = _extract_release(archive, tmp / "extract")
            if _version(release_root) != version:
                raise RuntimeError("wordpress-release-version-mismatch")
            files_root = snapshot / "files"
            files_root.mkdir(mode=0o700)
            root_stat = root.stat()
            for relative in issues:
                expected = checksums.get(relative)
                if not expected or relative.startswith("wp-content/") or relative == "wp-config.php":
                    raise RuntimeError("wordpress-core-repair-scope-invalid")
                source = release_root.joinpath(*PurePosixPath(relative).parts)
                if not source.is_file() or source.is_symlink() or _md5_file(source).lower() != expected.lower():
                    raise RuntimeError("wordpress-release-checksum-mismatch")
                target = _safe_checksum_path(root, relative)
                existed = target.is_file()
                if target.exists() and not existed:
                    raise RuntimeError("unsafe-wordpress-core-file")
                if existed:
                    st = target.stat()
                    saved = files_root.joinpath(*PurePosixPath(relative).parts)
                    saved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    shutil.copy2(target, saved)
                    entry = {"path": relative, "existed": True, "mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid, "gid": st.st_gid}
                    mode, uid, gid = stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid
                else:
                    entry = {"path": relative, "existed": False, "mode": 0o644, "uid": root_stat.st_uid, "gid": root_stat.st_gid}
                    mode, uid, gid = 0o644, root_stat.st_uid, root_stat.st_gid
                manifest["entries"].append(entry)
                _atomic_copy(source, target, mode=mode, uid=uid, gid=gid)
            (snapshot / "manifest.json").write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
            os.chmod(snapshot / "manifest.json", 0o600)
        after = _integrity_with_catalog(domain, root, version, checksums)
        if not after["integrity_ok"]:
            _rollback_snapshot(root, snapshot, manifest)
            return {"ok": False, "error": "wordpress-core-repair-validation-failed-rolled-back"}
        return {"ok": True, "domain": domain, "version": version, "repaired": len(issues), "snapshot_id": snapshot_id, "integrity_ok": True}
    except Exception:
        try:
            if manifest["entries"]:
                _rollback_snapshot(root, snapshot, manifest)
        finally:
            shutil.rmtree(snapshot, ignore_errors=True)
        raise


def rollback_repair(domain: str, snapshot_id: str) -> dict:
    domain = _domain(domain)
    if not SNAPSHOT_RE.fullmatch(str(snapshot_id or "")):
        raise ValueError("invalid-wordpress-snapshot")
    root = _wordpress_root(domain)
    snapshot = BACKUP_BASE / domain / snapshot_id
    try:
        resolved_base = (BACKUP_BASE / domain).resolve()
        resolved = snapshot.resolve()
    except OSError as exc:
        raise ValueError("wordpress-snapshot-not-found") from exc
    if os.path.commonpath((str(resolved_base), str(resolved))) != str(resolved_base) or not snapshot.is_dir() or snapshot.is_symlink():
        raise ValueError("wordpress-snapshot-not-found")
    manifest_path = snapshot / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink() or manifest_path.stat().st_size > 256 * 1024:
        raise ValueError("wordpress-snapshot-invalid")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("domain") != domain:
        raise ValueError("wordpress-snapshot-domain-mismatch")
    _rollback_snapshot(root, snapshot, manifest)
    return {"ok": True, "domain": domain, "snapshot_id": snapshot_id, "rolled_back": len(manifest.get("entries") or [])}


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
        return {"ok": True, "engine": "wordpress-lifecycle", "capabilities": {"inventory": True, "integrity": True, "maintenance": True, "core_repair": True, "repair_rollback": True}}
    if action == "inventory":
        return inventory(req.get("domain", ""))
    if action == "integrity":
        return integrity(req.get("domain", ""))
    if action == "maintenance":
        return maintenance(req.get("domain", ""), req.get("enabled"))
    if action == "repair-core":
        return repair_core(req.get("domain", ""))
    if action == "repair-rollback":
        return rollback_repair(req.get("domain", ""), str(req.get("snapshot_id", "")))
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
            conn.settimeout(90)
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
