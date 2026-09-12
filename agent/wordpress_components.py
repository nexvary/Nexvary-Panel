from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

COMPONENT_KIND = {"plugin", "theme"}
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")
COMPONENT_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,79}$")
MAX_COMPONENT_PACKAGE = 80 * 1024 * 1024
MAX_COMPONENT_EXTRACTED = 250 * 1024 * 1024
MAX_COMPONENT_MEMBERS = 20000
MAX_COMPONENT_FILE = 48 * 1024 * 1024
MAX_COMPONENT_TREE = 300 * 1024 * 1024
MAX_COMPONENT_TREE_MEMBERS = 30000


def _kind(value: object) -> str:
    kind = str(value or "").strip().lower()
    if kind not in COMPONENT_KIND:
        raise ValueError("invalid-wordpress-component-kind")
    return kind


def _slug(value: object) -> str:
    slug = str(value or "").strip().lower()
    if not SLUG_RE.fullmatch(slug):
        raise ValueError("invalid-wordpress-component-slug")
    return slug


def _base(root: Path, kind: str) -> Path:
    return root / "wp-content" / ("plugins" if kind == "plugin" else "themes")


def _path(root: Path, kind: str, slug: str) -> Path:
    base = _base(root, kind)
    target = base / slug
    if not base.is_dir() or base.is_symlink() or not target.is_dir() or target.is_symlink():
        raise ValueError("wordpress-component-not-installed")
    try:
        resolved_base = base.resolve()
        resolved = target.resolve()
    except OSError as exc:
        raise ValueError("wordpress-component-unavailable") from exc
    if os.path.commonpath((str(resolved_base), str(resolved))) != str(resolved_base):
        raise ValueError("unsafe-wordpress-component-path")
    return target


def _tree_stats(root: Path) -> tuple[int, int]:
    count = 0
    total = 0
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in list(dirs):
            path = current_path / name
            if path.is_symlink():
                raise ValueError("wordpress-component-symlink-detected")
            count += 1
        for name in files:
            path = current_path / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("wordpress-component-unsafe-file")
            size = path.stat().st_size
            if size < 0 or size > MAX_COMPONENT_FILE:
                raise ValueError("wordpress-component-file-too-large")
            count += 1
            total += size
            if count > MAX_COMPONENT_TREE_MEMBERS or total > MAX_COMPONENT_TREE:
                raise ValueError("wordpress-component-tree-too-large")
    return count, total


def _header_version(path: Path, kind: str, slug: str) -> str:
    if kind == "theme":
        candidates = [path / "style.css"]
    else:
        primary = path / f"{slug}.php"
        candidates = [primary] if primary.is_file() and not primary.is_symlink() else []
        candidates.extend([p for p in path.glob("*.php") if p.is_file() and not p.is_symlink()][:20])
    for candidate in candidates:
        if not candidate.is_file() or candidate.is_symlink() or candidate.stat().st_size > 512 * 1024:
            continue
        text = candidate.read_text(encoding="utf-8", errors="replace")[:64 * 1024]
        match = re.search(r"(?im)^\s*Version:\s*([^\r\n]+)", text)
        if match:
            return match.group(1).strip()[:80]
    return ""


def _official_info(wp, kind: str, slug: str) -> dict:
    if kind == "plugin":
        body = wp._wp_api("/plugins/info/1.2/", {"action": "plugin_information", "request[slug]": slug})
    else:
        body = wp._wp_api("/themes/info/1.2/", {"action": "theme_information", "request[slug]": slug})
    latest = str(body.get("version", "")).strip()
    download = str(body.get("download_link", "")).strip()
    if not COMPONENT_VERSION_RE.fullmatch(latest):
        raise RuntimeError("wordpress-component-version-unavailable")
    parsed = urllib.parse.urlsplit(download)
    expected_prefix = "/plugin/" if kind == "plugin" else "/theme/"
    if (
        parsed.scheme != "https"
        or parsed.hostname != "downloads.wordpress.org"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith(expected_prefix)
        or not parsed.path.endswith(".zip")
    ):
        raise RuntimeError("wordpress-component-download-untrusted")
    return {"version": latest, "download_link": download}


def check_component(wp, domain: str, kind: object, slug: object) -> dict:
    domain = wp._domain(domain)
    kind = _kind(kind)
    slug = _slug(slug)
    root = wp._wordpress_root(domain)
    component = _path(root, kind, slug)
    _tree_stats(component)
    installed = _header_version(component, kind, slug)
    info = _official_info(wp, kind, slug)
    latest = str(info["version"])
    return {
        "ok": True,
        "domain": domain,
        "kind": kind,
        "slug": slug,
        "installed_version": installed,
        "latest_version": latest,
        "update_available": installed != latest,
        "source": "downloads.wordpress.org",
    }


def _download(wp, url: str, destination: Path) -> Path:
    archive = destination / "component.zip"
    req = urllib.request.Request(url, headers={"Accept": "application/zip,application/octet-stream", "User-Agent": "Nexvary-Panel/0.7"})
    opener = urllib.request.build_opener(wp._ReleaseRedirect())
    total = 0
    try:
        with opener.open(req, timeout=30) as response, archive.open("wb") as out:
            parsed = urllib.parse.urlsplit(response.geturl())
            if response.status != 200 or parsed.scheme != "https" or parsed.hostname != "downloads.wordpress.org":
                raise RuntimeError("wordpress-component-package-unavailable")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_COMPONENT_PACKAGE:
                    raise RuntimeError("wordpress-component-package-too-large")
                out.write(chunk)
    except Exception as exc:
        archive.unlink(missing_ok=True)
        raise RuntimeError("wordpress-component-package-unavailable") from exc
    if total < 256:
        archive.unlink(missing_ok=True)
        raise RuntimeError("wordpress-component-package-invalid")
    return archive


def _zip_is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_IFMT((info.external_attr >> 16) & 0xFFFF) == stat.S_IFLNK


def _extract(archive: Path, destination: Path, slug: str) -> Path:
    total = 0
    count = 0
    destination.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(archive, "r") as zf:
            infos = zf.infolist()
            for info in infos:
                count += 1
                if count > MAX_COMPONENT_MEMBERS:
                    raise RuntimeError("wordpress-component-package-too-many-files")
                pure = PurePosixPath(info.filename)
                if pure.is_absolute() or not pure.parts or ".." in pure.parts or pure.parts[0] != slug:
                    raise RuntimeError("wordpress-component-package-unsafe-path")
                if _zip_is_symlink(info):
                    raise RuntimeError("wordpress-component-package-symlink")
                if not info.is_dir():
                    if info.file_size < 0 or info.file_size > MAX_COMPONENT_FILE:
                        raise RuntimeError("wordpress-component-package-unsafe-file")
                    total += info.file_size
                    if total > MAX_COMPONENT_EXTRACTED:
                        raise RuntimeError("wordpress-component-package-too-large")
            for info in infos:
                pure = PurePosixPath(info.filename)
                target = destination.joinpath(*pure.parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src, target.open("wb") as out:
                    shutil.copyfileobj(src, out, length=1024 * 1024)
    except (zipfile.BadZipFile, OSError) as exc:
        raise RuntimeError("wordpress-component-package-invalid") from exc
    extracted = destination / slug
    if not extracted.is_dir() or extracted.is_symlink():
        raise RuntimeError("wordpress-component-package-invalid")
    _tree_stats(extracted)
    return extracted


def _normalize(root: Path, uid: int, gid: int) -> None:
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        if current_path.is_symlink():
            raise ValueError("wordpress-component-symlink-detected")
        os.chown(current_path, uid, gid)
        os.chmod(current_path, 0o755)
        for name in dirs:
            path = current_path / name
            if path.is_symlink():
                raise ValueError("wordpress-component-symlink-detected")
        for name in files:
            path = current_path / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("wordpress-component-unsafe-file")
            os.chown(path, uid, gid)
            os.chmod(path, 0o644)


def _snapshot(wp, domain: str, component: Path, kind: str, slug: str, installed_version: str) -> tuple[str, Path, dict]:
    snapshot_id, snapshot = wp._snapshot_dir(domain)
    saved = snapshot / "component"
    st = component.stat()
    _tree_stats(component)
    shutil.copytree(component, saved, copy_function=shutil.copy2)
    manifest = {
        "type": "component",
        "domain": domain,
        "kind": kind,
        "slug": slug,
        "version": installed_version,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "created_at": int(wp.time.time()),
    }
    (snapshot / "component-manifest.json").write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
    os.chmod(snapshot / "component-manifest.json", 0o600)
    return snapshot_id, snapshot, manifest


def _restore_saved(component: Path, saved: Path, manifest: dict) -> None:
    parent = component.parent
    uid, gid = int(manifest["uid"]), int(manifest["gid"])
    if not saved.is_dir() or saved.is_symlink():
        raise RuntimeError("wordpress-component-snapshot-invalid")
    _tree_stats(saved)
    temp = Path(tempfile.mkdtemp(prefix=f".nvp-restore-{component.name}-", dir=str(parent)))
    staged = temp / component.name
    old = parent / f".nvp-old-{component.name}-{os.urandom(4).hex()}"
    try:
        shutil.copytree(saved, staged, copy_function=shutil.copy2)
        _normalize(staged, uid, gid)
        if component.exists():
            if component.is_symlink() or not component.is_dir():
                raise RuntimeError("unsafe-wordpress-component-path")
            os.replace(component, old)
        os.replace(staged, component)
        shutil.rmtree(old, ignore_errors=True)
    except Exception:
        if old.exists() and not component.exists():
            os.replace(old, component)
        raise
    finally:
        shutil.rmtree(temp, ignore_errors=True)


def update_component(wp, domain: str, kind: object, slug: object) -> dict:
    domain = wp._domain(domain)
    kind = _kind(kind)
    slug = _slug(slug)
    root = wp._wordpress_root(domain)
    component = _path(root, kind, slug)
    installed = _header_version(component, kind, slug)
    info = _official_info(wp, kind, slug)
    latest = str(info["version"])
    if installed == latest:
        return {"ok": True, "domain": domain, "kind": kind, "slug": slug, "installed_version": installed, "latest_version": latest, "updated": False, "snapshot_id": ""}

    snapshot_id, snapshot, manifest = _snapshot(wp, domain, component, kind, slug, installed)
    saved = snapshot / "component"
    was_maintenance = (root / ".maintenance").is_file()
    parent = component.parent
    st = component.stat()
    old = parent / f".nvp-old-{slug}-{os.urandom(4).hex()}"
    try:
        if not was_maintenance:
            wp.maintenance(domain, True)
        with tempfile.TemporaryDirectory(prefix=f".nvp-{kind}-update-", dir=str(parent)) as tmp_name:
            tmp = Path(tmp_name)
            archive = _download(wp, str(info["download_link"]), tmp)
            extracted = _extract(archive, tmp / "extract", slug)
            _normalize(extracted, st.st_uid, st.st_gid)
            os.replace(component, old)
            os.replace(extracted, component)
            try:
                new_version = _header_version(component, kind, slug)
                if new_version != latest:
                    raise RuntimeError("wordpress-component-version-validation-failed")
                _tree_stats(component)
            except Exception:
                shutil.rmtree(component, ignore_errors=True)
                os.replace(old, component)
                raise
            shutil.rmtree(old, ignore_errors=True)
        return {
            "ok": True,
            "domain": domain,
            "kind": kind,
            "slug": slug,
            "installed_version": installed,
            "latest_version": latest,
            "updated": True,
            "snapshot_id": snapshot_id,
            "source": "downloads.wordpress.org",
        }
    except Exception:
        try:
            if component.exists() and not old.exists():
                _restore_saved(component, saved, manifest)
            elif old.exists():
                shutil.rmtree(component, ignore_errors=True)
                os.replace(old, component)
        finally:
            shutil.rmtree(snapshot, ignore_errors=True)
        raise
    finally:
        if not was_maintenance:
            try:
                wp.maintenance(domain, False)
            except Exception:
                pass


def rollback_component(wp, domain: str, snapshot_id: object) -> dict:
    domain = wp._domain(domain)
    snapshot_id = str(snapshot_id or "").strip().lower()
    if not wp.SNAPSHOT_RE.fullmatch(snapshot_id):
        raise ValueError("invalid-wordpress-snapshot")
    root = wp._wordpress_root(domain)
    snapshot = wp.BACKUP_BASE / domain / snapshot_id
    try:
        resolved_base = (wp.BACKUP_BASE / domain).resolve()
        resolved = snapshot.resolve()
    except OSError as exc:
        raise ValueError("wordpress-snapshot-not-found") from exc
    if os.path.commonpath((str(resolved_base), str(resolved))) != str(resolved_base) or not snapshot.is_dir() or snapshot.is_symlink():
        raise ValueError("wordpress-snapshot-not-found")
    manifest_path = snapshot / "component-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink() or manifest_path.stat().st_size > 64 * 1024:
        raise ValueError("wordpress-component-snapshot-invalid")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("type") != "component" or manifest.get("domain") != domain:
        raise ValueError("wordpress-component-snapshot-invalid")
    kind = _kind(manifest.get("kind"))
    slug = _slug(manifest.get("slug"))
    component = _base(root, kind) / slug
    saved = snapshot / "component"
    was_maintenance = (root / ".maintenance").is_file()
    try:
        if not was_maintenance:
            wp.maintenance(domain, True)
        _restore_saved(component, saved, manifest)
    finally:
        if not was_maintenance:
            try:
                wp.maintenance(domain, False)
            except Exception:
                pass
    return {
        "ok": True,
        "domain": domain,
        "kind": kind,
        "slug": slug,
        "snapshot_id": snapshot_id,
        "restored_version": str(manifest.get("version", ""))[:80],
    }


def dispatch(wp, req: dict) -> dict | None:
    action = str(req.get("action", ""))
    if action == "component-check":
        return check_component(wp, req.get("domain", ""), req.get("kind"), req.get("slug"))
    if action == "component-update":
        return update_component(wp, req.get("domain", ""), req.get("kind"), req.get("slug"))
    if action == "component-rollback":
        return rollback_component(wp, req.get("domain", ""), req.get("snapshot_id"))
    return None
