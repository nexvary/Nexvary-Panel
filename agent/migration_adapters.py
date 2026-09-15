from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
DB_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
ARCHIVE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,220}\.(?:tar\.gz|tgz|tar|zip)$", re.I)
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
MAX_EXPANDED_BYTES = 80 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 20 * 1024 * 1024 * 1024
MAX_MEMBERS = 250_000
MAX_REPORT_NAMES = 100


@dataclass(frozen=True)
class Member:
    name: str
    size: int
    kind: str
    source: object


def _domain(value: object) -> str:
    domain = str(value or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("invalid-migration-domain")
    return domain


def _db(value: object) -> str:
    name = str(value or "").strip()
    if not DB_RE.fullmatch(name):
        raise ValueError("invalid-migration-database")
    return name


def _safe_name(raw: str) -> str:
    name = str(raw or "").replace("\\", "/")
    # Strip only explicit benign "./" prefixes. Never use lstrip("./") here:
    # it would transform traversal such as "../../etc/passwd" into a safe-looking path.
    while name.startswith("./"):
        name = name[2:]
    if not name or "\x00" in name or re.match(r"^[A-Za-z]:/", name):
        raise ValueError("unsafe-migration-archive")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("unsafe-migration-archive")
    clean = tuple(part for part in path.parts if part not in {"", "."})
    if not clean:
        raise ValueError("unsafe-migration-archive")
    return "/".join(clean)


def inbox_archive(value: str, inbox: Path) -> Path:
    name = Path(str(value or "")).name
    if name != str(value or "") or not ARCHIVE_NAME_RE.fullmatch(name):
        raise ValueError("invalid-migration-import-filename")
    base = inbox.resolve()
    path = (base / name).resolve()
    if path.parent != base or not path.is_file() or path.is_symlink():
        raise ValueError("migration-import-not-found")
    st = path.stat()
    if st.st_size < 1 or st.st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("migration-import-size-outside-policy")
    return path


def _tar_members(handle: tarfile.TarFile) -> list[Member]:
    raw = handle.getmembers()
    if len(raw) > MAX_MEMBERS:
        raise ValueError("migration-archive-too-many-files")
    rows: list[Member] = []
    expanded = 0
    for item in raw:
        name = _safe_name(item.name)
        if item.issym() or item.islnk() or item.ischr() or item.isblk() or item.isfifo():
            raise ValueError("unsafe-migration-archive-entry")
        if not (item.isdir() or item.isfile()):
            raise ValueError("unsafe-migration-archive-entry")
        size = int(item.size or 0)
        if size < 0 or size > MAX_MEMBER_BYTES:
            raise ValueError("migration-archive-member-too-large")
        expanded += size
        if expanded > MAX_EXPANDED_BYTES:
            raise ValueError("migration-archive-expanded-size-too-large")
        rows.append(Member(name=name, size=size, kind="dir" if item.isdir() else "file", source=item))
    return rows


def _zip_members(handle: zipfile.ZipFile) -> list[Member]:
    raw = handle.infolist()
    if len(raw) > MAX_MEMBERS:
        raise ValueError("migration-archive-too-many-files")
    rows: list[Member] = []
    expanded = 0
    for item in raw:
        name = _safe_name(item.filename)
        mode = (int(item.external_attr) >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise ValueError("unsafe-migration-archive-entry")
        size = int(item.file_size or 0)
        if size < 0 or size > MAX_MEMBER_BYTES:
            raise ValueError("migration-archive-member-too-large")
        expanded += size
        if expanded > MAX_EXPANDED_BYTES:
            raise ValueError("migration-archive-expanded-size-too-large")
        rows.append(Member(name=name, size=size, kind="dir" if item.is_dir() else "file", source=item))
    return rows


class Archive:
    def __init__(self, path: Path):
        self.path = path
        self.handle = None
        self.kind = ""
        self.members: list[Member] = []

    def __enter__(self):
        if tarfile.is_tarfile(self.path):
            self.kind = "tar"
            self.handle = tarfile.open(self.path, "r:*")
            self.members = _tar_members(self.handle)
            return self
        if zipfile.is_zipfile(self.path):
            self.kind = "zip"
            self.handle = zipfile.ZipFile(self.path, "r")
            self.members = _zip_members(self.handle)
            return self
        raise ValueError("unsupported-migration-archive-format")

    def __exit__(self, exc_type, exc, tb):
        if self.handle is not None:
            self.handle.close()

    def open_member(self, member: Member):
        if self.kind == "tar":
            stream = self.handle.extractfile(member.source)
            if stream is None:
                raise ValueError("migration-archive-member-unreadable")
            return stream
        return self.handle.open(member.source, "r")


def _parts(name: str) -> tuple[str, ...]:
    return tuple(PurePosixPath(name).parts)


def _after(parts: tuple[str, ...], marker: tuple[str, ...]) -> tuple[str, ...] | None:
    if len(parts) < len(marker):
        return None
    for index in range(0, len(parts) - len(marker) + 1):
        if tuple(part.lower() for part in parts[index:index + len(marker)]) == tuple(part.lower() for part in marker):
            return parts[index + len(marker):]
    return None


def _discover_domains(members: list[Member]) -> list[str]:
    found: set[str] = set()
    for member in members:
        parts = _parts(member.name)
        for index, part in enumerate(parts[:-1]):
            if part.lower() == "domains" and index + 1 < len(parts):
                candidate = parts[index + 1].lower().rstrip(".")
                candidate = candidate.split(" ", 1)[0]
                if DOMAIN_RE.fullmatch(candidate):
                    found.add(candidate)
        for index, part in enumerate(parts[:-1]):
            if part.lower() == "userdata" and index + 2 < len(parts):
                candidate = parts[index + 2].lower().rstrip(".")
                if DOMAIN_RE.fullmatch(candidate):
                    found.add(candidate)
    return sorted(found)[:MAX_REPORT_NAMES]


def _sql_candidates(members: list[Member]) -> list[str]:
    rows = []
    for member in members:
        if member.kind != "file":
            continue
        lower = member.name.lower()
        if lower.endswith(".sql") and any(token in lower.split("/") for token in ("mysql", "database", "databases", "backup")):
            rows.append(member.name)
        elif lower.endswith(".sql") and len(rows) < 5:
            rows.append(member.name)
        if len(rows) >= MAX_REPORT_NAMES:
            break
    return rows


def _detect_panel(path: Path, members: list[Member]) -> tuple[str, int]:
    names = [member.name.lower() for member in members[:MAX_MEMBERS]]
    filename = path.name.lower()
    cpanel = 0
    directadmin = 0
    plesk = 0
    if filename.startswith("cpmove-") or filename.startswith("backup-"):
        cpanel += 3
    if any("/homedir/public_html/" in "/" + name + "/" or "/userdata/" in "/" + name + "/" for name in names):
        cpanel += 4
    if any("/domains/" in "/" + name + "/" and "/public_html/" in "/" + name + "/" for name in names):
        directadmin += 4
    if any("/backup/" in "/" + name + "/" and name.endswith(".conf") for name in names):
        directadmin += 2
    if any(name.endswith(".xml") and ("backup" in name or "info" in name) for name in names):
        plesk += 2
    if any("/domains/" in "/" + name + "/" and "/httpdocs/" in "/" + name + "/" for name in names):
        plesk += 5
    best = max(((cpanel, "cpanel"), (directadmin, "directadmin"), (plesk, "plesk")), key=lambda item: item[0])
    return (best[1], best[0]) if best[0] > 0 else ("unknown", 0)


def _site_prefix(panel: str, members: list[Member], source_domain: str | None) -> tuple[str, ...] | None:
    domain = source_domain.lower() if source_domain else None
    for member in members:
        if member.kind != "file":
            continue
        parts = _parts(member.name)
        if panel == "cpanel":
            tail = _after(parts, ("homedir", "public_html"))
            if tail is not None:
                marker_at = len(parts) - len(tail) - 2
                return parts[:marker_at + 2]
        elif panel == "directadmin" and domain:
            tail = _after(parts, ("domains", domain, "public_html"))
            if tail is not None:
                marker_at = len(parts) - len(tail) - 3
                return parts[:marker_at + 3]
        elif panel == "plesk" and domain:
            tail = _after(parts, ("domains", domain, "httpdocs"))
            if tail is not None:
                marker_at = len(parts) - len(tail) - 3
                return parts[:marker_at + 3]
            tail = _after(parts, (domain, "httpdocs"))
            if tail is not None:
                marker_at = len(parts) - len(tail) - 2
                return parts[:marker_at + 2]
    return None


def inspect_import(path: Path, source_domain: str | None = None) -> dict:
    if source_domain:
        source_domain = _domain(source_domain)
    with Archive(path) as archive:
        members = archive.members
        panel, score = _detect_panel(path, members)
        domains = _discover_domains(members)
        selected_domain = source_domain or (domains[0] if len(domains) == 1 else None)
        prefix = _site_prefix(panel, members, selected_domain)
        sql = _sql_candidates(members)
        names_lower = [member.name.lower() for member in members]
        mail_detected = any("/mail/" in "/" + name + "/" or "/imap/" in "/" + name + "/" for name in names_lower)
        dns_detected = any("/dns/" in "/" + name + "/" or "/zones/" in "/" + name + "/" or name.endswith(".db") for name in names_lower)
        nested_content = any(name.endswith((".tgz", ".tar.gz", ".zip")) for name in names_lower)
        warnings: list[str] = []
        if panel == "unknown":
            warnings.append("backup layout was not recognized as cPanel, DirectAdmin or Plesk")
        if panel in {"directadmin", "plesk"} and not selected_domain:
            warnings.append("select source_domain because the archive contains zero or multiple discoverable domains")
        if not prefix:
            warnings.append("website document root was not found in the top-level archive layout")
        if panel == "plesk" and nested_content and not prefix:
            warnings.append("Plesk content appears nested; compatibility report is available but this archive needs flattening/export before web-root normalization")
        if mail_detected:
            warnings.append("mail data detected; 0.8 imports website/database only and does not silently rewrite mailbox state")
        if dns_detected:
            warnings.append("DNS data detected; DNS is reported but not auto-applied during migration")
        return {
            "ok": True,
            "panel": panel,
            "confidence": min(100, score * 20),
            "archive_kind": archive.kind,
            "members": len(members),
            "expanded_bytes": sum(member.size for member in members),
            "domains": domains,
            "selected_domain": selected_domain or "",
            "site_prefix": "/".join(prefix) if prefix else "",
            "database_candidates": sql[:MAX_REPORT_NAMES],
            "capabilities": {
                "website": bool(prefix),
                "mariadb_sql": bool(sql),
                "mail_discovery": mail_detected,
                "dns_discovery": dns_detected,
                "mail_import": False,
                "dns_apply": False,
            },
            "warnings": warnings,
        }


def _copy_member(archive: Archive, member: Member, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    if member.kind == "dir":
        target.mkdir(parents=True, exist_ok=True, mode=0o750)
        return
    with archive.open_member(member) as source, target.open("wb") as out:
        shutil.copyfileobj(source, out, length=1024 * 1024)
    if target.stat().st_size != member.size:
        raise ValueError("migration-member-size-mismatch")
    os.chmod(target, 0o640)


def _choose_sql(candidates: list[str], source_db: str | None) -> str | None:
    if not candidates:
        return None
    if source_db:
        source_db = _db(source_db)
        exact = []
        for name in candidates:
            stem = Path(name).name[:-4]
            variants = {stem, stem.split(".", 1)[0], stem.split("-", 1)[0]}
            if source_db in variants or stem.endswith("_" + source_db) or stem.endswith("-" + source_db):
                exact.append(name)
        if len(exact) == 1:
            return exact[0]
        if not exact:
            raise ValueError("migration-source-database-not-found")
        raise ValueError("migration-source-database-ambiguous")
    return candidates[0] if len(candidates) == 1 else None


def normalize_import(
    path: Path,
    output_dir: Path,
    *,
    target_domain: str,
    source_domain: str | None = None,
    source_db: str | None = None,
    target_db: str | None = None,
) -> dict:
    target_domain = _domain(target_domain)
    if source_domain:
        source_domain = _domain(source_domain)
    target_database = _db(target_db) if target_db else ""
    report = inspect_import(path, source_domain)
    if report["panel"] == "unknown":
        raise ValueError("migration-source-panel-not-recognized")
    selected_domain = source_domain or str(report.get("selected_domain") or "") or None
    if report["panel"] in {"directadmin", "plesk"} and not selected_domain:
        raise ValueError("migration-source-domain-required")

    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    work = Path(tempfile.mkdtemp(prefix="nvp-adapter-"))
    try:
        with Archive(path) as archive:
            prefix = _site_prefix(report["panel"], archive.members, selected_domain)
            if not prefix:
                raise ValueError("migration-website-root-not-supported-by-adapter")
            copied_files = 0
            copied_bytes = 0
            prefix_lower = tuple(part.lower() for part in prefix)
            for member in archive.members:
                parts = _parts(member.name)
                if len(parts) < len(prefix) or tuple(part.lower() for part in parts[:len(prefix)]) != prefix_lower:
                    continue
                relative = parts[len(prefix):]
                if not relative:
                    continue
                destination = work.joinpath("site", *relative)
                if os.path.commonpath((str(work / "site"), str(destination))) != str(work / "site"):
                    raise ValueError("unsafe-migration-archive")
                _copy_member(archive, member, destination)
                if member.kind == "file":
                    copied_files += 1
                    copied_bytes += member.size
            if copied_files < 1:
                raise ValueError("migration-website-root-empty")

            sql_candidates = _sql_candidates(archive.members)
            sql_name = _choose_sql(sql_candidates, source_db)
            if target_database:
                if not sql_name:
                    raise ValueError("migration-database-selection-required")
                sql_member = next(member for member in archive.members if member.name == sql_name and member.kind == "file")
                if sql_member.size > MAX_MEMBER_BYTES:
                    raise ValueError("migration-database-dump-too-large")
                _copy_member(archive, sql_member, work / "database.sql")

        manifest = {
            "version": 1,
            "domain": target_domain,
            "database": target_database,
            "created_at": int(time.time()),
            "adapter": {
                "source_panel": report["panel"],
                "source_domain": selected_domain or "",
                "source_archive": path.name,
                "website_files": copied_files,
                "website_bytes": copied_bytes,
                "database_source": sql_name or "",
            },
        }
        (work / "manifest.json").write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + os.urandom(3).hex()
        destination = output_dir / f"{target_domain}-import-{report['panel']}-{stamp}.tar.gz"
        with tarfile.open(destination, "w:gz") as out:
            out.add(work / "site", arcname="site", recursive=True)
            out.add(work / "manifest.json", arcname="manifest.json")
            if (work / "database.sql").is_file():
                out.add(work / "database.sql", arcname="database.sql")
        os.chmod(destination, 0o600)
        digest = hashlib.sha256()
        with destination.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return {
            "ok": True,
            "panel": report["panel"],
            "archive": str(destination),
            "size_bytes": destination.stat().st_size,
            "sha256": digest.hexdigest(),
            "website_files": copied_files,
            "website_bytes": copied_bytes,
            "database_included": bool(target_database),
            "warnings": report["warnings"],
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)
