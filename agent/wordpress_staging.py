from __future__ import annotations

import json
import os
import pwd
import grp
import re
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path

DB_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
PREFIX_RE = re.compile(r"^[A-Za-z0-9_]{1,24}$")
SNAPSHOT_RE = re.compile(r"^[0-9]{10}-[a-f0-9]{8}$")
MAX_STAGE_FILES = 100_000
MAX_STAGE_BYTES = 4 * 1024 * 1024 * 1024
MAX_CONFIG = 1024 * 1024
MYSQL_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


def _safe_db(value: object) -> str:
    value = str(value or "").strip()
    if not DB_RE.fullmatch(value):
        raise ValueError("invalid-database-identifier")
    return value


def _managed_public(wp, domain: str) -> Path:
    domain = wp._domain(domain)
    root = wp.SITE_BASE / domain / "public"
    try:
        base = wp.SITE_BASE.resolve()
        resolved = root.resolve()
    except OSError as exc:
        raise ValueError("managed-site-root-unavailable") from exc
    if not root.is_dir() or root.is_symlink() or os.path.commonpath((str(base), str(resolved))) != str(base):
        raise ValueError("managed-site-root-unavailable")
    return root


def _config_value(text: str, key: str) -> str:
    pattern = re.compile(r"define\s*\(\s*['\"]" + re.escape(key) + r"['\"]\s*,\s*['\"]([^'\"]*)['\"]\s*\)\s*;", re.I)
    match = pattern.search(text)
    if not match:
        raise ValueError(f"wordpress-config-{key.lower()}-missing")
    return match.group(1)


def _config_meta(root: Path) -> dict:
    path = root / "wp-config.php"
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_CONFIG:
        raise ValueError("wordpress-config-unavailable")
    text = path.read_text(encoding="utf-8", errors="strict")
    db_name = _safe_db(_config_value(text, "DB_NAME"))
    db_user = _safe_db(_config_value(text, "DB_USER"))
    db_password = _config_value(text, "DB_PASSWORD")
    db_host = _config_value(text, "DB_HOST").strip().lower()
    if db_host not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("wordpress-staging-requires-local-mariadb")
    prefix_match = re.search(r"\$table_prefix\s*=\s*['\"]([A-Za-z0-9_]+)['\"]\s*;", text)
    prefix = prefix_match.group(1) if prefix_match else ""
    if not PREFIX_RE.fullmatch(prefix):
        raise ValueError("wordpress-table-prefix-unsupported")
    return {
        "db_name": db_name,
        "db_user": db_user,
        "db_password": db_password,
        "db_host": db_host,
        "table_prefix": prefix,
    }


def _php_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _replace_define(text: str, key: str, value: str) -> str:
    pattern = re.compile(
        r"(define\s*\(\s*['\"]" + re.escape(key) + r"['\"]\s*,\s*['\"])([^'\"]*)(['\"]\s*\)\s*;)",
        re.I,
    )
    updated, count = pattern.subn(lambda m: m.group(1) + _php_escape(value) + m.group(3), text, count=1)
    if count != 1:
        raise ValueError(f"wordpress-config-{key.lower()}-missing")
    return updated


def _rewrite_config(path: Path, *, db_name: str, environment: str, db_user: str | None = None,
                    db_password: str | None = None, db_host: str | None = None) -> None:
    if environment not in {"staging", "production"}:
        raise ValueError("invalid-wordpress-environment")
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_CONFIG:
        raise ValueError("wordpress-config-unavailable")
    text = path.read_text(encoding="utf-8", errors="strict")
    text = _replace_define(text, "DB_NAME", _safe_db(db_name))
    if db_user is not None:
        text = _replace_define(text, "DB_USER", _safe_db(db_user))
    if db_password is not None:
        text = _replace_define(text, "DB_PASSWORD", str(db_password))
    if db_host is not None:
        text = _replace_define(text, "DB_HOST", str(db_host))
    env_pattern = re.compile(r"define\s*\(\s*['\"]WP_ENVIRONMENT_TYPE['\"]\s*,\s*['\"][^'\"]*['\"]\s*\)\s*;", re.I)
    env_line = f"define('WP_ENVIRONMENT_TYPE', '{environment}');"
    if env_pattern.search(text):
        text = env_pattern.sub(env_line, text, count=1)
    else:
        marker = "if (!defined('ABSPATH'))"
        if marker not in text:
            raise ValueError("wordpress-config-layout-unsupported")
        text = text.replace(marker, env_line + "\n" + marker, 1)
    fd, tmp_name = tempfile.mkstemp(prefix=".nvp-wp-config-", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        st = path.stat()
        os.chmod(tmp, stat.S_IMODE(st.st_mode))
        os.chown(tmp, st.st_uid, st.st_gid)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _scan_tree(root: Path) -> tuple[int, int]:
    files = 0
    total = 0
    for base, dirs, names in os.walk(root, followlinks=False):
        for name in dirs + names:
            path = Path(base) / name
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode):
                raise ValueError("wordpress-staging-symlink-blocked")
            if stat.S_ISDIR(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                raise ValueError("wordpress-staging-special-file-blocked")
            files += 1
            total += st.st_size
            if files > MAX_STAGE_FILES or total > MAX_STAGE_BYTES:
                raise ValueError("wordpress-staging-tree-too-large")
    return files, total


def _chown_www(path: Path) -> None:
    account = pwd.getpwnam("www-data")
    gid = grp.getgrnam("www-data").gr_gid
    for base, dirs, files in os.walk(path, followlinks=False):
        os.chown(base, account.pw_uid, gid)
        for name in dirs + files:
            item = Path(base) / name
            if not item.is_symlink():
                os.chown(item, account.pw_uid, gid)


def _prepare_public_copy(source: Path, target_current: Path, *, db_name: str, environment: str,
                         credentials: dict | None = None) -> Path:
    _scan_tree(source)
    parent = target_current.parent
    temp = parent / f".nvp-wp-import-{os.urandom(6).hex()}"
    shutil.copytree(source, temp, symlinks=False)
    maintenance = temp / ".maintenance"
    if maintenance.exists() and not maintenance.is_symlink():
        maintenance.unlink(missing_ok=True)
    target_well_known = target_current / ".well-known"
    if target_well_known.is_dir() and not target_well_known.is_symlink():
        incoming = temp / ".well-known"
        if incoming.exists():
            if incoming.is_dir() and not incoming.is_symlink():
                shutil.rmtree(incoming)
            else:
                incoming.unlink()
        shutil.copytree(target_well_known, incoming, symlinks=False)
    creds = credentials or {}
    _rewrite_config(
        temp / "wp-config.php",
        db_name=db_name,
        environment=environment,
        db_user=creds.get("db_user"),
        db_password=creds.get("db_password"),
        db_host=creds.get("db_host"),
    )
    _chown_www(temp)
    return temp


def _mysql(sql: str, *, database: str = "", timeout: int = 35) -> str:
    args = ["mariadb", "--batch", "--skip-column-names"]
    if database:
        args.append(_safe_db(database))
    proc = subprocess.run(args, input=sql, text=True, capture_output=True, timeout=timeout, env=MYSQL_ENV)
    if proc.returncode:
        raise RuntimeError("mariadb-operation-failed")
    return (proc.stdout or "").strip()


def _db_exists(name: str) -> bool:
    name = _safe_db(name)
    out = _mysql(f"SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='{name}';")
    return out.splitlines()[-1:] == ["1"]


def _local_user_exists(user: str) -> bool:
    user = _safe_db(user)
    out = _mysql(f"SELECT COUNT(*) FROM mysql.user WHERE User='{user}' AND Host='localhost';")
    return out.splitlines()[-1:] == ["1"]


def _dump_db(name: str, destination: Path) -> None:
    name = _safe_db(name)
    with destination.open("wb") as handle:
        proc = subprocess.run(
            ["mariadb-dump", "--single-transaction", "--quick", "--skip-lock-tables", "--routines", "--triggers", "--", name],
            stdout=handle, stderr=subprocess.PIPE, timeout=180, env=MYSQL_ENV,
        )
    if proc.returncode or not destination.is_file() or destination.stat().st_size < 32:
        destination.unlink(missing_ok=True)
        raise RuntimeError("mariadb-dump-failed")


def _drop_db(name: str) -> None:
    name = _safe_db(name)
    _mysql(f"DROP DATABASE IF EXISTS `{name}`;")


def _create_db(name: str, user: str) -> None:
    name = _safe_db(name)
    user = _safe_db(user)
    if not _local_user_exists(user):
        raise RuntimeError("wordpress-database-user-not-local")
    _mysql(
        f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
        f"GRANT ALL PRIVILEGES ON `{name}`.* TO '{user}'@'localhost';FLUSH PRIVILEGES;"
    )


def _import_db(name: str, dump: Path) -> None:
    name = _safe_db(name)
    if not dump.is_file() or dump.is_symlink():
        raise RuntimeError("mariadb-import-source-invalid")
    with dump.open("rb") as handle:
        proc = subprocess.run(["mariadb", name], stdin=handle, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=180, env=MYSQL_ENV)
    if proc.returncode:
        raise RuntimeError("mariadb-import-failed")


def _replace_db(name: str, user: str, dump: Path) -> None:
    _drop_db(name)
    _create_db(name, user)
    try:
        _import_db(name, dump)
    except Exception:
        _drop_db(name)
        raise


def _update_urls(db_name: str, prefix: str, domain: str) -> None:
    db_name = _safe_db(db_name)
    if not PREFIX_RE.fullmatch(prefix):
        raise ValueError("wordpress-table-prefix-unsupported")
    domain = str(domain).strip().lower()
    url = f"https://{domain}"
    _mysql(
        f"UPDATE `{prefix}options` SET option_value='{url}' WHERE option_name IN ('home','siteurl');",
        database=db_name,
    )


def _swap_public(target: Path, prepared: Path) -> Path:
    previous = target.parent / f".nvp-wp-previous-{os.urandom(6).hex()}"
    os.replace(target, previous)
    try:
        os.replace(prepared, target)
    except Exception:
        os.replace(previous, target)
        raise
    return previous


def _restore_db(name: str, user: str, dump: Path) -> None:
    _replace_db(name, user, dump)


def clone(wp, source_domain: str, target_domain: str, target_db: str, replace: bool = False) -> dict:
    source_domain = wp._domain(source_domain)
    target_domain = wp._domain(target_domain)
    target_db = _safe_db(target_db)
    if source_domain == target_domain:
        raise ValueError("staging-target-must-differ")
    if not isinstance(replace, bool):
        raise ValueError("replace-must-be-boolean")
    source_root = wp._wordpress_root(source_domain)
    target_root = _managed_public(wp, target_domain)
    source = _config_meta(source_root)
    source_db = source["db_name"]
    db_user = source["db_user"]
    if target_db == source_db:
        raise ValueError("staging-database-must-differ")
    target_has_wp = (target_root / "wp-includes" / "version.php").is_file()
    existing_db = _db_exists(target_db)
    if (target_has_wp or existing_db) and not replace:
        raise ValueError("staging-target-not-empty")
    if not replace:
        allowed = {"index.php", "index.html", ".well-known"}
        extra = {p.name for p in target_root.iterdir()} - allowed
        if extra:
            raise ValueError("staging-target-not-empty")

    with tempfile.TemporaryDirectory(prefix="nvp-wp-stage-") as tmp_name:
        tmp = Path(tmp_name)
        source_dump = tmp / "source.sql"
        old_target_dump = tmp / "old-target.sql"
        _dump_db(source_db, source_dump)
        if existing_db:
            _dump_db(target_db, old_target_dump)
        prepared = _prepare_public_copy(source_root, target_root, db_name=target_db, environment="staging")
        db_mutation_started = False
        previous: Path | None = None
        try:
            db_mutation_started = True
            _replace_db(target_db, db_user, source_dump)
            _update_urls(target_db, source["table_prefix"], target_domain)
            previous = _swap_public(target_root, prepared)
            check = wp.inventory(target_domain)
            if not check.get("ok"):
                raise RuntimeError("wordpress-staging-validation-failed")
            if previous:
                shutil.rmtree(previous, ignore_errors=True)
            return {
                "ok": True,
                "source_domain": source_domain,
                "target_domain": target_domain,
                "source_db": source_db,
                "target_db": target_db,
                "db_user": db_user,
                "version": str(check.get("version", ""))[:40],
                "files": _scan_tree(target_root)[0],
                "rewrite_scope": "home-siteurl",
            }
        except Exception:
            if previous and previous.exists():
                failed = target_root.parent / f".nvp-wp-failed-{os.urandom(4).hex()}"
                if target_root.exists():
                    os.replace(target_root, failed)
                os.replace(previous, target_root)
                shutil.rmtree(failed, ignore_errors=True)
            if prepared.exists():
                shutil.rmtree(prepared, ignore_errors=True)
            if db_mutation_started:
                try:
                    if old_target_dump.is_file():
                        _restore_db(target_db, db_user, old_target_dump)
                    else:
                        _drop_db(target_db)
                except Exception:
                    pass
            raise


def preview(wp, source_domain: str, target_domain: str) -> dict:
    source_domain = wp._domain(source_domain)
    target_domain = wp._domain(target_domain)
    source_root = wp._wordpress_root(source_domain)
    target_root = wp._wordpress_root(target_domain)
    source_meta = _config_meta(source_root)
    target_meta = _config_meta(target_root)
    return {
        "ok": True,
        "source_domain": source_domain,
        "target_domain": target_domain,
        "source_version": wp._version(source_root),
        "target_version": wp._version(target_root),
        "source_db": source_meta["db_name"],
        "target_db": target_meta["db_name"],
        "source_files": _scan_tree(source_root)[0],
        "target_files": _scan_tree(target_root)[0],
        "safety": "snapshot-before-publish",
    }


def _publish_dir(wp, domain: str, snapshot_id: str) -> Path:
    if not SNAPSHOT_RE.fullmatch(snapshot_id):
        raise ValueError("invalid-wordpress-publish-snapshot")
    base = wp.BACKUP_BASE / wp._domain(domain) / "publish"
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(base, 0o700)
    path = base / snapshot_id
    try:
        resolved_base = base.resolve()
        resolved = path.resolve(strict=False)
    except OSError as exc:
        raise ValueError("wordpress-publish-snapshot-unavailable") from exc
    if os.path.commonpath((str(resolved_base), str(resolved))) != str(resolved_base):
        raise ValueError("invalid-wordpress-publish-snapshot")
    return path


def _restore_publish(wp, live_domain: str, snapshot: Path, manifest: dict) -> None:
    live_root = _managed_public(wp, live_domain)
    backup_files = snapshot / "files"
    backup_sql = snapshot / "database.sql"
    live_db = _safe_db(manifest.get("live_db"))
    db_user = _safe_db(manifest.get("db_user"))
    if not backup_files.is_dir() or backup_files.is_symlink() or not backup_sql.is_file() or backup_sql.is_symlink():
        raise RuntimeError("wordpress-publish-snapshot-invalid")
    prepared = live_root.parent / f".nvp-wp-restore-{os.urandom(6).hex()}"
    shutil.copytree(backup_files, prepared, symlinks=False)
    _chown_www(prepared)
    _restore_db(live_db, db_user, backup_sql)
    previous = _swap_public(live_root, prepared)
    shutil.rmtree(previous, ignore_errors=True)


def publish(wp, live_domain: str, staging_domain: str) -> dict:
    live_domain = wp._domain(live_domain)
    staging_domain = wp._domain(staging_domain)
    if live_domain == staging_domain:
        raise ValueError("staging-target-must-differ")
    live_root = wp._wordpress_root(live_domain)
    stage_root = wp._wordpress_root(staging_domain)
    live = _config_meta(live_root)
    stage = _config_meta(stage_root)
    snapshot_id = f"{int(time.time()):010d}-{os.urandom(4).hex()}"
    snapshot = _publish_dir(wp, live_domain, snapshot_id)
    snapshot.mkdir(mode=0o700)
    try:
        _scan_tree(live_root)
        shutil.copytree(live_root, snapshot / "files", symlinks=False)
        _dump_db(live["db_name"], snapshot / "database.sql")
        manifest = {
            "live_domain": live_domain,
            "staging_domain": staging_domain,
            "live_db": live["db_name"],
            "db_user": live["db_user"],
            "created_at": int(time.time()),
        }
        (snapshot / "manifest.json").write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
        os.chmod(snapshot / "manifest.json", 0o600)

        with tempfile.TemporaryDirectory(prefix="nvp-wp-publish-") as tmp_name:
            stage_dump = Path(tmp_name) / "stage.sql"
            _dump_db(stage["db_name"], stage_dump)
            prepared = _prepare_public_copy(
                stage_root,
                live_root,
                db_name=live["db_name"],
                environment="production",
                credentials={
                    "db_user": live["db_user"],
                    "db_password": live["db_password"],
                    "db_host": live["db_host"],
                },
            )
            previous: Path | None = None
            try:
                _replace_db(live["db_name"], live["db_user"], stage_dump)
                _update_urls(live["db_name"], stage["table_prefix"], live_domain)
                previous = _swap_public(live_root, prepared)
                check = wp.inventory(live_domain)
                if not check.get("ok"):
                    raise RuntimeError("wordpress-publish-validation-failed")
                if previous:
                    shutil.rmtree(previous, ignore_errors=True)
                return {
                    "ok": True,
                    "live_domain": live_domain,
                    "staging_domain": staging_domain,
                    "snapshot_id": snapshot_id,
                    "version": str(check.get("version", ""))[:40],
                    "safety": "rollback-ready",
                    "rewrite_scope": "home-siteurl",
                }
            except Exception:
                if previous and previous.exists():
                    failed = live_root.parent / f".nvp-wp-failed-{os.urandom(4).hex()}"
                    if live_root.exists():
                        os.replace(live_root, failed)
                    os.replace(previous, live_root)
                    shutil.rmtree(failed, ignore_errors=True)
                if prepared.exists():
                    shutil.rmtree(prepared, ignore_errors=True)
                _restore_publish(wp, live_domain, snapshot, manifest)
                raise
    except Exception:
        if not (snapshot / "manifest.json").exists():
            shutil.rmtree(snapshot, ignore_errors=True)
        raise


def rollback_publish(wp, live_domain: str, snapshot_id: str) -> dict:
    live_domain = wp._domain(live_domain)
    snapshot = _publish_dir(wp, live_domain, str(snapshot_id or ""))
    manifest_path = snapshot / "manifest.json"
    if not snapshot.is_dir() or snapshot.is_symlink() or not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("wordpress-publish-snapshot-not-found")
    if manifest_path.stat().st_size > 128 * 1024:
        raise ValueError("wordpress-publish-snapshot-invalid")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("live_domain") != live_domain:
        raise ValueError("wordpress-publish-snapshot-invalid")
    _restore_publish(wp, live_domain, snapshot, manifest)
    check = wp.inventory(live_domain)
    return {
        "ok": True,
        "live_domain": live_domain,
        "snapshot_id": snapshot.name,
        "version": str(check.get("version", ""))[:40],
        "rolled_back": True,
    }


def dispatch(wp, req: dict) -> dict | None:
    action = str(req.get("action", ""))
    if action == "staging-clone":
        replace = req.get("replace", False)
        if not isinstance(replace, bool):
            raise ValueError("replace-must-be-boolean")
        return clone(wp, req.get("source_domain", ""), req.get("target_domain", ""), req.get("target_db", ""), replace)
    if action == "staging-preview":
        return preview(wp, req.get("source_domain", ""), req.get("target_domain", ""))
    if action == "staging-publish":
        return publish(wp, req.get("source_domain", ""), req.get("target_domain", ""))
    if action == "staging-publish-rollback":
        return rollback_publish(wp, req.get("source_domain", ""), str(req.get("snapshot_id", "")))
    return None
