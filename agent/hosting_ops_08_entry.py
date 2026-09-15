#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path

import hosting_ops_entry as v07
from migration_adapters import inbox_archive, inspect_import, normalize_import

core = v07.core
BASE_DISPATCH = v07.composed_dispatch
DATA_DIR = Path(os.environ.get("NVP_DATA_DIR", "/var/lib/nexvary-panel"))
IMPORT_INBOX = DATA_DIR / "migration-inbox"


def migration_status() -> dict:
    body = v07.composed_status()
    capabilities = body.setdefault("capabilities", {})
    capabilities["migration_adapters"] = True
    capabilities["migration_cpanel"] = True
    capabilities["migration_directadmin"] = True
    capabilities["migration_plesk"] = True
    capabilities["migration_mail_import"] = False
    capabilities["migration_dns_apply"] = False
    return body


def _import_archive(data: dict) -> Path:
    return inbox_archive(str(data.get("filename", "")), IMPORT_INBOX)


def migration_inspect(data: dict) -> dict:
    archive = _import_archive(data)
    source_domain = str(data.get("source_domain", "")).strip() or None
    result = inspect_import(archive, source_domain)
    result["filename"] = archive.name
    return result


def migration_normalize(data: dict) -> dict:
    archive = _import_archive(data)
    target_domain = core._domain(data.get("target_domain", ""))
    source_domain = str(data.get("source_domain", "")).strip() or None
    source_db = str(data.get("source_db", "")).strip() or None
    target_db = str(data.get("target_db", "")).strip() or None
    if not core._site_root(target_domain).is_dir():
        raise ValueError("migration-target-site-not-found")
    if target_db:
        core._db(target_db)
    result = normalize_import(
        archive,
        core.MIGRATION_BASE,
        target_domain=target_domain,
        source_domain=source_domain,
        source_db=source_db,
        target_db=target_db,
    )
    result["filename"] = archive.name
    return result


def composed_dispatch_08(data: dict) -> dict:
    action = str(data.get("action", ""))
    if action == "status":
        return migration_status()
    if action == "migration-import-inspect":
        return migration_inspect(data)
    if action == "migration-import-normalize":
        return migration_normalize(data)
    return BASE_DISPATCH(data)


core.dispatch = composed_dispatch_08
core._status = migration_status

if __name__ == "__main__":
    IMPORT_INBOX.mkdir(parents=True, exist_ok=True, mode=0o700)
    core.MIGRATION_BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
    core.main()
