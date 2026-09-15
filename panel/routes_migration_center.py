from __future__ import annotations

import os
import re
import secrets
import time
from pathlib import Path

from flask import jsonify, request, session

from .config import DATA_DIR
from .core import audit, db
from .ops_client import ops_call
from .security import role_required, step_up_required

IMPORT_INBOX = DATA_DIR / "migration-inbox"
MAX_IMPORT_BYTES = 8 * 1024 * 1024 * 1024
UPLOAD_CHUNK = 1024 * 1024
SAFE_UPLOAD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,180}$")
ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar", ".zip")


def _suffix(filename: str) -> str:
    lower = filename.lower()
    for suffix in ARCHIVE_SUFFIXES:
        if lower.endswith(suffix):
            return suffix
    raise ValueError("archive must be .tar.gz, .tgz, .tar or .zip")


def _safe_inbox_file(filename: object) -> Path:
    name = str(filename or "")
    if not SAFE_UPLOAD_RE.fullmatch(name) or not any(name.lower().endswith(suffix) for suffix in ARCHIVE_SUFFIXES):
        raise ValueError("invalid migration import filename")
    path = (IMPORT_INBOX / name).resolve()
    base = IMPORT_INBOX.resolve()
    if path.parent != base:
        raise ValueError("invalid migration import path")
    return path


def _owner() -> str:
    return str(session.get("user", "admin"))[:64]


def register_migration_center_routes(app):
    @app.get("/api/migration-center/uploads")
    @role_required("admin")
    def migration_center_uploads():
        IMPORT_INBOX.mkdir(parents=True, exist_ok=True, mode=0o700)
        items = []
        for path in sorted(IMPORT_INBOX.iterdir(), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True):
            try:
                if path.is_symlink() or not path.is_file() or not SAFE_UPLOAD_RE.fullmatch(path.name):
                    continue
                if not any(path.name.lower().endswith(suffix) for suffix in ARCHIVE_SUFFIXES):
                    continue
                st = path.stat()
                items.append({"filename": path.name, "size_bytes": int(st.st_size), "uploaded_at": int(st.st_mtime)})
                if len(items) >= 100:
                    break
            except OSError:
                continue
        return jsonify(ok=True, uploads=items, max_upload_bytes=MAX_IMPORT_BYTES, supported_panels=["cpanel", "directadmin", "plesk"])

    @app.post("/api/migration-center/uploads")
    @role_required("admin")
    @step_up_required
    def migration_center_upload():
        # Flask 3.1 supports a per-request limit. Keep the rest of the panel at its global 16 MiB cap.
        request.max_content_length = MAX_IMPORT_BYTES + (16 * 1024 * 1024)
        uploaded = request.files.get("archive")
        if uploaded is None or not uploaded.filename:
            return jsonify(ok=False, error="archive upload is required"), 400
        try:
            suffix = _suffix(str(uploaded.filename))
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        IMPORT_INBOX.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(IMPORT_INBOX, 0o700)
        filename = f"import-{int(time.time())}-{secrets.token_hex(8)}{suffix}"
        destination = _safe_inbox_file(filename)
        temporary = destination.with_name("." + destination.name + ".part")
        total = 0
        try:
            with temporary.open("xb") as handle:
                os.chmod(temporary, 0o600)
                while True:
                    chunk = uploaded.stream.read(UPLOAD_CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_IMPORT_BYTES:
                        raise ValueError("migration archive exceeds 8 GiB policy")
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
            if total < 1:
                raise ValueError("migration archive is empty")
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)
        except (OSError, ValueError) as exc:
            temporary.unlink(missing_ok=True)
            destination.unlink(missing_ok=True)
            return jsonify(ok=False, error=str(exc)[:180]), 400
        audit("migration-import-upload", f"file={filename} bytes={total}")
        return jsonify(ok=True, filename=filename, size_bytes=total), 201

    @app.post("/api/migration-center/inspect")
    @role_required("admin")
    @step_up_required
    def migration_center_inspect():
        data = request.get_json(silent=True) or {}
        try:
            path = _safe_inbox_file(data.get("filename"))
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        if not path.is_file() or path.is_symlink():
            return jsonify(ok=False, error="migration upload not found"), 404
        result = ops_call(
            {"action": "migration-import-inspect", "filename": path.name, "source_domain": str(data.get("source_domain", ""))},
            timeout=180,
        )
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "migration compatibility inspection failed"))[:220]), 422
        audit("migration-import-inspect", f"file={path.name} panel={result.get('panel', 'unknown')}")
        return jsonify(result)

    @app.post("/api/migration-center/normalize")
    @role_required("admin")
    @step_up_required
    def migration_center_normalize():
        data = request.get_json(silent=True) or {}
        try:
            path = _safe_inbox_file(data.get("filename"))
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        if not path.is_file() or path.is_symlink():
            return jsonify(ok=False, error="migration upload not found"), 404
        payload = {
            "action": "migration-import-normalize",
            "filename": path.name,
            "source_domain": str(data.get("source_domain", "")),
            "target_domain": str(data.get("target_domain", "")),
            "source_db": str(data.get("source_db", "")),
            "target_db": str(data.get("target_db", "")),
        }
        result = ops_call(payload, timeout=1800)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "migration normalization failed"))[:220]), 422
        archive = str(result.get("archive", ""))[:800]
        target_domain = str(data.get("target_domain", "")).strip().lower().rstrip(".")[:253]
        now = int(time.time())
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO migration_bundles(domain,archive,size_bytes,sha256,status,owner,created_at) VALUES(?,?,?,?, 'ready',?,?)",
                (target_domain, archive, int(result.get("size_bytes", 0) or 0), str(result.get("sha256", ""))[:128], _owner(), now),
            )
            bundle_id = int(cur.lastrowid)
        audit("migration-import-normalize", f"bundle={bundle_id} file={path.name} panel={result.get('panel', '')} domain={target_domain}")
        return jsonify(
            ok=True,
            bundle_id=bundle_id,
            status="ready",
            source_panel=str(result.get("panel", "unknown"))[:32],
            domain=target_domain,
            size_bytes=int(result.get("size_bytes", 0) or 0),
            sha256=str(result.get("sha256", ""))[:128],
            website_files=int(result.get("website_files", 0) or 0),
            database_included=bool(result.get("database_included")),
            warnings=result.get("warnings") if isinstance(result.get("warnings"), list) else [],
            restore_endpoint=f"/api/advanced/migrations/{bundle_id}/restore",
        ), 201

    @app.delete("/api/migration-center/uploads/<path:filename>")
    @role_required("admin")
    @step_up_required
    def migration_center_delete_upload(filename: str):
        try:
            path = _safe_inbox_file(filename)
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        if not path.is_file() or path.is_symlink():
            return jsonify(ok=False, error="migration upload not found"), 404
        try:
            path.unlink()
        except OSError:
            return jsonify(ok=False, error="migration upload delete failed"), 503
        audit("migration-import-delete", f"file={path.name}")
        return jsonify(ok=True, filename=path.name)
