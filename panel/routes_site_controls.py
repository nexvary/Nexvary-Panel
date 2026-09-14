from __future__ import annotations

import json
import re
import time

from flask import jsonify, request

from .config import DOMAIN_RE
from .core import audit, can_manage_domain, db
from .hosting_policy import feature_allowed
from .security import login_required, role_required, step_up_required
from .webtools_client import webtools_call

SAFE_PATH_RE = re.compile(r"^/(?:[A-Za-z0-9._~-]+/)*[A-Za-z0-9._~-]*$")
SAFE_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SAFE_EXT_RE = re.compile(r"^[a-z0-9]{1,12}$")
SAFE_MIME_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,95}$")
BLOCKED_MIME_EXTENSIONS = frozenset({
    "php", "phtml", "phar", "cgi", "pl", "py", "sh", "bash", "zsh", "fish",
    "env", "ini", "conf", "config", "key", "pem", "crt", "csr", "htaccess", "htpasswd",
    "sql", "sqlite", "db", "bak", "backup", "log", "old", "swp",
})
DEFAULT_EXTENSIONS = ["jpg", "jpeg", "png", "gif", "webp", "svg"]


def _domain(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().lower().rstrip(".")
    return value if DOMAIN_RE.fullmatch(value) and can_manage_domain(value) else None


def _site_owner(conn, domain: str) -> str | None:
    row = conn.execute("SELECT owner FROM sites WHERE domain=?", (domain,)).fetchone()
    return str(row["owner"]) if row else None


def _settings(conn, domain: str) -> dict:
    row = conn.execute(
        "SELECT domain,owner,privacy_enabled,privacy_path,privacy_username,hotlink_enabled,hotlink_extensions,indexing_mode,mime_overrides,updated_at FROM site_web_controls WHERE domain=?",
        (domain,),
    ).fetchone()
    if not row:
        owner = _site_owner(conn, domain) or ""
        return {
            "domain": domain,
            "owner": owner,
            "privacy_enabled": 0,
            "privacy_path": "/",
            "privacy_username": None,
            "hotlink_enabled": 0,
            "hotlink_extensions": DEFAULT_EXTENSIONS,
            "indexing_mode": "off",
            "mime_overrides": {},
            "updated_at": 0,
        }
    data = dict(row)
    data["hotlink_extensions"] = [item for item in str(data.get("hotlink_extensions") or "").split(",") if item]
    try:
        parsed = json.loads(str(data.get("mime_overrides") or "{}"))
        data["mime_overrides"] = parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        data["mime_overrides"] = {}
    return data


def _upsert(conn, domain: str, owner: str, **updates) -> None:
    current = _settings(conn, domain)
    current.update(updates)
    now = int(time.time())
    conn.execute(
        """
        INSERT INTO site_web_controls(
          domain,owner,privacy_enabled,privacy_path,privacy_username,
          hotlink_enabled,hotlink_extensions,indexing_mode,mime_overrides,updated_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(domain) DO UPDATE SET
          owner=excluded.owner,
          privacy_enabled=excluded.privacy_enabled,
          privacy_path=excluded.privacy_path,
          privacy_username=excluded.privacy_username,
          hotlink_enabled=excluded.hotlink_enabled,
          hotlink_extensions=excluded.hotlink_extensions,
          indexing_mode=excluded.indexing_mode,
          mime_overrides=excluded.mime_overrides,
          updated_at=excluded.updated_at
        """,
        (
            domain,
            owner,
            int(bool(current.get("privacy_enabled"))),
            str(current.get("privacy_path") or "/"),
            current.get("privacy_username"),
            int(bool(current.get("hotlink_enabled"))),
            ",".join(current.get("hotlink_extensions") or DEFAULT_EXTENSIONS),
            str(current.get("indexing_mode") or "off"),
            json.dumps(current.get("mime_overrides") or {}, separators=(",", ":"), sort_keys=True),
            now,
        ),
    )


def _feature(feature_id: str):
    if not feature_allowed(feature_id):
        return jsonify(ok=False, error=f"{feature_id} disabled by hosting package policy"), 403
    return None


def register_site_control_routes(app):
    @app.get("/api/site-controls")
    @login_required
    def site_controls_get():
        domain = _domain(request.args.get("domain", ""))
        if not domain:
            return jsonify(ok=False, error="invalid or unauthorized domain"), 400
        with db() as conn:
            if not _site_owner(conn, domain):
                return jsonify(ok=False, error="managed site not found"), 404
            settings = _settings(conn, domain)
        return jsonify(
            ok=True,
            settings=settings,
            capabilities={
                "directory_privacy": feature_allowed("files.directory_privacy"),
                "hotlink": feature_allowed("security.hotlink"),
                "indexes": feature_allowed("advanced.indexes"),
                "mime_types": feature_allowed("advanced.mime_types"),
                "raw_access": feature_allowed("metrics.raw_access"),
            },
        )

    @app.put("/api/site-controls/privacy")
    @role_required("admin", "operator")
    @step_up_required
    def site_controls_privacy():
        denied = _feature("files.directory_privacy")
        if denied:
            return denied
        data = request.get_json(silent=True) or {}
        domain = _domain(data.get("domain"))
        enabled = data.get("enabled") is True
        path = str(data.get("path", "/")).strip()
        username = str(data.get("username", "")).strip() if enabled else None
        password = data.get("password")
        if not domain or not SAFE_PATH_RE.fullmatch(path) or len(path) > 180:
            return jsonify(ok=False, error="invalid privacy configuration"), 400
        if enabled and (not SAFE_USER_RE.fullmatch(username or "") or not isinstance(password, str) or not 12 <= len(password) <= 256):
            return jsonify(ok=False, error="username and a 12+ character password are required"), 400
        with db() as conn:
            owner = _site_owner(conn, domain)
            if not owner:
                return jsonify(ok=False, error="managed site not found"), 404
            result = webtools_call(
                {"action": "site-control-privacy", "domain": domain, "enabled": enabled, "path": path, "username": username, "password": password if enabled else None},
                timeout=40,
            )
            if not result.get("ok"):
                return jsonify(ok=False, error=str(result.get("error", "privacy provider failed"))[:180]), 502
            _upsert(conn, domain, owner, privacy_enabled=int(enabled), privacy_path=path, privacy_username=username)
            settings = _settings(conn, domain)
        audit("site-control-privacy", f"domain={domain} enabled={int(enabled)} path={path} username={username or '-'}")
        return jsonify(ok=True, settings=settings)

    @app.put("/api/site-controls/hotlink")
    @role_required("admin", "operator")
    @step_up_required
    def site_controls_hotlink():
        denied = _feature("security.hotlink")
        if denied:
            return denied
        data = request.get_json(silent=True) or {}
        domain = _domain(data.get("domain"))
        enabled = data.get("enabled") is True
        values = data.get("extensions", DEFAULT_EXTENSIONS)
        if not domain or not isinstance(values, list) or not 1 <= len(values) <= 24:
            return jsonify(ok=False, error="invalid hotlink configuration"), 400
        extensions: list[str] = []
        for item in values:
            value = str(item).strip().lower().lstrip(".")
            if not SAFE_EXT_RE.fullmatch(value):
                return jsonify(ok=False, error="invalid hotlink extension"), 400
            if value not in extensions:
                extensions.append(value)
        with db() as conn:
            owner = _site_owner(conn, domain)
            if not owner:
                return jsonify(ok=False, error="managed site not found"), 404
            result = webtools_call({"action": "site-control-hotlink", "domain": domain, "enabled": enabled, "extensions": extensions}, timeout=40)
            if not result.get("ok"):
                return jsonify(ok=False, error=str(result.get("error", "hotlink provider failed"))[:180]), 502
            _upsert(conn, domain, owner, hotlink_enabled=int(enabled), hotlink_extensions=extensions)
            settings = _settings(conn, domain)
        audit("site-control-hotlink", f"domain={domain} enabled={int(enabled)} extensions={','.join(extensions)}")
        return jsonify(ok=True, settings=settings)

    @app.put("/api/site-controls/indexing")
    @role_required("admin", "operator")
    @step_up_required
    def site_controls_indexing():
        denied = _feature("advanced.indexes")
        if denied:
            return denied
        data = request.get_json(silent=True) or {}
        domain = _domain(data.get("domain"))
        mode = str(data.get("mode", "off"))
        if not domain or mode not in {"on", "off"}:
            return jsonify(ok=False, error="invalid indexing configuration"), 400
        with db() as conn:
            owner = _site_owner(conn, domain)
            if not owner:
                return jsonify(ok=False, error="managed site not found"), 404
            result = webtools_call({"action": "site-control-indexing", "domain": domain, "mode": mode}, timeout=40)
            if not result.get("ok"):
                return jsonify(ok=False, error=str(result.get("error", "indexing provider failed"))[:180]), 502
            _upsert(conn, domain, owner, indexing_mode=mode)
            settings = _settings(conn, domain)
        audit("site-control-indexing", f"domain={domain} mode={mode}")
        return jsonify(ok=True, settings=settings)

    @app.put("/api/site-controls/mime")
    @role_required("admin", "operator")
    @step_up_required
    def site_controls_mime():
        denied = _feature("advanced.mime_types")
        if denied:
            return denied
        data = request.get_json(silent=True) or {}
        domain = _domain(data.get("domain"))
        mappings = data.get("mappings", {})
        if not domain or not isinstance(mappings, dict) or len(mappings) > 24:
            return jsonify(ok=False, error="invalid MIME configuration"), 400
        normalized: dict[str, str] = {}
        for extension, mime in mappings.items():
            ext = str(extension).strip().lower().lstrip(".")
            mtype = str(mime).strip().lower()
            if not SAFE_EXT_RE.fullmatch(ext) or not SAFE_MIME_RE.fullmatch(mtype) or ext in BLOCKED_MIME_EXTENSIONS:
                return jsonify(ok=False, error="invalid, sensitive or executable MIME override"), 400
            normalized[ext] = mtype
        with db() as conn:
            owner = _site_owner(conn, domain)
            if not owner:
                return jsonify(ok=False, error="managed site not found"), 404
            result = webtools_call({"action": "site-control-mime", "domain": domain, "mappings": normalized}, timeout=40)
            if not result.get("ok"):
                return jsonify(ok=False, error=str(result.get("error", "MIME provider failed"))[:180]), 502
            _upsert(conn, domain, owner, mime_overrides=normalized)
            settings = _settings(conn, domain)
        audit("site-control-mime", f"domain={domain} mappings={len(normalized)}")
        return jsonify(ok=True, settings=settings)

    @app.get("/api/site-controls/raw-access")
    @login_required
    def site_controls_raw_access():
        denied = _feature("metrics.raw_access")
        if denied:
            return denied
        domain = _domain(request.args.get("domain", ""))
        if not domain:
            return jsonify(ok=False, error="invalid or unauthorized domain"), 400
        try:
            lines = max(1, min(500, int(request.args.get("lines", 200))))
        except (TypeError, ValueError):
            lines = 200
        result = webtools_call({"action": "site-control-raw-access", "domain": domain, "lines": lines}, timeout=15)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "raw access unavailable"))[:180]), 502
        return jsonify(ok=True, domain=domain, lines=result.get("lines") or [], truncated=bool(result.get("truncated")), privacy_notice="Raw access intentionally contains client IP addresses and request paths.")
