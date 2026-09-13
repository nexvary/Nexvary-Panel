from __future__ import annotations

import json
import re
import time

from flask import jsonify, request, session

from .api_tokens import ALLOWED_SCOPES, bearer_scope, generate_token, hash_token
from .config import VERSION
from .core import audit, db
from .hosting_features import maturity_summary
from .security import role_required, step_up_required

TOKEN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")


def _token_rows() -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            "SELECT id,name,scopes_json,created_by,created_at,last_used_at,revoked_at FROM api_tokens ORDER BY id DESC LIMIT 200"
        ).fetchall()
    out = []
    for row in rows:
        try:
            scopes = json.loads(str(row["scopes_json"]))
        except Exception:
            scopes = []
        out.append({
            "id": int(row["id"]),
            "name": str(row["name"]),
            "scopes": scopes if isinstance(scopes, list) else [],
            "created_by": str(row["created_by"]),
            "created_at": int(row["created_at"]),
            "last_used_at": int(row["last_used_at"]) if row["last_used_at"] is not None else None,
            "revoked_at": int(row["revoked_at"]) if row["revoked_at"] is not None else None,
            "active": row["revoked_at"] is None,
        })
    return out


def register_api_token_routes(app):
    @app.get("/api/api-tokens")
    @role_required("admin")
    def api_token_list():
        return jsonify(ok=True, allowed_scopes=sorted(ALLOWED_SCOPES), tokens=_token_rows())

    @app.post("/api/api-tokens")
    @role_required("admin")
    @step_up_required
    def api_token_create():
        data = request.get_json(silent=True) or {}
        name = str(data.get("name", "")).strip()
        scopes = data.get("scopes")
        if not TOKEN_NAME_RE.fullmatch(name):
            return jsonify(ok=False, error="invalid token name"), 400
        if not isinstance(scopes, list) or not scopes or len(scopes) > len(ALLOWED_SCOPES):
            return jsonify(ok=False, error="invalid token scopes"), 400
        normalized = sorted({str(scope) for scope in scopes})
        if len(normalized) != len(scopes) or any(scope not in ALLOWED_SCOPES for scope in normalized):
            return jsonify(ok=False, error="invalid token scopes"), 400
        raw = generate_token()
        digest = hash_token(raw)
        now = int(time.time())
        actor = str(session.get("user", "admin"))[:64]
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO api_tokens(name,token_hash,scopes_json,created_by,created_at) VALUES(?,?,?,?,?)",
                (name, digest, json.dumps(normalized, separators=(",", ":")), actor, now),
            )
            token_id = int(cur.lastrowid)
        audit("api-token-create", f"id={token_id} name={name} scopes={','.join(normalized)}")
        return jsonify(ok=True, id=token_id, name=name, scopes=normalized, token=raw, shown_once=True), 201

    @app.delete("/api/api-tokens/<int:token_id>")
    @role_required("admin")
    @step_up_required
    def api_token_revoke(token_id: int):
        now = int(time.time())
        with db() as conn:
            row = conn.execute("SELECT id,name,revoked_at FROM api_tokens WHERE id=?", (token_id,)).fetchone()
            if not row:
                return jsonify(ok=False, error="token not found"), 404
            if row["revoked_at"] is None:
                conn.execute("UPDATE api_tokens SET revoked_at=? WHERE id=?", (now, token_id))
        audit("api-token-revoke", f"id={token_id} name={row['name']}")
        return jsonify(ok=True, id=token_id, revoked=True, revoked_at=now)

    @app.get("/api/v1/status")
    @bearer_scope("status:read")
    def api_v1_status():
        return jsonify(ok=True, panel="Nexvary Panel", version=VERSION, access="read-only-token")

    @app.get("/api/v1/sites")
    @bearer_scope("sites:read")
    def api_v1_sites():
        with db() as conn:
            rows = conn.execute("SELECT domain,kind,enabled,owner FROM sites ORDER BY domain LIMIT 500").fetchall()
        return jsonify(ok=True, sites=[dict(row) for row in rows])

    @app.get("/api/v1/hosting")
    @bearer_scope("hosting:read")
    def api_v1_hosting():
        with db() as conn:
            packages = conn.execute(
                "SELECT id,name,disk_mb,bandwidth_mb,max_sites,max_databases,max_mailboxes,max_ftp_accounts,max_cron_jobs,max_subdomains,max_backups FROM hosting_packages ORDER BY id LIMIT 200"
            ).fetchall()
        return jsonify(ok=True, maturity=maturity_summary(), packages=[dict(row) for row in packages])
