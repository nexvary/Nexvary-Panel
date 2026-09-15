from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from functools import wraps

from flask import g, jsonify, request

from .core import db

TOKEN_RE = re.compile(r"^nvp_[A-Za-z0-9_-]{40,96}$")
ALLOWED_SCOPES = frozenset({"status:read", "sites:read", "hosting:read"})


def generate_token() -> str:
    return "nvp_" + secrets.token_urlsafe(36)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def bearer_scope(required_scope: str):
    if required_scope not in ALLOWED_SCOPES:
        raise ValueError("unknown-api-token-scope")

    def decorate(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            header = str(request.headers.get("Authorization", ""))
            if not header.startswith("Bearer "):
                return jsonify(ok=False, error="bearer token required"), 401
            token = header[7:].strip()
            if not TOKEN_RE.fullmatch(token):
                return jsonify(ok=False, error="invalid bearer token"), 401
            digest = hash_token(token)
            with db() as conn:
                row = conn.execute(
                    "SELECT id,scopes_json,revoked_at FROM api_tokens WHERE token_hash=?",
                    (digest,),
                ).fetchone()
                if not row or row["revoked_at"] is not None:
                    return jsonify(ok=False, error="invalid bearer token"), 401
                try:
                    scopes = json.loads(str(row["scopes_json"]))
                except Exception:
                    return jsonify(ok=False, error="invalid bearer token"), 401
                if not isinstance(scopes, list) or any(scope not in ALLOWED_SCOPES for scope in scopes):
                    return jsonify(ok=False, error="invalid bearer token"), 401
                if required_scope not in scopes:
                    return jsonify(ok=False, error="token scope denied"), 403
                conn.execute("UPDATE api_tokens SET last_used_at=? WHERE id=?", (int(time.time()), int(row["id"])))
                g.api_token_id = int(row["id"])
                g.api_token_scopes = tuple(scopes)
            return fn(*args, **kwargs)
        return wrapped
    return decorate
