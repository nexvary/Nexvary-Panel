from __future__ import annotations

import base64
import hashlib
import re
import secrets
import sqlite3
import time

from flask import jsonify, request, session

from .core import audit, db
from .hosting_policy import enabled_features, package_for_user
from .security import role_required, step_up_required
from .transfer_client import transfer_call

LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$")
SYSTEM_USER_RE = re.compile(r"^nvpt_[a-f0-9]{10}$")
KEY_TYPES = {"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}


def _owner_role(conn, owner: str) -> str:
    if owner == "admin":
        return "admin"
    row = conn.execute("SELECT role FROM users WHERE username=?", (owner,)).fetchone()
    return str(row["role"]) if row else "operator"


def _feature_allowed(conn, owner: str) -> bool:
    role = _owner_role(conn, owner)
    package = package_for_user(conn, owner, role)
    package_id = int(package["id"]) if package else None
    return "files.ftp_accounts" in enabled_features(conn, package_id, role)


def _limit(conn, owner: str) -> int:
    package = package_for_user(conn, owner, _owner_role(conn, owner))
    return int(package["max_ftp_accounts"]) if package else 0


def _parse_public_key(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or not 40 <= len(value) <= 16384 or "\n" in value or "\r" in value or "\x00" in value:
        raise ValueError("invalid SSH public key")
    parts = value.strip().split(maxsplit=2)
    if len(parts) < 2 or parts[0] not in KEY_TYPES:
        raise ValueError("only modern OpenSSH public keys are accepted")
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except Exception as exc:
        raise ValueError("invalid SSH public key encoding") from exc
    if not 32 <= len(raw) <= 8192:
        raise ValueError("invalid SSH public key payload")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    normalized = f"{parts[0]} {parts[1]}"
    return normalized, fingerprint


def _site_scope(conn, domain: str) -> tuple[bool, str | None]:
    row = conn.execute("SELECT domain,owner,enabled FROM sites WHERE domain=?", (domain,)).fetchone()
    if not row or not row["enabled"]:
        return False, None
    owner = str(row["owner"])
    if session.get("role") == "admin" or owner == session.get("user"):
        return True, owner
    return False, owner


def _visible_where() -> tuple[str, tuple]:
    if session.get("role") == "admin":
        return "1=1", ()
    return "owner=?", (str(session.get("user", ""))[:64],)


def register_transfer_routes(app):
    @app.get("/api/transfers")
    @role_required("admin", "operator")
    def transfer_inventory():
        where, args = _visible_where()
        with db() as conn:
            accounts = [dict(r) for r in conn.execute(
                f"SELECT id,label,system_user,domain,owner,key_fingerprint,enabled,created_at,updated_at FROM transfer_accounts WHERE {where} ORDER BY created_at DESC",
                args,
            ).fetchall()]
            sites = []
            site_rows = conn.execute("SELECT domain,owner FROM sites WHERE enabled=1 ORDER BY domain").fetchall() if session.get("role") == "admin" else conn.execute(
                "SELECT domain,owner FROM sites WHERE enabled=1 AND owner=? ORDER BY domain", (session.get("user"),)
            ).fetchall()
            for row in site_rows:
                owner = str(row["owner"])
                sites.append({
                    "domain": str(row["domain"]), "owner": owner,
                    "enabled": _feature_allowed(conn, owner),
                    "used": int(conn.execute("SELECT COUNT(*) FROM transfer_accounts WHERE owner=?", (owner,)).fetchone()[0]),
                    "limit": _limit(conn, owner),
                })
            actor = str(session.get("user", ""))[:64]
            actor_limit = _limit(conn, actor)
            actor_used = int(conn.execute("SELECT COUNT(*) FROM transfer_accounts WHERE owner=?", (actor,)).fetchone()[0])
        provider = transfer_call({"action": "status"}, timeout=5)
        return jsonify(ok=True, accounts=accounts, sites=sites, used=actor_used, limit=actor_limit,
                       provider={"online": bool(provider.get("ok")), "engine": str(provider.get("engine", "openssh-internal-sftp") if provider.get("ok") else "offline")})

    @app.post("/api/transfers")
    @role_required("admin", "operator")
    @step_up_required
    def transfer_create():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        label = str(data.get("label", "")).strip()
        domain = str(data.get("domain", "")).strip().lower()
        if not LABEL_RE.fullmatch(label):
            return jsonify(ok=False, error="transfer label must be 3-32 safe characters"), 400
        try:
            public_key, fingerprint = _parse_public_key(str(data.get("public_key", "")))
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        with db() as conn:
            allowed, owner = _site_scope(conn, domain)
            if not allowed or not owner:
                return jsonify(ok=False, error="site is outside your transfer scope"), 403
            if not _feature_allowed(conn, owner):
                return jsonify(ok=False, error="files.ftp_accounts is disabled by target hosting policy"), 403
            limit = _limit(conn, owner)
            used = int(conn.execute("SELECT COUNT(*) FROM transfer_accounts WHERE owner=?", (owner,)).fetchone()[0])
            if limit <= 0 or used >= limit:
                return jsonify(ok=False, error="transfer account quota reached"), 409
            if conn.execute("SELECT 1 FROM transfer_accounts WHERE owner=? AND label=?", (owner, label)).fetchone():
                return jsonify(ok=False, error="transfer label already exists"), 409
        system_user = "nvpt_" + secrets.token_hex(5)
        if not SYSTEM_USER_RE.fullmatch(system_user):
            return jsonify(ok=False, error="transfer identity generation failed"), 500
        result = transfer_call({"action": "account-create", "system_user": system_user, "domain": domain, "public_key": public_key}, timeout=45)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "transfer provider failed"))[:160]), 503
        now = int(time.time())
        try:
            with db() as conn:
                cur = conn.execute(
                    "INSERT INTO transfer_accounts(label,system_user,domain,owner,key_fingerprint,enabled,created_at,updated_at) VALUES(?,?,?,?,?,1,?,?)",
                    (label, system_user, domain, owner, fingerprint, now, now),
                )
                transfer_id = int(cur.lastrowid)
        except sqlite3.IntegrityError:
            transfer_call({"action": "account-delete", "system_user": system_user, "domain": domain}, timeout=35)
            return jsonify(ok=False, error="transfer account metadata conflict"), 409
        audit("transfer-account-create", f"id={transfer_id} label={label} domain={domain} owner={owner} fingerprint={fingerprint}")
        return jsonify(ok=True, id=transfer_id, label=label, fingerprint=fingerprint), 201

    @app.put("/api/transfers/<int:transfer_id>/key")
    @role_required("admin", "operator")
    @step_up_required
    def transfer_rotate_key(transfer_id: int):
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        try:
            public_key, fingerprint = _parse_public_key(str(data.get("public_key", "")))
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        with db() as conn:
            row = conn.execute("SELECT * FROM transfer_accounts WHERE id=?", (transfer_id,)).fetchone()
            if not row:
                return jsonify(ok=False, error="transfer account not found"), 404
            if session.get("role") != "admin" and row["owner"] != session.get("user"):
                return jsonify(ok=False, error="transfer account is outside your scope"), 403
            if not _feature_allowed(conn, str(row["owner"])):
                return jsonify(ok=False, error="files.ftp_accounts is disabled by target hosting policy"), 403
        result = transfer_call({"action": "key-update", "system_user": row["system_user"], "public_key": public_key}, timeout=25)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "transfer provider failed"))[:160]), 503
        with db() as conn:
            conn.execute("UPDATE transfer_accounts SET key_fingerprint=?,updated_at=? WHERE id=?", (fingerprint, int(time.time()), transfer_id))
        audit("transfer-key-rotate", f"id={transfer_id} owner={row['owner']} fingerprint={fingerprint}")
        return jsonify(ok=True, fingerprint=fingerprint)

    @app.delete("/api/transfers/<int:transfer_id>")
    @role_required("admin", "operator")
    @step_up_required
    def transfer_delete(transfer_id: int):
        with db() as conn:
            row = conn.execute("SELECT * FROM transfer_accounts WHERE id=?", (transfer_id,)).fetchone()
            if not row:
                return jsonify(ok=False, error="transfer account not found"), 404
            if session.get("role") != "admin" and row["owner"] != session.get("user"):
                return jsonify(ok=False, error="transfer account is outside your scope"), 403
        result = transfer_call({"action": "account-delete", "system_user": row["system_user"], "domain": row["domain"]}, timeout=40)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "transfer provider failed"))[:160]), 503
        with db() as conn:
            conn.execute("DELETE FROM transfer_accounts WHERE id=?", (transfer_id,))
        audit("transfer-account-delete", f"id={transfer_id} label={row['label']} domain={row['domain']} owner={row['owner']}")
        return jsonify(ok=True)
