from __future__ import annotations

import sqlite3
import time

from flask import jsonify, request, session

from .config import PASSWORD_RE
from .core import audit, db
from .dav_client import dav_call
from .hosting_policy import enabled_features, package_for_user
from .mail_dav_schema import ensure_mail_dav_schema
from .security import role_required, step_up_required

FEATURE_ID = "email.calendars_contacts"


def _owner_role(conn, owner: str) -> str:
    if owner == "admin":
        return "admin"
    row = conn.execute("SELECT role FROM users WHERE username=?", (owner,)).fetchone()
    return str(row["role"]) if row else "operator"


def _feature_allowed(conn, owner: str) -> bool:
    role = _owner_role(conn, owner)
    package = package_for_user(conn, owner, role)
    package_id = int(package["id"]) if package else None
    return FEATURE_ID in enabled_features(conn, package_id, role)


def _mailbox(conn, mailbox_id: int):
    return conn.execute(
        "SELECT id,domain,localpart,enabled,owner FROM mailboxes WHERE id=?",
        (mailbox_id,),
    ).fetchone()


def _in_scope(owner: str) -> bool:
    return session.get("role") == "admin" or owner == str(session.get("user", ""))


def _address(row) -> str:
    return f"{row['localpart']}@{row['domain']}".lower()


def _inventory(conn) -> tuple[list[dict], list[dict]]:
    if session.get("role") == "admin":
        mailboxes = conn.execute(
            "SELECT id,domain,localpart,enabled,owner FROM mailboxes WHERE enabled=1 ORDER BY owner,domain,localpart"
        ).fetchall()
        accounts = conn.execute(
            """SELECT d.id,d.mailbox_id,d.username,d.owner,d.enabled,d.created_at,d.updated_at
               FROM mail_dav_accounts d ORDER BY d.owner,d.username"""
        ).fetchall()
    else:
        actor = str(session.get("user", ""))[:64]
        mailboxes = conn.execute(
            "SELECT id,domain,localpart,enabled,owner FROM mailboxes WHERE enabled=1 AND owner=? ORDER BY domain,localpart",
            (actor,),
        ).fetchall()
        accounts = conn.execute(
            """SELECT d.id,d.mailbox_id,d.username,d.owner,d.enabled,d.created_at,d.updated_at
               FROM mail_dav_accounts d WHERE d.owner=? ORDER BY d.username""",
            (actor,),
        ).fetchall()
    mailbox_payload = []
    for row in mailboxes:
        owner = str(row["owner"])
        mailbox_payload.append({
            "id": int(row["id"]),
            "address": _address(row),
            "owner": owner,
            "feature_allowed": _feature_allowed(conn, owner),
        })
    return mailbox_payload, [dict(row) for row in accounts]


def register_mail_dav_routes(app):
    ensure_mail_dav_schema()

    @app.get("/api/mail/dav")
    @role_required("admin", "operator")
    def dav_inventory():
        with db() as conn:
            mailboxes, accounts = _inventory(conn)
        provider = dav_call({"action": "status"}, timeout=5)
        return jsonify(
            ok=True,
            endpoint="/dav/",
            discovery={"caldav": "/.well-known/caldav", "carddav": "/.well-known/carddav"},
            provider={
                "online": bool(provider.get("ok") and provider.get("online")),
                "engine": str(provider.get("engine", "radicale-caldav-carddav")),
            },
            mailboxes=mailboxes,
            accounts=accounts,
        )

    @app.post("/api/mail/dav/accounts")
    @role_required("admin", "operator")
    @step_up_required
    def dav_create():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        try:
            mailbox_id = int(data.get("mailbox_id", 0))
        except (TypeError, ValueError):
            mailbox_id = 0
        password = str(data.get("password", ""))
        if mailbox_id < 1 or not PASSWORD_RE.fullmatch(password):
            return jsonify(ok=False, error="invalid mailbox or DAV password"), 400

        with db() as conn:
            row = _mailbox(conn, mailbox_id)
            if not row or not int(row["enabled"]):
                return jsonify(ok=False, error="mailbox not found"), 404
            owner = str(row["owner"])
            if not _in_scope(owner):
                return jsonify(ok=False, error="mailbox is outside your hosting scope"), 403
            if not _feature_allowed(conn, owner):
                return jsonify(ok=False, error=f"{FEATURE_ID} is disabled by target hosting policy"), 403
            if conn.execute("SELECT 1 FROM mail_dav_accounts WHERE mailbox_id=?", (mailbox_id,)).fetchone():
                return jsonify(ok=False, error="DAV account already exists for mailbox"), 409
            username = _address(row)

        result = dav_call(
            {"action": "credential-sync", "username": username, "password": password, "expected_present": False},
            timeout=35,
        )
        password = ""
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "DAV provider failed"))[:160]), 503

        now = int(time.time())
        try:
            with db() as conn:
                cur = conn.execute(
                    """INSERT INTO mail_dav_accounts(mailbox_id,username,owner,enabled,created_at,updated_at)
                       VALUES(?,?,?,1,?,?)""",
                    (mailbox_id, username, owner, now, now),
                )
                account_id = int(cur.lastrowid)
                account = dict(conn.execute("SELECT * FROM mail_dav_accounts WHERE id=?", (account_id,)).fetchone())
        except sqlite3.Error:
            dav_call({"action": "credential-delete", "username": username}, timeout=35)
            return jsonify(ok=False, error="DAV metadata failed; provider credential removed"), 500

        audit("dav-account-create", f"address={username} owner={owner}")
        return jsonify(ok=True, account=account, endpoint="/dav/"), 201

    @app.put("/api/mail/dav/accounts/<int:account_id>")
    @role_required("admin", "operator")
    @step_up_required
    def dav_rotate(account_id: int):
        data = request.get_json(silent=True) or {}
        password = str(data.get("password", "")) if isinstance(data, dict) else ""
        if not PASSWORD_RE.fullmatch(password):
            return jsonify(ok=False, error="invalid DAV password"), 400
        with db() as conn:
            row = conn.execute("SELECT * FROM mail_dav_accounts WHERE id=?", (account_id,)).fetchone()
            if not row:
                return jsonify(ok=False, error="DAV account not found"), 404
            owner = str(row["owner"])
            if not _in_scope(owner):
                return jsonify(ok=False, error="DAV account is outside your hosting scope"), 403
            if not _feature_allowed(conn, owner):
                return jsonify(ok=False, error=f"{FEATURE_ID} is disabled by target hosting policy"), 403
            username = str(row["username"])

        result = dav_call(
            {"action": "credential-sync", "username": username, "password": password, "expected_present": True},
            timeout=35,
        )
        password = ""
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "DAV provider failed"))[:160]), 503
        now = int(time.time())
        with db() as conn:
            conn.execute("UPDATE mail_dav_accounts SET updated_at=?,enabled=1 WHERE id=?", (now, account_id))
            account = dict(conn.execute("SELECT * FROM mail_dav_accounts WHERE id=?", (account_id,)).fetchone())
        audit("dav-account-rotate", f"address={username} owner={owner}")
        return jsonify(ok=True, account=account, endpoint="/dav/")

    @app.delete("/api/mail/dav/accounts/<int:account_id>")
    @role_required("admin", "operator")
    @step_up_required
    def dav_delete(account_id: int):
        with db() as conn:
            row = conn.execute("SELECT * FROM mail_dav_accounts WHERE id=?", (account_id,)).fetchone()
            if not row:
                return jsonify(ok=False, error="DAV account not found"), 404
            owner = str(row["owner"])
            if not _in_scope(owner):
                return jsonify(ok=False, error="DAV account is outside your hosting scope"), 403
            if not _feature_allowed(conn, owner):
                return jsonify(ok=False, error=f"{FEATURE_ID} is disabled by target hosting policy"), 403
            username = str(row["username"])

        result = dav_call({"action": "credential-delete", "username": username}, timeout=35)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "DAV provider failed"))[:160]), 503
        try:
            with db() as conn:
                conn.execute("DELETE FROM mail_dav_accounts WHERE id=?", (account_id,))
        except sqlite3.Error:
            return jsonify(ok=False, error="DAV credential revoked but metadata cleanup failed; retry deletion"), 500
        audit("dav-account-delete", f"address={username} owner={owner}")
        return jsonify(ok=True, id=account_id)
