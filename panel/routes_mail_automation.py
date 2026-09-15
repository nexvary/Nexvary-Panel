from __future__ import annotations

import re
import time

from flask import jsonify, request, session

from .core import audit, db
from .mail_client import mail_call
from .routes_mail import _owner_feature_allowed
from .security import role_required, step_up_required

FILTER_FIELDS = {"from", "to", "subject", "spam_flag"}
MATCH_TYPES = {"contains", "is"}
FILTER_ACTIONS = {"fileinto", "redirect", "discard"}
FOLDER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}$")
MAX_FILTERS = 40
MAX_PATTERN = 200
MAX_VACATION_BODY = 5000


def _mailbox_scope(conn, mailbox_id: int):
    row = conn.execute(
        "SELECT id,domain,localpart,enabled,owner FROM mailboxes WHERE id=?",
        (mailbox_id,),
    ).fetchone()
    if not row:
        return None
    if session.get("role") != "admin" and str(row["owner"]) != str(session.get("user", "")):
        return None
    return row


def _feature(conn, owner: str, feature_id: str) -> bool:
    return _owner_feature_allowed(conn, owner, feature_id)


def _clean_text(value: object, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) > limit or any(ch in text for ch in "\x00\r"):
        raise ValueError("invalid text")
    return text


def _automation_payload(conn, mailbox) -> dict:
    mailbox_id = int(mailbox["id"])
    address = f"{mailbox['localpart']}@{mailbox['domain']}"
    auto = conn.execute(
        "SELECT enabled,subject,body,interval_days FROM mail_autoresponders WHERE mailbox_id=?",
        (mailbox_id,),
    ).fetchone()
    filters = conn.execute(
        """SELECT id,priority,field,match_type,pattern,action,destination,enabled
           FROM mail_filters WHERE mailbox_id=? ORDER BY priority,id""",
        (mailbox_id,),
    ).fetchall()
    spam = conn.execute(
        "SELECT enabled,action FROM mail_spam_policies WHERE mailbox_id=?",
        (mailbox_id,),
    ).fetchone()
    return {
        "action": "sieve-sync",
        "address": address,
        "autoresponder": dict(auto) if auto else {"enabled": 0, "subject": "", "body": "", "interval_days": 1},
        "filters": [dict(row) for row in filters],
        "spam": dict(spam) if spam else {"enabled": 0, "action": "junk"},
    }


def _sync(conn, mailbox) -> dict:
    return mail_call(_automation_payload(conn, mailbox), timeout=35)


def _inventory(conn, mailbox) -> dict:
    owner = str(mailbox["owner"])
    mailbox_id = int(mailbox["id"])
    auto = conn.execute(
        "SELECT enabled,subject,body,interval_days,updated_at FROM mail_autoresponders WHERE mailbox_id=?",
        (mailbox_id,),
    ).fetchone()
    filters = conn.execute(
        """SELECT id,priority,field,match_type,pattern,action,destination,enabled,created_at,updated_at
           FROM mail_filters WHERE mailbox_id=? ORDER BY priority,id""",
        (mailbox_id,),
    ).fetchall()
    spam = conn.execute(
        "SELECT enabled,action,updated_at FROM mail_spam_policies WHERE mailbox_id=?",
        (mailbox_id,),
    ).fetchone()
    return {
        "mailbox": {
            "id": mailbox_id,
            "address": f"{mailbox['localpart']}@{mailbox['domain']}",
            "enabled": bool(mailbox["enabled"]),
            "owner": owner,
        },
        "features": {
            "autoresponders": _feature(conn, owner, "email.autoresponders"),
            "filters": _feature(conn, owner, "email.filters"),
            "spam_filters": _feature(conn, owner, "email.spam_filters"),
        },
        "autoresponder": dict(auto) if auto else {"enabled": 0, "subject": "", "body": "", "interval_days": 1, "updated_at": 0},
        "filters": [dict(row) for row in filters],
        "spam": dict(spam) if spam else {"enabled": 0, "action": "junk", "updated_at": 0},
        "limits": {"max_filters": MAX_FILTERS},
    }


def register_mail_automation_routes(app):
    @app.get("/api/mail/automation/<int:mailbox_id>")
    @role_required("admin", "operator")
    def mail_automation_get(mailbox_id: int):
        with db() as conn:
            mailbox = _mailbox_scope(conn, mailbox_id)
            if not mailbox:
                return jsonify(ok=False, error="mailbox not found or outside your scope"), 404
            return jsonify(ok=True, **_inventory(conn, mailbox))

    @app.put("/api/mail/automation/<int:mailbox_id>/autoresponder")
    @role_required("admin", "operator")
    @step_up_required
    def mail_autoresponder_save(mailbox_id: int):
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        enabled = data.get("enabled")
        try:
            interval_days = int(data.get("interval_days", 1))
            subject = _clean_text(data.get("subject", ""), 180)
            body = _clean_text(data.get("body", ""), MAX_VACATION_BODY)
        except (TypeError, ValueError):
            return jsonify(ok=False, error="invalid autoresponder"), 400
        if not isinstance(enabled, bool) or not 1 <= interval_days <= 30:
            return jsonify(ok=False, error="invalid autoresponder"), 400
        if enabled and (not subject or not body):
            return jsonify(ok=False, error="subject and body are required when autoresponder is enabled"), 400
        now = int(time.time())
        with db() as conn:
            mailbox = _mailbox_scope(conn, mailbox_id)
            if not mailbox:
                return jsonify(ok=False, error="mailbox not found or outside your scope"), 404
            owner = str(mailbox["owner"])
            if enabled and not _feature(conn, owner, "email.autoresponders"):
                return jsonify(ok=False, error="email.autoresponders disabled by hosting policy"), 403
            conn.execute(
                """INSERT INTO mail_autoresponders(mailbox_id,enabled,subject,body,interval_days,owner,updated_at)
                   VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(mailbox_id) DO UPDATE SET enabled=excluded.enabled,subject=excluded.subject,
                     body=excluded.body,interval_days=excluded.interval_days,owner=excluded.owner,updated_at=excluded.updated_at""",
                (mailbox_id, 1 if enabled else 0, subject, body, interval_days, owner, now),
            )
            result = _sync(conn, mailbox)
            if not result.get("ok"):
                conn.rollback()
                return jsonify(ok=False, error=str(result.get("error", "mail automation provider failed"))[:180]), 503
            state = _inventory(conn, mailbox)
        audit("mail-autoresponder-policy", f"mailbox_id={mailbox_id} owner={owner} enabled={int(enabled)} interval_days={interval_days}")
        return jsonify(ok=True, **state)

    @app.post("/api/mail/automation/<int:mailbox_id>/filters")
    @role_required("admin", "operator")
    @step_up_required
    def mail_filter_create(mailbox_id: int):
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        field = str(data.get("field", "")).strip().lower()
        match_type = str(data.get("match_type", "")).strip().lower()
        action = str(data.get("action", "")).strip().lower()
        try:
            priority = int(data.get("priority", 100))
            pattern = _clean_text(data.get("pattern", ""), MAX_PATTERN)
            destination = _clean_text(data.get("destination", ""), 320)
        except (TypeError, ValueError):
            return jsonify(ok=False, error="invalid mail filter"), 400
        if field not in FILTER_FIELDS or match_type not in MATCH_TYPES or action not in FILTER_ACTIONS or not 1 <= priority <= 10000 or not pattern:
            return jsonify(ok=False, error="invalid mail filter"), 400
        if action == "fileinto" and not FOLDER_RE.fullmatch(destination):
            return jsonify(ok=False, error="fileinto requires a safe mailbox folder name"), 400
        if action == "redirect" and (not EMAIL_RE.fullmatch(destination) or ".." in destination):
            return jsonify(ok=False, error="redirect requires a valid destination address"), 400
        if action == "discard":
            destination = ""
        now = int(time.time())
        with db() as conn:
            mailbox = _mailbox_scope(conn, mailbox_id)
            if not mailbox:
                return jsonify(ok=False, error="mailbox not found or outside your scope"), 404
            owner = str(mailbox["owner"])
            if not _feature(conn, owner, "email.filters"):
                return jsonify(ok=False, error="email.filters disabled by hosting policy"), 403
            used = int(conn.execute("SELECT COUNT(*) FROM mail_filters WHERE mailbox_id=?", (mailbox_id,)).fetchone()[0])
            if used >= MAX_FILTERS:
                return jsonify(ok=False, error="mail filter limit reached"), 409
            cur = conn.execute(
                """INSERT INTO mail_filters(mailbox_id,priority,field,match_type,pattern,action,destination,enabled,owner,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,1,?,?,?)""",
                (mailbox_id, priority, field, match_type, pattern, action, destination, owner, now, now),
            )
            filter_id = int(cur.lastrowid)
            result = _sync(conn, mailbox)
            if not result.get("ok"):
                conn.rollback()
                return jsonify(ok=False, error=str(result.get("error", "mail automation provider failed"))[:180]), 503
            state = _inventory(conn, mailbox)
        audit("mail-filter-create", f"filter_id={filter_id} mailbox_id={mailbox_id} owner={owner} field={field} action={action}")
        return jsonify(ok=True, filter_id=filter_id, **state), 201

    @app.delete("/api/mail/automation/filters/<int:filter_id>")
    @role_required("admin", "operator")
    @step_up_required
    def mail_filter_delete(filter_id: int):
        with db() as conn:
            row = conn.execute("SELECT id,mailbox_id,owner FROM mail_filters WHERE id=?", (filter_id,)).fetchone()
            if not row:
                return jsonify(ok=False, error="mail filter not found"), 404
            mailbox = _mailbox_scope(conn, int(row["mailbox_id"]))
            if not mailbox:
                return jsonify(ok=False, error="mail filter outside your scope"), 403
            conn.execute("DELETE FROM mail_filters WHERE id=?", (filter_id,))
            result = _sync(conn, mailbox)
            if not result.get("ok"):
                conn.rollback()
                return jsonify(ok=False, error=str(result.get("error", "mail automation provider failed"))[:180]), 503
            state = _inventory(conn, mailbox)
        audit("mail-filter-delete", f"filter_id={filter_id} mailbox_id={row['mailbox_id']} owner={row['owner']}")
        return jsonify(ok=True, **state)

    @app.put("/api/mail/automation/<int:mailbox_id>/spam")
    @role_required("admin", "operator")
    @step_up_required
    def mail_spam_policy_save(mailbox_id: int):
        data = request.get_json(silent=True) or {}
        enabled = data.get("enabled")
        action = str(data.get("action", "junk")).strip().lower()
        if not isinstance(enabled, bool) or action not in {"junk", "discard"}:
            return jsonify(ok=False, error="invalid spam policy"), 400
        now = int(time.time())
        with db() as conn:
            mailbox = _mailbox_scope(conn, mailbox_id)
            if not mailbox:
                return jsonify(ok=False, error="mailbox not found or outside your scope"), 404
            owner = str(mailbox["owner"])
            if enabled and not _feature(conn, owner, "email.spam_filters"):
                return jsonify(ok=False, error="email.spam_filters disabled by hosting policy"), 403
            conn.execute(
                """INSERT INTO mail_spam_policies(mailbox_id,enabled,action,owner,updated_at) VALUES(?,?,?,?,?)
                   ON CONFLICT(mailbox_id) DO UPDATE SET enabled=excluded.enabled,action=excluded.action,
                     owner=excluded.owner,updated_at=excluded.updated_at""",
                (mailbox_id, 1 if enabled else 0, action, owner, now),
            )
            result = _sync(conn, mailbox)
            if not result.get("ok"):
                conn.rollback()
                return jsonify(ok=False, error=str(result.get("error", "mail automation provider failed"))[:180]), 503
            state = _inventory(conn, mailbox)
        audit("mail-spam-policy", f"mailbox_id={mailbox_id} owner={owner} enabled={int(enabled)} action={action}")
        return jsonify(ok=True, **state)
