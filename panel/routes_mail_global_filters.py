from __future__ import annotations

import re
import time

from flask import jsonify, request, session

from .config import DOMAIN_RE
from .core import audit, db
from .mail_client import mail_call
from .routes_mail import EMAIL_RE, _domain_allowed, _owner_domains, _owner_feature_allowed
from .routes_mail_automation import _automation_payload
from .security import role_required, step_up_required

GLOBAL_FIELDS = {"from", "to", "subject", "header"}
MATCH_TYPES = {"contains", "is"}
FILTER_ACTIONS = {"fileinto", "redirect", "discard"}
HEADER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")
FOLDER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$")
MAX_GLOBAL_FILTERS = 30
MAX_PATTERN = 200


def _clean_text(value: object, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) > limit or any(ch in text for ch in "\x00\r\n"):
        raise ValueError("invalid text")
    return text


def _owner_rows(conn, owner: str) -> list[dict]:
    rows = conn.execute(
        """SELECT id,owner,priority,field,header_name,match_type,pattern,action,destination,
                  enabled,created_at,updated_at
           FROM mail_global_filters WHERE owner=? ORDER BY priority,id""",
        (owner,),
    ).fetchall()
    return [dict(row) for row in rows]


def _owner_mailboxes(conn, owner: str):
    return conn.execute(
        "SELECT id,domain,localpart,enabled,owner FROM mailboxes WHERE owner=? AND enabled=1 ORDER BY id",
        (owner,),
    ).fetchall()


def _scope_owner(conn, owner: str) -> bool:
    return session.get("role") == "admin" or str(session.get("user", "")) == owner


def _validate_filter(conn, owner: str, data: dict) -> tuple[dict | None, str | None]:
    field = str(data.get("field", "")).strip().lower()
    header_name = str(data.get("header_name", "")).strip()
    match_type = str(data.get("match_type", "")).strip().lower()
    action = str(data.get("action", "")).strip().lower()
    enabled = data.get("enabled", True)
    try:
        priority = int(data.get("priority", 100))
        pattern = _clean_text(data.get("pattern", ""), MAX_PATTERN)
        destination = _clean_text(data.get("destination", ""), 320)
    except (TypeError, ValueError):
        return None, "invalid global mail filter"
    if field not in GLOBAL_FIELDS or match_type not in MATCH_TYPES or action not in FILTER_ACTIONS:
        return None, "invalid global mail filter"
    if not isinstance(enabled, bool) or not pattern or not 1 <= priority <= 10000:
        return None, "invalid global mail filter"
    if field == "header":
        if not HEADER_RE.fullmatch(header_name):
            return None, "header field requires a safe RFC-style header name"
    else:
        header_name = ""
    if action == "fileinto":
        if not FOLDER_RE.fullmatch(destination):
            return None, "fileinto requires a safe mailbox folder name"
    elif action == "redirect":
        destination = destination.lower()
        if not EMAIL_RE.fullmatch(destination) or ".." in destination.rsplit("@", 1)[1]:
            return None, "redirect requires a valid destination address"
        destination_domain = destination.rsplit("@", 1)[1].rstrip(".")
        if destination_domain in set(_owner_domains(conn, owner)):
            return None, "redirect destination cannot target a domain in the same hosting account"
    else:
        destination = ""
    return {
        "priority": priority,
        "field": field,
        "header_name": header_name,
        "match_type": match_type,
        "pattern": pattern,
        "action": action,
        "destination": destination,
        "enabled": 1 if enabled else 0,
    }, None


def _sync_owner(conn, owner: str) -> tuple[dict, list]:
    applied = []
    for mailbox in _owner_mailboxes(conn, owner):
        result = mail_call(_automation_payload(conn, mailbox), timeout=35)
        if not result.get("ok"):
            return result, applied
        applied.append(mailbox)
    return {"ok": True, "mailboxes": len(applied)}, applied


def _restore_owner(conn, applied: list) -> list[str]:
    failed: list[str] = []
    for mailbox in reversed(applied):
        result = mail_call(_automation_payload(conn, mailbox), timeout=35)
        if not result.get("ok"):
            failed.append(f"{mailbox['localpart']}@{mailbox['domain']}")
    return failed


def register_mail_global_filter_routes(app):
    @app.get("/api/mail/global-filters")
    @role_required("admin", "operator")
    def mail_global_filters_get():
        domain = str(request.args.get("domain", "")).strip().lower().rstrip(".")
        if not DOMAIN_RE.fullmatch(domain):
            return jsonify(ok=False, error="invalid mail domain"), 400
        with db() as conn:
            allowed, owner = _domain_allowed(conn, domain)
            if not allowed or not owner:
                return jsonify(ok=False, error="mail domain is outside your hosting scope"), 403
            feature = _owner_feature_allowed(conn, owner, "email.global_filters")
            rows = _owner_rows(conn, owner)
            owner_domains = _owner_domains(conn, owner)
            mailbox_count = len(_owner_mailboxes(conn, owner))
        return jsonify(
            ok=True,
            owner=owner,
            scope="account",
            selected_domain=domain,
            owner_domains=owner_domains,
            feature_allowed=feature,
            filters=rows,
            mailbox_count=mailbox_count,
            max_filters=MAX_GLOBAL_FILTERS,
        )

    @app.post("/api/mail/global-filters")
    @role_required("admin", "operator")
    @step_up_required
    def mail_global_filter_create():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        if not DOMAIN_RE.fullmatch(domain):
            return jsonify(ok=False, error="invalid mail domain"), 400
        now = int(time.time())
        with db() as conn:
            allowed, owner = _domain_allowed(conn, domain)
            if not allowed or not owner:
                return jsonify(ok=False, error="mail domain is outside your hosting scope"), 403
            if not _owner_feature_allowed(conn, owner, "email.global_filters"):
                return jsonify(ok=False, error="email.global_filters is disabled by target hosting policy"), 403
            if len(_owner_rows(conn, owner)) >= MAX_GLOBAL_FILTERS:
                return jsonify(ok=False, error="global mail filter limit reached"), 409
            normalized, error = _validate_filter(conn, owner, data)
            if error or not normalized:
                return jsonify(ok=False, error=error or "invalid global mail filter"), 400
            cur = conn.execute(
                """INSERT INTO mail_global_filters(owner,priority,field,header_name,match_type,pattern,
                                                   action,destination,enabled,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    owner, normalized["priority"], normalized["field"], normalized["header_name"],
                    normalized["match_type"], normalized["pattern"], normalized["action"],
                    normalized["destination"], normalized["enabled"], now, now,
                ),
            )
            filter_id = int(cur.lastrowid)
            result, applied = _sync_owner(conn, owner)
            if not result.get("ok"):
                conn.rollback()
                rollback_failed = _restore_owner(conn, applied)
                return jsonify(
                    ok=False,
                    error=str(result.get("error", "mail global filter provider failed"))[:180],
                    rolled_back=not rollback_failed,
                    rollback_failed=rollback_failed,
                ), 503
            rows = _owner_rows(conn, owner)
            mailbox_count = len(_owner_mailboxes(conn, owner))
        audit(
            "mail-global-filter-create",
            f"filter_id={filter_id} owner={owner} field={normalized['field']} action={normalized['action']} mailboxes={mailbox_count}",
        )
        return jsonify(ok=True, filter_id=filter_id, owner=owner, filters=rows, mailbox_count=mailbox_count), 201

    @app.put("/api/mail/global-filters/<int:filter_id>")
    @role_required("admin", "operator")
    @step_up_required
    def mail_global_filter_update(filter_id: int):
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        now = int(time.time())
        with db() as conn:
            row = conn.execute("SELECT id,owner FROM mail_global_filters WHERE id=?", (filter_id,)).fetchone()
            if not row:
                return jsonify(ok=False, error="global mail filter not found"), 404
            owner = str(row["owner"])
            if not _scope_owner(conn, owner):
                return jsonify(ok=False, error="global mail filter is outside your hosting scope"), 403
            if not _owner_feature_allowed(conn, owner, "email.global_filters"):
                return jsonify(ok=False, error="email.global_filters is disabled by target hosting policy"), 403
            normalized, error = _validate_filter(conn, owner, data)
            if error or not normalized:
                return jsonify(ok=False, error=error or "invalid global mail filter"), 400
            conn.execute(
                """UPDATE mail_global_filters SET priority=?,field=?,header_name=?,match_type=?,pattern=?,
                       action=?,destination=?,enabled=?,updated_at=? WHERE id=?""",
                (
                    normalized["priority"], normalized["field"], normalized["header_name"],
                    normalized["match_type"], normalized["pattern"], normalized["action"],
                    normalized["destination"], normalized["enabled"], now, filter_id,
                ),
            )
            result, applied = _sync_owner(conn, owner)
            if not result.get("ok"):
                conn.rollback()
                rollback_failed = _restore_owner(conn, applied)
                return jsonify(
                    ok=False,
                    error=str(result.get("error", "mail global filter provider failed"))[:180],
                    rolled_back=not rollback_failed,
                    rollback_failed=rollback_failed,
                ), 503
            rows = _owner_rows(conn, owner)
            mailbox_count = len(_owner_mailboxes(conn, owner))
        audit(
            "mail-global-filter-update",
            f"filter_id={filter_id} owner={owner} field={normalized['field']} action={normalized['action']} enabled={normalized['enabled']} mailboxes={mailbox_count}",
        )
        return jsonify(ok=True, filter_id=filter_id, owner=owner, filters=rows, mailbox_count=mailbox_count)

    @app.delete("/api/mail/global-filters/<int:filter_id>")
    @role_required("admin", "operator")
    @step_up_required
    def mail_global_filter_delete(filter_id: int):
        with db() as conn:
            row = conn.execute("SELECT id,owner FROM mail_global_filters WHERE id=?", (filter_id,)).fetchone()
            if not row:
                return jsonify(ok=False, error="global mail filter not found"), 404
            owner = str(row["owner"])
            if not _scope_owner(conn, owner):
                return jsonify(ok=False, error="global mail filter is outside your hosting scope"), 403
            if not _owner_feature_allowed(conn, owner, "email.global_filters"):
                return jsonify(ok=False, error="email.global_filters is disabled by target hosting policy"), 403
            conn.execute("DELETE FROM mail_global_filters WHERE id=?", (filter_id,))
            result, applied = _sync_owner(conn, owner)
            if not result.get("ok"):
                conn.rollback()
                rollback_failed = _restore_owner(conn, applied)
                return jsonify(
                    ok=False,
                    error=str(result.get("error", "mail global filter provider failed"))[:180],
                    rolled_back=not rollback_failed,
                    rollback_failed=rollback_failed,
                ), 503
            rows = _owner_rows(conn, owner)
            mailbox_count = len(_owner_mailboxes(conn, owner))
        audit("mail-global-filter-delete", f"filter_id={filter_id} owner={owner} mailboxes={mailbox_count}")
        return jsonify(ok=True, id=filter_id, owner=owner, filters=rows, mailbox_count=mailbox_count)
