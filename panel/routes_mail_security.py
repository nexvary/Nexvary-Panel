from __future__ import annotations

import time

from flask import jsonify, request, session

from .config import PASSWORD_RE
from .core import audit, db
from .mail_client import mail_call
from .routes_mail import _owner_feature_allowed
from .security import role_required, step_up_required


def register_mail_security_routes(app):
    @app.put("/api/mail/mailboxes/<int:mailbox_id>/password")
    @role_required("admin", "operator")
    @step_up_required
    def mailbox_password_rotate(mailbox_id: int):
        data = request.get_json(silent=True) or {}
        password = str(data.get("password", ""))
        if not PASSWORD_RE.fullmatch(password):
            return jsonify(ok=False, error="invalid mailbox password"), 400

        with db() as conn:
            row = conn.execute(
                "SELECT id,domain,localpart,owner,enabled FROM mailboxes WHERE id=?",
                (mailbox_id,),
            ).fetchone()
            if not row:
                return jsonify(ok=False, error="mailbox not found"), 404
            owner = str(row["owner"])
            if session.get("role") != "admin" and owner != str(session.get("user", "")):
                return jsonify(ok=False, error="mailbox is outside your hosting scope"), 403
            if not int(row["enabled"]):
                return jsonify(ok=False, error="mailbox is disabled"), 409
            if not _owner_feature_allowed(conn, owner, "email.accounts"):
                return jsonify(ok=False, error="email.accounts is disabled by target hosting policy"), 403
            address = f"{row['localpart']}@{row['domain']}"

        result = mail_call({"action": "mailbox-upsert", "address": address, "password": password}, timeout=35)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "mail provider failed"))[:160]), 503

        now = int(time.time())
        with db() as conn:
            conn.execute("UPDATE mailboxes SET updated_at=? WHERE id=?", (now, mailbox_id))
        audit("mailbox-password-rotate", f"address={address} owner={owner}")
        return jsonify(ok=True, address=address, rotated=True, updated_at=now)
