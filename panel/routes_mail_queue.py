from __future__ import annotations

import re

from flask import jsonify

from .core import audit
from .mail_client import mail_call
from .security import role_required, step_up_required

QUEUE_ID_RE = re.compile(r"^[A-Za-z0-9]{5,32}$")


def register_mail_queue_routes(app):
    @app.delete("/api/advanced/mail/queue/<queue_id>")
    @role_required("admin")
    @step_up_required
    def mail_queue_delete(queue_id: str):
        value = str(queue_id or "").strip()
        if not QUEUE_ID_RE.fullmatch(value):
            return jsonify(ok=False, error="invalid mail queue id"), 400
        result = mail_call({"action": "queue-delete", "queue_id": value}, timeout=20)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "mail queue delete failed"))[:160]), 503
        audit("mail-queue-delete", f"queue_id={value}")
        return jsonify(ok=True, queue_id=value, deleted=True)
