from __future__ import annotations

import re

from flask import jsonify, request

from .core import audit, db
from .mail_client import mail_call
from .routes_mail import _domain_allowed, _owner_feature_allowed
from .security import role_required, step_up_required

QUEUE_ID_RE = re.compile(r"^[A-Za-z0-9]{5,32}$")


def register_mail_queue_routes(app):
    @app.get("/api/mail/trace")
    @role_required("admin", "operator")
    def mail_delivery_trace():
        domain = str(request.args.get("domain", "")).strip().lower().rstrip(".")
        try:
            limit = min(200, max(1, int(request.args.get("limit", 100))))
        except (TypeError, ValueError):
            return jsonify(ok=False, error="invalid delivery trace limit"), 400
        with db() as conn:
            allowed, owner = _domain_allowed(conn, domain)
            if not allowed or not owner:
                return jsonify(ok=False, error="mail domain is outside your hosting scope"), 403
            if not _owner_feature_allowed(conn, owner, "email.delivery_trace"):
                return jsonify(ok=False, error="email.delivery_trace is disabled by target hosting policy"), 403
        result = mail_call({"action": "delivery-trace", "domain": domain, "limit": limit}, timeout=12)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "delivery trace unavailable"))[:160]), 503
        events = result.get("events") if isinstance(result.get("events"), list) else []
        return jsonify(
            ok=True,
            domain=domain,
            source=str(result.get("source", ""))[:32],
            count=min(len(events), limit),
            events=events[:limit],
        )

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
