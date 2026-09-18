from __future__ import annotations

import re
import sqlite3
import time

from flask import jsonify, request, session

from .config import DOMAIN_RE, PASSWORD_RE
from .core import audit, db
from .mail_client import mail_call
from .mail_default_schema import ensure_mail_default_schema
from .routes_mail import _domain_allowed, _owner_feature_allowed
from .security import role_required, step_up_required

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}$")


def _default_state(conn, domain: str, owner: str) -> dict:
    row = conn.execute(
        "SELECT domain,mode,destination,owner,updated_at FROM mail_default_addresses WHERE domain=?",
        (domain,),
    ).fetchone()
    if not row:
        return {"domain": domain, "mode": "reject", "destination": "", "owner": owner, "updated_at": 0}
    return dict(row)


def _routing_state(conn, domain: str, owner: str) -> dict:
    row = conn.execute(
        "SELECT domain,mode,owner,updated_at FROM mail_routing_policies WHERE domain=?",
        (domain,),
    ).fetchone()
    if not row:
        return {"domain": domain, "mode": "local", "owner": owner, "updated_at": 0}
    return dict(row)


def _routing_conflicts(conn, domain: str) -> dict[str, int | bool]:
    mailboxes = int(conn.execute("SELECT COUNT(*) FROM mailboxes WHERE domain=?", (domain,)).fetchone()[0])
    forwarders = int(conn.execute("SELECT COUNT(*) FROM mail_forwarders WHERE domain=?", (domain,)).fetchone()[0])
    catchall = conn.execute(
        "SELECT mode FROM mail_default_addresses WHERE domain=?",
        (domain,),
    ).fetchone()
    catchall_forward = bool(catchall and str(catchall["mode"]) == "forward")
    return {"mailboxes": mailboxes, "forwarders": forwarders, "catchall_forward": catchall_forward}


def register_mail_security_routes(app):
    ensure_mail_default_schema()

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

    @app.get("/api/mail/default-address")
    @role_required("admin", "operator")
    def mail_default_address_get():
        domain = str(request.args.get("domain", "")).strip().lower().rstrip(".")
        if not DOMAIN_RE.fullmatch(domain):
            return jsonify(ok=False, error="invalid mail domain"), 400
        with db() as conn:
            allowed, owner = _domain_allowed(conn, domain)
            if not allowed or not owner:
                return jsonify(ok=False, error="mail domain is outside your hosting scope"), 403
            feature = _owner_feature_allowed(conn, owner, "email.default_address")
            state = _default_state(conn, domain, owner)
        return jsonify(ok=True, feature_allowed=feature, default_address=state)

    @app.put("/api/mail/default-address")
    @role_required("admin", "operator")
    @step_up_required
    def mail_default_address_save():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        mode = str(data.get("mode", "reject")).strip().lower()
        destination = str(data.get("destination", "")).strip().lower()
        if not DOMAIN_RE.fullmatch(domain) or mode not in {"reject", "forward"}:
            return jsonify(ok=False, error="invalid default-address policy"), 400
        if mode == "forward":
            if len(destination) > 320 or not EMAIL_RE.fullmatch(destination) or ".." in destination:
                return jsonify(ok=False, error="invalid catch-all destination"), 400
            if destination.rsplit("@", 1)[1].rstrip(".") == domain:
                return jsonify(ok=False, error="catch-all destination cannot point back into the same domain"), 400
        else:
            destination = ""

        with db() as conn:
            allowed, owner = _domain_allowed(conn, domain)
            if not allowed or not owner:
                return jsonify(ok=False, error="mail domain is outside your hosting scope"), 403
            if not _owner_feature_allowed(conn, owner, "email.default_address"):
                return jsonify(ok=False, error="email.default_address is disabled by target hosting policy"), 403
            previous = _default_state(conn, domain, owner)

        result = mail_call(
            {"action": "default-address-sync", "domain": domain, "mode": mode, "destination": destination},
            timeout=35,
        )
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "mail provider failed"))[:160]), 503

        now = int(time.time())
        try:
            with db() as conn:
                conn.execute(
                    """INSERT INTO mail_default_addresses(domain,mode,destination,owner,updated_at)
                       VALUES(?,?,?,?,?)
                       ON CONFLICT(domain) DO UPDATE SET mode=excluded.mode,destination=excluded.destination,
                         owner=excluded.owner,updated_at=excluded.updated_at""",
                    (domain, mode, destination, owner, now),
                )
                state = _default_state(conn, domain, owner)
        except sqlite3.Error:
            mail_call(
                {
                    "action": "default-address-sync",
                    "domain": domain,
                    "mode": str(previous["mode"]),
                    "destination": str(previous["destination"]),
                },
                timeout=35,
            )
            return jsonify(ok=False, error="default-address metadata failed; provider state restored"), 500

        audit("mail-default-address", f"domain={domain} owner={owner} mode={mode}")
        return jsonify(ok=True, default_address=state)

    @app.get("/api/mail/routing")
    @role_required("admin", "operator")
    def mail_routing_get():
        domain = str(request.args.get("domain", "")).strip().lower().rstrip(".")
        if not DOMAIN_RE.fullmatch(domain):
            return jsonify(ok=False, error="invalid mail domain"), 400
        with db() as conn:
            allowed, owner = _domain_allowed(conn, domain)
            if not allowed or not owner:
                return jsonify(ok=False, error="mail domain is outside your hosting scope"), 403
            feature = _owner_feature_allowed(conn, owner, "email.routing")
            state = _routing_state(conn, domain, owner)
            conflicts = _routing_conflicts(conn, domain)
        return jsonify(ok=True, feature_allowed=feature, routing=state, local_resources=conflicts)

    @app.put("/api/mail/routing")
    @role_required("admin", "operator")
    @step_up_required
    def mail_routing_save():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        mode = str(data.get("mode", "local")).strip().lower()
        if not DOMAIN_RE.fullmatch(domain) or mode not in {"local", "remote"}:
            return jsonify(ok=False, error="invalid mail routing policy"), 400

        with db() as conn:
            allowed, owner = _domain_allowed(conn, domain)
            if not allowed or not owner:
                return jsonify(ok=False, error="mail domain is outside your hosting scope"), 403
            if not _owner_feature_allowed(conn, owner, "email.routing"):
                return jsonify(ok=False, error="email.routing is disabled by target hosting policy"), 403
            previous = _routing_state(conn, domain, owner)
            conflicts = _routing_conflicts(conn, domain)
            if mode == "remote" and (
                int(conflicts["mailboxes"]) > 0
                or int(conflicts["forwarders"]) > 0
                or bool(conflicts["catchall_forward"])
            ):
                return jsonify(
                    ok=False,
                    error="remove local mailboxes, forwarders and catch-all forwarding before switching to remote routing",
                    local_resources=conflicts,
                ), 409

        result = mail_call({"action": "routing-sync", "domain": domain, "mode": mode}, timeout=35)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "mail provider failed"))[:160]), 503

        now = int(time.time())
        try:
            with db() as conn:
                conn.execute(
                    """INSERT INTO mail_routing_policies(domain,mode,owner,updated_at)
                       VALUES(?,?,?,?)
                       ON CONFLICT(domain) DO UPDATE SET mode=excluded.mode,owner=excluded.owner,
                         updated_at=excluded.updated_at""",
                    (domain, mode, owner, now),
                )
                state = _routing_state(conn, domain, owner)
        except sqlite3.Error:
            mail_call(
                {"action": "routing-sync", "domain": domain, "mode": str(previous["mode"])},
                timeout=35,
            )
            return jsonify(ok=False, error="mail-routing metadata failed; provider state restored"), 500

        audit("mail-routing", f"domain={domain} owner={owner} mode={mode}")
        return jsonify(ok=True, routing=state)
