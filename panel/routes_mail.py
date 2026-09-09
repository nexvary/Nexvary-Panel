from __future__ import annotations

import re
import time

from flask import jsonify, request, session

from .config import DOMAIN_RE, PASSWORD_RE
from .core import audit, db
from .hosting_policy import feature_allowed, package_for_user
from .mail_client import mail_call
from .security import role_required, step_up_required

LOCALPART_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,62}[A-Za-z0-9])?$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}$")


def _valid_localpart(value: str) -> bool:
    return bool(LOCALPART_RE.fullmatch(value)) and ".." not in value


def _domain_owner(conn, domain: str) -> str | None:
    row = conn.execute("SELECT owner FROM sites WHERE domain=?", (domain,)).fetchone()
    if row:
        return str(row["owner"])
    row = conn.execute("SELECT username FROM hosting_accounts WHERE primary_domain=?", (domain,)).fetchone()
    if row:
        return str(row["username"])
    row = conn.execute("SELECT owner FROM mail_domains WHERE domain=?", (domain,)).fetchone()
    return str(row["owner"]) if row else None


def _owner_role(conn, owner: str) -> str:
    if owner == "admin":
        return "admin"
    row = conn.execute("SELECT role FROM users WHERE username=?", (owner,)).fetchone()
    return str(row["role"]) if row else "operator"


def _owner_feature_allowed(conn, owner: str, feature_id: str) -> bool:
    return feature_allowed(feature_id, username=owner, role=_owner_role(conn, owner))


def _domain_allowed(conn, domain: str) -> tuple[bool, str | None]:
    if not DOMAIN_RE.fullmatch(domain):
        return False, None
    owner = _domain_owner(conn, domain)
    if not owner:
        return False, None
    if session.get("role") == "admin":
        return True, owner
    return owner == session.get("user"), owner


def _mail_limits(conn, owner: str) -> tuple[int, int]:
    package = package_for_user(conn, owner, _owner_role(conn, owner))
    mailbox_limit = int(package["max_mailboxes"]) if package else 0
    # Forwarders use a bounded derived limit until a dedicated package column lands.
    forwarder_limit = min(100000, max(10, mailbox_limit * 5)) if mailbox_limit else 0
    return mailbox_limit, forwarder_limit


def _visible_clause() -> tuple[str, tuple]:
    if session.get("role") == "admin":
        return "1=1", ()
    return "owner=?", (str(session.get("user", ""))[:64],)


def _available_domains(conn) -> list[dict]:
    actor = str(session.get("user", ""))[:64]
    admin = session.get("role") == "admin"
    candidates: dict[str, str] = {}
    if admin:
        for row in conn.execute("SELECT domain,owner FROM sites WHERE enabled=1").fetchall():
            candidates[str(row["domain"])] = str(row["owner"])
        for row in conn.execute("SELECT primary_domain,username FROM hosting_accounts WHERE status='active'").fetchall():
            candidates[str(row["primary_domain"])] = str(row["username"])
    else:
        for row in conn.execute("SELECT domain,owner FROM sites WHERE enabled=1 AND owner=?", (actor,)).fetchall():
            candidates[str(row["domain"])] = actor
        row = conn.execute("SELECT primary_domain FROM hosting_accounts WHERE username=? AND status='active'", (actor,)).fetchone()
        if row:
            candidates[str(row["primary_domain"])] = actor
    for row in conn.execute("SELECT domain,owner FROM mail_domains").fetchall():
        owner = str(row["owner"])
        if admin or owner == actor:
            candidates[str(row["domain"])] = owner
    result = []
    for domain, owner in sorted(candidates.items()):
        mailbox_limit, forwarder_limit = _mail_limits(conn, owner)
        mailbox_used = int(conn.execute("SELECT COUNT(*) FROM mailboxes WHERE owner=?", (owner,)).fetchone()[0])
        forwarder_used = int(conn.execute("SELECT COUNT(*) FROM mail_forwarders WHERE owner=?", (owner,)).fetchone()[0])
        result.append({
            "domain": domain,
            "owner": owner,
            "email_accounts": _owner_feature_allowed(conn, owner, "email.accounts"),
            "email_forwarders": _owner_feature_allowed(conn, owner, "email.forwarders"),
            "mailbox_used": mailbox_used,
            "mailbox_limit": mailbox_limit,
            "forwarder_used": forwarder_used,
            "forwarder_limit": forwarder_limit,
        })
    return result


def register_mail_routes(app):
    @app.get("/api/mail")
    @role_required("admin", "operator")
    def mail_inventory():
        where, args = _visible_clause()
        username = str(session.get("user", ""))[:64]
        role = str(session.get("role", "operator"))
        with db() as conn:
            domains = [dict(r) for r in conn.execute(f"SELECT * FROM mail_domains WHERE {where} ORDER BY domain", args).fetchall()]
            mailboxes = [dict(r) for r in conn.execute(f"SELECT id,domain,localpart,quota_mb,enabled,owner,created_at,updated_at FROM mailboxes WHERE {where} ORDER BY domain,localpart", args).fetchall()]
            forwarders = [dict(r) for r in conn.execute(f"SELECT id,domain,localpart,destination,enabled,owner,created_at,updated_at FROM mail_forwarders WHERE {where} ORDER BY domain,localpart", args).fetchall()]
            package = package_for_user(conn, username, role)
            mailbox_limit = int(package["max_mailboxes"]) if package else 0
            forwarder_limit = min(100000, max(10, mailbox_limit * 5)) if mailbox_limit else 0
            available_domains = _available_domains(conn)
        provider = mail_call({"action": "status"}, timeout=5)
        return jsonify(
            ok=True,
            domains=domains,
            available_domains=available_domains,
            mailboxes=mailboxes,
            forwarders=forwarders,
            mailbox_limit=mailbox_limit,
            forwarder_limit=forwarder_limit,
            provider={"online": bool(provider.get("ok")), "engine": str(provider.get("engine", "postfix-dovecot") if provider.get("ok") else "offline")},
        )

    @app.post("/api/mail/mailboxes")
    @role_required("admin", "operator")
    @step_up_required
    def mailbox_create():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        domain = str(data.get("domain", "")).lower().strip()
        localpart = str(data.get("localpart", "")).strip()
        password = str(data.get("password", ""))
        try:
            quota_mb = int(data.get("quota_mb", 1024))
        except (TypeError, ValueError):
            quota_mb = 0
        if not _valid_localpart(localpart) or not PASSWORD_RE.fullmatch(password) or not 64 <= quota_mb <= 102400:
            return jsonify(ok=False, error="invalid mailbox localpart, password or quota"), 400
        with db() as conn:
            allowed, owner = _domain_allowed(conn, domain)
            if not allowed or not owner:
                return jsonify(ok=False, error="mail domain is not registered in your hosting scope"), 403
            if not _owner_feature_allowed(conn, owner, "email.accounts"):
                return jsonify(ok=False, error="email.accounts is disabled by target hosting policy"), 403
            mailbox_limit, _ = _mail_limits(conn, owner)
            used = int(conn.execute("SELECT COUNT(*) FROM mailboxes WHERE owner=?", (owner,)).fetchone()[0])
            if mailbox_limit <= 0 or used >= mailbox_limit:
                return jsonify(ok=False, error="mailbox quota reached"), 409
            if conn.execute("SELECT 1 FROM mailboxes WHERE domain=? AND localpart=?", (domain, localpart)).fetchone():
                return jsonify(ok=False, error="mailbox already exists"), 409
        address = f"{localpart}@{domain}"
        result = mail_call({"action": "mailbox-upsert", "address": address, "password": password}, timeout=35)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "mail provider failed"))[:160]), 503
        now = int(time.time())
        with db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO mail_domains(domain,owner,enabled,created_at,updated_at) VALUES(?,?,1,?,?)",
                (domain, owner, now, now),
            )
            conn.execute(
                "INSERT INTO mailboxes(domain,localpart,quota_mb,enabled,owner,created_at,updated_at) VALUES(?,?,?,1,?,?,?)",
                (domain, localpart, quota_mb, owner, now, now),
            )
        audit("mailbox-create", f"address={address} owner={owner} quota_mb={quota_mb}")
        return jsonify(ok=True, address=address), 201

    @app.delete("/api/mail/mailboxes/<int:mailbox_id>")
    @role_required("admin", "operator")
    @step_up_required
    def mailbox_delete(mailbox_id: int):
        with db() as conn:
            row = conn.execute("SELECT * FROM mailboxes WHERE id=?", (mailbox_id,)).fetchone()
            if not row:
                return jsonify(ok=False, error="mailbox not found"), 404
            if session.get("role") != "admin" and row["owner"] != session.get("user"):
                return jsonify(ok=False, error="mailbox is outside your hosting scope"), 403
            if not _owner_feature_allowed(conn, str(row["owner"]), "email.accounts"):
                return jsonify(ok=False, error="email.accounts is disabled by target hosting policy"), 403
        address = f"{row['localpart']}@{row['domain']}"
        result = mail_call({"action": "mailbox-delete", "address": address}, timeout=30)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "mail provider failed"))[:160]), 503
        with db() as conn:
            conn.execute("DELETE FROM mailboxes WHERE id=?", (mailbox_id,))
        audit("mailbox-delete", f"address={address} owner={row['owner']}")
        return jsonify(ok=True)

    @app.post("/api/mail/forwarders")
    @role_required("admin", "operator")
    @step_up_required
    def forwarder_create():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        domain = str(data.get("domain", "")).lower().strip()
        localpart = str(data.get("localpart", "")).strip()
        destination = str(data.get("destination", "")).strip()
        if not _valid_localpart(localpart) or len(destination) > 320 or not EMAIL_RE.fullmatch(destination) or ".." in destination.split("@", 1)[1]:
            return jsonify(ok=False, error="invalid forwarder address"), 400
        with db() as conn:
            allowed, owner = _domain_allowed(conn, domain)
            if not allowed or not owner:
                return jsonify(ok=False, error="mail domain is not registered in your hosting scope"), 403
            if not _owner_feature_allowed(conn, owner, "email.forwarders"):
                return jsonify(ok=False, error="email.forwarders is disabled by target hosting policy"), 403
            _, forwarder_limit = _mail_limits(conn, owner)
            used = int(conn.execute("SELECT COUNT(*) FROM mail_forwarders WHERE owner=?", (owner,)).fetchone()[0])
            if forwarder_limit <= 0 or used >= forwarder_limit:
                return jsonify(ok=False, error="forwarder quota reached"), 409
            if conn.execute("SELECT 1 FROM mail_forwarders WHERE domain=? AND localpart=?", (domain, localpart)).fetchone():
                return jsonify(ok=False, error="forwarder already exists"), 409
        source = f"{localpart}@{domain}"
        result = mail_call({"action": "forwarder-upsert", "source": source, "destination": destination}, timeout=30)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "mail provider failed"))[:160]), 503
        now = int(time.time())
        with db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO mail_domains(domain,owner,enabled,created_at,updated_at) VALUES(?,?,1,?,?)",
                (domain, owner, now, now),
            )
            conn.execute(
                "INSERT INTO mail_forwarders(domain,localpart,destination,enabled,owner,created_at,updated_at) VALUES(?,?,?,1,?,?,?)",
                (domain, localpart, destination, owner, now, now),
            )
        audit("mail-forwarder-create", f"source={source} destination={destination} owner={owner}")
        return jsonify(ok=True, source=source), 201

    @app.delete("/api/mail/forwarders/<int:forwarder_id>")
    @role_required("admin", "operator")
    @step_up_required
    def forwarder_delete(forwarder_id: int):
        with db() as conn:
            row = conn.execute("SELECT * FROM mail_forwarders WHERE id=?", (forwarder_id,)).fetchone()
            if not row:
                return jsonify(ok=False, error="forwarder not found"), 404
            if session.get("role") != "admin" and row["owner"] != session.get("user"):
                return jsonify(ok=False, error="forwarder is outside your hosting scope"), 403
            if not _owner_feature_allowed(conn, str(row["owner"]), "email.forwarders"):
                return jsonify(ok=False, error="email.forwarders is disabled by target hosting policy"), 403
        source = f"{row['localpart']}@{row['domain']}"
        result = mail_call({"action": "forwarder-delete", "source": source}, timeout=30)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "mail provider failed"))[:160]), 503
        with db() as conn:
            conn.execute("DELETE FROM mail_forwarders WHERE id=?", (forwarder_id,))
        audit("mail-forwarder-delete", f"source={source} owner={row['owner']}")
        return jsonify(ok=True)
