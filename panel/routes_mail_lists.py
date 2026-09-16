from __future__ import annotations

import re
import sqlite3
import time

from flask import jsonify, request, session

from .config import DOMAIN_RE
from .core import audit, db
from .mail_client import mail_call
from .mail_list_schema import ensure_mail_list_schema
from .routes_mail import _domain_allowed, _mail_limits, _owner_feature_allowed
from .security import role_required, step_up_required

LOCALPART_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,62}[A-Za-z0-9])?$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}$")
MAX_MEMBERS = 100


def _valid_localpart(value: str) -> bool:
    return bool(LOCALPART_RE.fullmatch(value)) and ".." not in value


def _normalize_members(value: object, source: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_MEMBERS:
        raise ValueError("mailing list requires between 1 and 100 members")
    members: list[str] = []
    seen: set[str] = set()
    for raw in value:
        address = str(raw or "").strip().lower()
        if len(address) > 320 or not EMAIL_RE.fullmatch(address) or ".." in address:
            raise ValueError("invalid mailing list member")
        if address == source:
            raise ValueError("mailing list cannot contain itself")
        if address in seen:
            continue
        seen.add(address)
        members.append(address)
    if not members:
        raise ValueError("mailing list requires at least one unique member")
    return members


def _list_members(conn, list_id: int) -> list[str]:
    return [
        str(row["address"])
        for row in conn.execute(
            "SELECT address FROM mail_distribution_members WHERE list_id=? ORDER BY position,id",
            (list_id,),
        ).fetchall()
    ]


def _list_payload(conn, row) -> dict:
    return {
        "id": int(row["id"]),
        "domain": str(row["domain"]),
        "localpart": str(row["localpart"]),
        "address": f"{row['localpart']}@{row['domain']}",
        "owner": str(row["owner"]),
        "enabled": bool(row["enabled"]),
        "members": _list_members(conn, int(row["id"])),
        "created_at": int(row["created_at"]),
        "updated_at": int(row["updated_at"]),
    }


def _is_remote_route(conn, domain: str) -> bool:
    row = conn.execute("SELECT mode FROM mail_routing_policies WHERE domain=?", (domain,)).fetchone()
    return bool(row and str(row["mode"]) == "remote")


def _list_limit(conn, owner: str) -> int:
    mailbox_limit, _ = _mail_limits(conn, owner)
    if mailbox_limit <= 0:
        return 0
    return min(100, max(5, mailbox_limit))


def _would_create_cycle(conn, source: str, members: list[str], ignore_list_id: int | None = None) -> bool:
    rows = conn.execute("SELECT id,domain,localpart FROM mail_distribution_lists WHERE enabled=1").fetchall()
    sources = {int(row["id"]): f"{row['localpart']}@{row['domain']}" for row in rows}
    source_set = set(sources.values()) | {source}
    graph: dict[str, set[str]] = {address: set() for address in source_set}
    for list_id, address in sources.items():
        if ignore_list_id is not None and list_id == ignore_list_id:
            continue
        for member in _list_members(conn, list_id):
            if member in source_set:
                graph.setdefault(address, set()).add(member)
    for member in members:
        if member in source_set:
            graph.setdefault(source, set()).add(member)

    stack = list(graph.get(source, ()))
    seen: set[str] = set()
    while stack:
        node = stack.pop()
        if node == source:
            return True
        if node in seen:
            continue
        seen.add(node)
        stack.extend(graph.get(node, ()))
    return False


def register_mail_list_routes(app) -> None:
    ensure_mail_list_schema()

    @app.get("/api/mail/mailing-lists")
    @role_required("admin", "operator")
    def mailing_lists_inventory():
        actor = str(session.get("user", ""))[:64]
        if session.get("role") == "admin":
            where, args = "1=1", ()
        else:
            where, args = "owner=?", (actor,)
        with db() as conn:
            rows = conn.execute(
                f"SELECT * FROM mail_distribution_lists WHERE {where} ORDER BY domain,localpart",
                args,
            ).fetchall()
            items = [_list_payload(conn, row) for row in rows]
        return jsonify(ok=True, mailing_lists=items, max_members=MAX_MEMBERS)

    @app.post("/api/mail/mailing-lists")
    @role_required("admin", "operator")
    @step_up_required
    def mailing_list_create():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        localpart = str(data.get("localpart", "")).strip().lower()
        if not DOMAIN_RE.fullmatch(domain) or not _valid_localpart(localpart):
            return jsonify(ok=False, error="invalid mailing list address"), 400
        source = f"{localpart}@{domain}"
        try:
            members = _normalize_members(data.get("members"), source)
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400

        with db() as conn:
            allowed, owner = _domain_allowed(conn, domain)
            if not allowed or not owner:
                return jsonify(ok=False, error="mail domain is outside your hosting scope"), 403
            if not _owner_feature_allowed(conn, owner, "email.mailing_lists"):
                return jsonify(ok=False, error="email.mailing_lists is disabled by target hosting policy"), 403
            if _is_remote_route(conn, domain):
                return jsonify(ok=False, error="mailing lists require Local Mail Exchanger routing"), 409
            limit = _list_limit(conn, owner)
            used = int(conn.execute("SELECT COUNT(*) FROM mail_distribution_lists WHERE owner=?", (owner,)).fetchone()[0])
            if limit <= 0 or used >= limit:
                return jsonify(ok=False, error="mailing list quota reached"), 409
            if conn.execute("SELECT 1 FROM mailboxes WHERE domain=? AND localpart=?", (domain, localpart)).fetchone():
                return jsonify(ok=False, error="mailing list address conflicts with an existing mailbox"), 409
            if conn.execute("SELECT 1 FROM mail_forwarders WHERE domain=? AND localpart=?", (domain, localpart)).fetchone():
                return jsonify(ok=False, error="mailing list address conflicts with an existing forwarder"), 409
            if conn.execute("SELECT 1 FROM mail_distribution_lists WHERE domain=? AND localpart=?", (domain, localpart)).fetchone():
                return jsonify(ok=False, error="mailing list already exists"), 409
            if _would_create_cycle(conn, source, members):
                return jsonify(ok=False, error="mailing list membership would create a delivery loop"), 409

        result = mail_call(
            {"action": "mailing-list-sync", "address": source, "members": members, "expected_members": []},
            timeout=35,
        )
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "mail provider failed"))[:160]), 503

        now = int(time.time())
        try:
            with db() as conn:
                cur = conn.execute(
                    "INSERT INTO mail_distribution_lists(domain,localpart,owner,enabled,created_at,updated_at) VALUES(?,?,?,1,?,?)",
                    (domain, localpart, owner, now, now),
                )
                list_id = int(cur.lastrowid)
                conn.executemany(
                    "INSERT INTO mail_distribution_members(list_id,address,position,created_at) VALUES(?,?,?,?)",
                    [(list_id, address, index, now) for index, address in enumerate(members)],
                )
                row = conn.execute("SELECT * FROM mail_distribution_lists WHERE id=?", (list_id,)).fetchone()
                payload = _list_payload(conn, row)
        except sqlite3.Error:
            mail_call(
                {"action": "mailing-list-sync", "address": source, "members": [], "expected_members": members},
                timeout=35,
            )
            return jsonify(ok=False, error="mailing-list metadata failed; provider state restored"), 500

        audit("mailing-list-create", f"address={source} owner={owner} members={len(members)}")
        return jsonify(ok=True, mailing_list=payload), 201

    @app.put("/api/mail/mailing-lists/<int:list_id>")
    @role_required("admin", "operator")
    @step_up_required
    def mailing_list_update(list_id: int):
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400

        with db() as conn:
            row = conn.execute("SELECT * FROM mail_distribution_lists WHERE id=?", (list_id,)).fetchone()
            if not row:
                return jsonify(ok=False, error="mailing list not found"), 404
            owner = str(row["owner"])
            if session.get("role") != "admin" and owner != str(session.get("user", "")):
                return jsonify(ok=False, error="mailing list is outside your hosting scope"), 403
            if not _owner_feature_allowed(conn, owner, "email.mailing_lists"):
                return jsonify(ok=False, error="email.mailing_lists is disabled by target hosting policy"), 403
            domain = str(row["domain"])
            source = f"{row['localpart']}@{domain}"
            if _is_remote_route(conn, domain):
                return jsonify(ok=False, error="mailing lists require Local Mail Exchanger routing"), 409
            previous = _list_members(conn, list_id)
            try:
                members = _normalize_members(data.get("members"), source)
            except ValueError as exc:
                return jsonify(ok=False, error=str(exc)), 400
            if _would_create_cycle(conn, source, members, ignore_list_id=list_id):
                return jsonify(ok=False, error="mailing list membership would create a delivery loop"), 409

        result = mail_call(
            {"action": "mailing-list-sync", "address": source, "members": members, "expected_members": previous},
            timeout=35,
        )
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "mail provider failed"))[:160]), 503

        now = int(time.time())
        try:
            with db() as conn:
                conn.execute("DELETE FROM mail_distribution_members WHERE list_id=?", (list_id,))
                conn.executemany(
                    "INSERT INTO mail_distribution_members(list_id,address,position,created_at) VALUES(?,?,?,?)",
                    [(list_id, address, index, now) for index, address in enumerate(members)],
                )
                conn.execute("UPDATE mail_distribution_lists SET updated_at=? WHERE id=?", (now, list_id))
                row = conn.execute("SELECT * FROM mail_distribution_lists WHERE id=?", (list_id,)).fetchone()
                payload = _list_payload(conn, row)
        except sqlite3.Error:
            mail_call(
                {"action": "mailing-list-sync", "address": source, "members": previous, "expected_members": members},
                timeout=35,
            )
            return jsonify(ok=False, error="mailing-list metadata failed; provider state restored"), 500

        audit("mailing-list-update", f"address={source} owner={owner} members={len(members)}")
        return jsonify(ok=True, mailing_list=payload)

    @app.delete("/api/mail/mailing-lists/<int:list_id>")
    @role_required("admin", "operator")
    @step_up_required
    def mailing_list_delete(list_id: int):
        with db() as conn:
            row = conn.execute("SELECT * FROM mail_distribution_lists WHERE id=?", (list_id,)).fetchone()
            if not row:
                return jsonify(ok=False, error="mailing list not found"), 404
            owner = str(row["owner"])
            if session.get("role") != "admin" and owner != str(session.get("user", "")):
                return jsonify(ok=False, error="mailing list is outside your hosting scope"), 403
            if not _owner_feature_allowed(conn, owner, "email.mailing_lists"):
                return jsonify(ok=False, error="email.mailing_lists is disabled by target hosting policy"), 403
            source = f"{row['localpart']}@{row['domain']}"
            previous = _list_members(conn, list_id)

        result = mail_call(
            {"action": "mailing-list-sync", "address": source, "members": [], "expected_members": previous},
            timeout=35,
        )
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "mail provider failed"))[:160]), 503

        try:
            with db() as conn:
                conn.execute("DELETE FROM mail_distribution_members WHERE list_id=?", (list_id,))
                conn.execute("DELETE FROM mail_distribution_lists WHERE id=?", (list_id,))
        except sqlite3.Error:
            mail_call(
                {"action": "mailing-list-sync", "address": source, "members": previous, "expected_members": []},
                timeout=35,
            )
            return jsonify(ok=False, error="mailing-list metadata failed; provider state restored"), 500

        audit("mailing-list-delete", f"address={source} owner={owner} members={len(previous)}")
        return jsonify(ok=True, id=list_id)
