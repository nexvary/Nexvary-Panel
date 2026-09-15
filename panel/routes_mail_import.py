from __future__ import annotations

import sqlite3
import time

from flask import jsonify, request

from .config import DOMAIN_RE, PASSWORD_RE
from .core import audit, db
from .mail_client import mail_call
from .routes_mail import EMAIL_RE, _domain_allowed, _mail_limits, _owner_feature_allowed, _valid_localpart
from .security import role_required, step_up_required

MAX_IMPORT_ENTRIES = 100


def _rollback_provider(created: list[dict]) -> list[str]:
    failed: list[str] = []
    for item in reversed(created):
        if item["kind"] == "mailbox":
            result = mail_call({"action": "mailbox-delete", "address": item["source"]}, timeout=30)
        else:
            result = mail_call({"action": "forwarder-delete", "source": item["source"]}, timeout=30)
        if not result.get("ok"):
            failed.append(item["source"])
    return failed


def _normalize_entries(domain: str, raw_entries: object) -> tuple[list[dict], str | None]:
    if not isinstance(raw_entries, list) or not 1 <= len(raw_entries) <= MAX_IMPORT_ENTRIES:
        return [], f"entries must contain 1-{MAX_IMPORT_ENTRIES} items"

    normalized: list[dict] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_entries):
        if not isinstance(raw, dict):
            return [], f"entry {index + 1} must be an object"
        kind = str(raw.get("kind", "")).strip().lower()
        localpart = str(raw.get("localpart", "")).strip()
        if kind not in {"mailbox", "forwarder"} or not _valid_localpart(localpart):
            return [], f"entry {index + 1} has invalid kind or localpart"
        source = f"{localpart}@{domain}"
        key = source.lower()
        if key in seen:
            return [], f"duplicate source address in import: {source}"
        seen.add(key)

        if kind == "mailbox":
            password = str(raw.get("password", ""))
            try:
                quota_mb = int(raw.get("quota_mb", 1024))
            except (TypeError, ValueError):
                quota_mb = 0
            if not PASSWORD_RE.fullmatch(password) or not 64 <= quota_mb <= 102400:
                return [], f"entry {index + 1} has invalid mailbox password or quota"
            normalized.append({
                "kind": "mailbox",
                "localpart": localpart,
                "source": source,
                "password": password,
                "quota_mb": quota_mb,
            })
            continue

        destination = str(raw.get("destination", "")).strip().lower()
        if len(destination) > 320 or not EMAIL_RE.fullmatch(destination) or ".." in destination.split("@", 1)[1]:
            return [], f"entry {index + 1} has invalid forwarder destination"
        if destination.lower() == source.lower():
            return [], f"entry {index + 1} creates a forwarding loop"
        normalized.append({
            "kind": "forwarder",
            "localpart": localpart,
            "source": source,
            "destination": destination,
        })
    return normalized, None


def register_mail_import_routes(app):
    @app.post("/api/mail/import")
    @role_required("admin", "operator")
    @step_up_required
    def mail_address_import():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        if not DOMAIN_RE.fullmatch(domain):
            return jsonify(ok=False, error="invalid mail domain"), 400
        entries, error = _normalize_entries(domain, data.get("entries"))
        if error:
            return jsonify(ok=False, error=error), 400

        mailbox_count = sum(1 for item in entries if item["kind"] == "mailbox")
        forwarder_count = len(entries) - mailbox_count
        with db() as conn:
            allowed, owner = _domain_allowed(conn, domain)
            if not allowed or not owner:
                return jsonify(ok=False, error="mail domain is outside your hosting scope"), 403
            if not _owner_feature_allowed(conn, owner, "email.address_importer"):
                return jsonify(ok=False, error="email.address_importer is disabled by target hosting policy"), 403
            if mailbox_count and not _owner_feature_allowed(conn, owner, "email.accounts"):
                return jsonify(ok=False, error="email.accounts is disabled by target hosting policy"), 403
            if forwarder_count and not _owner_feature_allowed(conn, owner, "email.forwarders"):
                return jsonify(ok=False, error="email.forwarders is disabled by target hosting policy"), 403

            mailbox_limit, forwarder_limit = _mail_limits(conn, owner)
            mailbox_used = int(conn.execute("SELECT COUNT(*) FROM mailboxes WHERE owner=?", (owner,)).fetchone()[0])
            forwarder_used = int(conn.execute("SELECT COUNT(*) FROM mail_forwarders WHERE owner=?", (owner,)).fetchone()[0])
            if mailbox_count and (mailbox_limit <= 0 or mailbox_used + mailbox_count > mailbox_limit):
                return jsonify(ok=False, error="mailbox quota would be exceeded by import"), 409
            if forwarder_count and (forwarder_limit <= 0 or forwarder_used + forwarder_count > forwarder_limit):
                return jsonify(ok=False, error="forwarder quota would be exceeded by import"), 409

            localparts = [item["localpart"] for item in entries]
            placeholders = ",".join("?" for _ in localparts)
            if localparts:
                existing_boxes = conn.execute(
                    f"SELECT localpart FROM mailboxes WHERE domain=? AND localpart IN ({placeholders})",
                    (domain, *localparts),
                ).fetchall()
                existing_forwarders = conn.execute(
                    f"SELECT localpart FROM mail_forwarders WHERE domain=? AND localpart IN ({placeholders})",
                    (domain, *localparts),
                ).fetchall()
                conflicts = {str(row[0]) for row in existing_boxes} | {str(row[0]) for row in existing_forwarders}
                if conflicts:
                    return jsonify(ok=False, error="address already exists", conflicts=sorted(conflicts)), 409

        created: list[dict] = []
        for item in entries:
            if item["kind"] == "mailbox":
                result = mail_call(
                    {"action": "mailbox-upsert", "address": item["source"], "password": item["password"]},
                    timeout=35,
                )
            else:
                result = mail_call(
                    {"action": "forwarder-upsert", "source": item["source"], "destination": item["destination"]},
                    timeout=30,
                )
            if not result.get("ok"):
                rollback_failed = _rollback_provider(created)
                payload = {
                    "ok": False,
                    "error": str(result.get("error", "mail provider failed"))[:160],
                    "failed_source": item["source"],
                    "rolled_back": not rollback_failed,
                }
                if rollback_failed:
                    payload["rollback_failed"] = rollback_failed
                return jsonify(payload), 502
            created.append(item)

        now = int(time.time())
        try:
            with db() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO mail_domains(domain,owner,enabled,created_at,updated_at) VALUES(?,?,1,?,?)",
                    (domain, owner, now, now),
                )
                for item in entries:
                    if item["kind"] == "mailbox":
                        conn.execute(
                            "INSERT INTO mailboxes(domain,localpart,quota_mb,enabled,owner,created_at,updated_at) VALUES(?,?,?,1,?,?,?)",
                            (domain, item["localpart"], item["quota_mb"], owner, now, now),
                        )
                    else:
                        conn.execute(
                            "INSERT INTO mail_forwarders(domain,localpart,destination,enabled,owner,created_at,updated_at) VALUES(?,?,?,1,?,?,?)",
                            (domain, item["localpart"], item["destination"], owner, now, now),
                        )
        except sqlite3.Error:
            rollback_failed = _rollback_provider(created)
            payload = {
                "ok": False,
                "error": "mail import metadata failed; provider rollback attempted",
                "rolled_back": not rollback_failed,
            }
            if rollback_failed:
                payload["rollback_failed"] = rollback_failed
            return jsonify(payload), 500

        audit(
            "mail-address-import",
            f"domain={domain} owner={owner} entries={len(entries)} mailboxes={mailbox_count} forwarders={forwarder_count}",
        )
        return jsonify(
            ok=True,
            domain=domain,
            owner=owner,
            imported=len(entries),
            mailboxes=mailbox_count,
            forwarders=forwarder_count,
        ), 201
