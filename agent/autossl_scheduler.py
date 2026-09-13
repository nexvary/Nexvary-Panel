#!/usr/bin/env python3
from __future__ import annotations

import email.utils
import json
import os
import socket
import sqlite3
import time
from datetime import timezone
from pathlib import Path

DB_PATH = Path(os.environ.get("NVP_DB_PATH", "/var/lib/nexvary-panel/panel.db"))
OPS_SOCK = Path(os.environ.get("NVP_OPS_SOCK", "/run/nexvary-panel/ops.sock"))
MAX_REPLY = 256 * 1024
SSL_FEATURE = "security.ssl_tls"
MAX_NAMES = 25


def _ops(payload: dict, timeout: int = 240) -> dict:
    data = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > 64 * 1024:
        return {"ok": False, "error": "request-too-large"}
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(str(OPS_SOCK))
        sock.sendall(data)
        reply = b""
        while not reply.endswith(b"\n") and len(reply) < MAX_REPLY:
            chunk = sock.recv(8192)
            if not chunk:
                break
            reply += chunk
        if not reply.endswith(b"\n") or len(reply) >= MAX_REPLY:
            return {"ok": False, "error": "invalid-provider-reply"}
        parsed = json.loads(reply.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else {"ok": False, "error": "invalid-provider-reply"}
    except (OSError, ValueError, json.JSONDecodeError):
        return {"ok": False, "error": "ops-provider-unavailable"}
    finally:
        sock.close()


def _expiry_epoch(detail: object) -> int | None:
    if not isinstance(detail, str):
        return None
    for line in detail.splitlines():
        if line.startswith("notAfter="):
            value = line.split("=", 1)[1].strip()
            try:
                dt = email.utils.parsedate_to_datetime(value)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return int(dt.timestamp())
            except (TypeError, ValueError, OverflowError):
                return None
    return None


def _ssl_allowed(conn: sqlite3.Connection, owner: str) -> bool:
    if owner == "admin":
        return True
    user = conn.execute("SELECT role,enabled FROM users WHERE username=?", (owner,)).fetchone()
    if not user or not int(user["enabled"]):
        return False
    package = conn.execute(
        """SELECT p.id FROM user_hosting_package u JOIN hosting_packages p ON p.id=u.package_id
           WHERE u.username=? AND p.enabled=1""", (owner,)
    ).fetchone()
    if package is None:
        package = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core' AND enabled=1").fetchone()
    if package is None:
        return False
    explicit = conn.execute(
        "SELECT enabled FROM hosting_package_features WHERE package_id=? AND feature_id=?",
        (int(package["id"]), SSL_FEATURE),
    ).fetchone()
    return bool(int(explicit["enabled"])) if explicit is not None else True


def _desired_names(conn: sqlite3.Connection, domain: str) -> list[str]:
    names = [domain]
    try:
        rows = conn.execute("SELECT alias FROM domain_aliases WHERE domain=? ORDER BY alias LIMIT ?", (domain, MAX_NAMES - 1)).fetchall()
    except sqlite3.OperationalError:
        rows = []
    for row in rows:
        name = str(row["alias"] or "").strip().lower().rstrip(".")
        if name and name not in names:
            names.append(name)
    return names[:MAX_NAMES]


def _eligible(preflight: dict, fallback: list[str]) -> list[str]:
    values = preflight.get("eligible_domains")
    if isinstance(values, list):
        return [str(v).lower().rstrip(".") for v in values if isinstance(v, str)]
    return list(fallback) if preflight.get("ready") else []


def _preflight_detail(result: dict) -> str:
    checks = result.get("checks") if isinstance(result.get("checks"), list) else []
    failed = []
    for item in checks[:8]:
        if isinstance(item, dict) and not item.get("ready"):
            failed.append(f"{item.get('domain','?')}:{item.get('reason','not-ready')}")
    if result.get("ready") and not failed:
        return "AutoSSL HTTP-01 preflight passed for all names"
    if result.get("ready") and failed:
        return ("AutoSSL primary ready; excluded SANs: " + "; ".join(failed))[:700]
    return ("; ".join(failed) or str(result.get("error", "AutoSSL preflight failed")))[:700]


def _record(conn: sqlite3.Connection, domain: str, owner: str, status: str, detail: str, *, renewed: bool = False) -> None:
    now = int(time.time())
    conn.execute(
        """UPDATE ssl_policies SET last_check=?,last_renewal=CASE WHEN ? THEN ? ELSE last_renewal END,
           last_status=?,last_detail=?,updated_at=? WHERE domain=? AND owner=?""",
        (now, 1 if renewed else 0, now, status[:32], detail[:700], now, domain, owner),
    )
    conn.execute(
        "INSERT INTO audit(ts,actor,action,detail,ip) VALUES(?,?,?,?,?)",
        (now, "autossl", "autossl-check", f"domain={domain} status={status}"[:700], ""),
    )


def _preflight(domain: str, names: list[str]) -> dict:
    return _ops({"action": "ssl-preflight", "domain": domain, "domains": names}, timeout=35)


def run_once() -> int:
    if not DB_PATH.is_file():
        return 0
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        rows = conn.execute(
            """SELECT p.domain,p.owner,p.contact_email,p.renew_before_days,p.last_check
               FROM ssl_policies p JOIN sites s ON s.domain=p.domain
               WHERE p.auto_renew=1 AND s.enabled=1 ORDER BY p.last_check,p.domain LIMIT 200"""
        ).fetchall()
        now = int(time.time())
        for row in rows:
            domain = str(row["domain"])
            owner = str(row["owner"])
            names = _desired_names(conn, domain)
            if int(row["last_check"] or 0) > now - 3600:
                continue
            if not _ssl_allowed(conn, owner):
                _record(conn, domain, owner, "policy-disabled", "security.ssl_tls disabled or account inactive; no provider action executed")
                conn.commit()
                continue
            status = _ops({"action": "ssl-status", "domain": domain}, timeout=20)
            if not status.get("ok"):
                _record(conn, domain, owner, "check-failed", str(status.get("error", "ssl status unavailable")))
                conn.commit()
                continue
            contact = str(row["contact_email"] or "").strip().lower()
            if not status.get("installed"):
                if not contact:
                    _record(conn, domain, owner, "needs-contact", "certificate missing; contact email required for automatic issuance")
                    conn.commit()
                    continue
                preflight = _preflight(domain, names)
                if not preflight.get("ok") or not preflight.get("ready"):
                    _record(conn, domain, owner, "preflight-failed", _preflight_detail(preflight))
                    conn.commit()
                    continue
                result = _ops({"action": "ssl-issue", "domain": domain, "domains": names, "email": contact})
                state = "valid-partial" if result.get("ok") and result.get("excluded_names") else "valid" if result.get("ok") else "issue-failed"
                detail = _preflight_detail(result.get("preflight") or preflight) if result.get("ok") else str(result.get("detail", result.get("error", "")))
                _record(conn, domain, owner, state, detail, renewed=bool(result.get("ok")))
                conn.commit()
                continue

            current_names = [str(value).lower().rstrip(".") for value in (status.get("names") or []) if isinstance(value, str)]
            preflight = None
            if current_names and set(current_names) != set(names):
                preflight = _preflight(domain, names)
                if not preflight.get("ok") or not preflight.get("ready"):
                    _record(conn, domain, owner, "preflight-failed", _preflight_detail(preflight))
                    conn.commit()
                    continue
                eligible = _eligible(preflight, names)
                if set(current_names) != set(eligible):
                    if not contact:
                        _record(conn, domain, owner, "needs-contact", "certificate names changed; contact email required for SAN reconciliation")
                        conn.commit()
                        continue
                    result = _ops({"action": "ssl-issue", "domain": domain, "domains": names, "email": contact})
                    state = "valid-partial" if result.get("ok") and (result.get("excluded_names") or not preflight.get("fully_ready", True)) else "valid" if result.get("ok") else "san-update-failed"
                    detail = _preflight_detail(result.get("preflight") or preflight) if result.get("ok") else str(result.get("detail", result.get("error", "")))
                    _record(conn, domain, owner, state, detail, renewed=bool(result.get("ok")))
                    conn.commit()
                    continue

            expiry = _expiry_epoch(status.get("detail"))
            if expiry is None:
                _record(conn, domain, owner, "parse-failed", "certificate expiry could not be parsed")
                conn.commit()
                continue
            remaining = max(0, expiry - now)
            threshold = int(row["renew_before_days"] or 30) * 86400
            if remaining <= threshold:
                preflight = preflight or _preflight(domain, names)
                if not preflight.get("ok") or not preflight.get("ready"):
                    _record(conn, domain, owner, "preflight-failed", _preflight_detail(preflight))
                    conn.commit()
                    continue
                result = _ops({"action": "ssl-renew", "domain": domain, "domains": names, "email": contact})
                state = "valid-partial" if result.get("ok") and (result.get("excluded_names") or not preflight.get("fully_ready", True)) else "valid" if result.get("ok") else "renew-failed"
                detail = _preflight_detail(result.get("preflight") or preflight) if result.get("ok") else str(result.get("detail", result.get("error", "")))
                _record(conn, domain, owner, state, detail, renewed=bool(result.get("ok")))
            else:
                days = remaining // 86400
                if preflight and not preflight.get("fully_ready", True):
                    _record(conn, domain, owner, "valid-partial", f"certificate valid; {days} day(s) remaining; {_preflight_detail(preflight)}")
                else:
                    _record(conn, domain, owner, "valid", f"certificate valid; {days} day(s) remaining; names={len(names)}")
            conn.commit()
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(run_once())
