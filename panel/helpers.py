from __future__ import annotations

import subprocess
from flask import session
from .db_layer import db


def visible_owner_clause(alias: str = "") -> tuple[str, tuple]:
    prefix = f"{alias}." if alias else ""
    if session.get("role") == "admin":
        return "1=1", ()
    return f"{prefix}owner=?", (session.get("user", ""),)


def can_manage_domain(domain: str) -> bool:
    if session.get("role") == "admin":
        return True
    with db() as conn:
        row = conn.execute("SELECT owner FROM sites WHERE domain=?", (domain,)).fetchone()
    return bool(row and row["owner"] == session.get("user"))


def service(name: str) -> bool:
    names = [name] if name != "ssh" else ["ssh", "sshd"]
    for candidate in names:
        try:
            proc = subprocess.run(["systemctl", "is-active", candidate], capture_output=True, text=True, timeout=2)
            if proc.stdout.strip() == "active":
                return True
        except Exception:
            pass
    return False
