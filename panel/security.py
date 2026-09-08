from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from functools import wraps
from flask import flash, redirect, request, session, url_for
from .config import ADMIN_FILE
from .db_layer import db

FAILED: dict[str, dict[str, float | int]] = {}


def load_admin() -> dict[str, str]:
    vals = {"NVP_ADMIN_SALT": os.environ.get("NVP_ADMIN_SALT", ""), "NVP_ADMIN_HASH": os.environ.get("NVP_ADMIN_HASH", "")}
    if all(vals.values()):
        return vals
    try:
        if ADMIN_FILE.exists():
            for line in ADMIN_FILE.read_text().splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    key, value = line.split("=", 1)
                    vals[key.strip()] = value.strip()
    except PermissionError:
        pass
    return vals


def password_hash(password: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 310_000).hex()


def authenticate(username: str, password: str) -> tuple[bool, str]:
    if username == "admin":
        vals = load_admin()
        salt, expected = vals.get("NVP_ADMIN_SALT", ""), vals.get("NVP_ADMIN_HASH", "")
        if salt and expected:
            return hmac.compare_digest(password_hash(password, salt), expected), "admin"
        return False, "admin"
    with db() as conn:
        row = conn.execute("SELECT username,role,salt,password_hash,enabled FROM users WHERE username=?", (username,)).fetchone()
    if not row or not row["enabled"]:
        return False, "viewer"
    return hmac.compare_digest(password_hash(password, row["salt"]), row["password_hash"]), row["role"]


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def csrf_guard():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        if not token or not hmac.compare_digest(token, session.get("csrf", "")):
            return ("CSRF validation failed", 403)
    return None


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("auth"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped


def role_required(*roles: str):
    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("auth"):
                return redirect(url_for("login"))
            if session.get("role") not in roles:
                flash("ليس لديك صلاحية لتنفيذ هذه العملية.", "error")
                return redirect(url_for("home"))
            return fn(*args, **kwargs)
        return wrapped
    return deco
