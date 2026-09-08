from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from functools import wraps
from urllib.parse import quote

from flask import flash, jsonify, redirect, request, session, url_for
from .config import ADMIN_FILE
from .db_layer import db

FAILED: dict[str, dict[str, float | int]] = {}
STEP_UP_TTL_SECONDS = 300


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
    return hmac.compare_digest(password_hash(password, row["salt"],), row["password_hash"]), row["role"]


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _totp(secret: str, timestamp: int | None = None) -> str:
    ts = int(time.time() if timestamp is None else timestamp)
    counter = ts // 30
    padded = secret.upper() + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{value:06d}"


def verify_totp_secret(secret: str, code: str) -> bool:
    if not secret or not isinstance(code, str) or not code.isdigit() or len(code) != 6:
        return False
    now = int(time.time())
    try:
        return any(hmac.compare_digest(_totp(secret, now + delta * 30), code) for delta in (-1, 0, 1))
    except Exception:
        return False


def totp_enabled_for(username: str) -> bool:
    if not username:
        return False
    with db() as conn:
        row = conn.execute("SELECT totp_enabled FROM user_security WHERE username=?", (username,)).fetchone()
    return bool(row and row["totp_enabled"])


def verify_totp(username: str, code: str) -> bool:
    with db() as conn:
        row = conn.execute("SELECT totp_secret,totp_enabled FROM user_security WHERE username=?", (username,)).fetchone()
    return bool(row and row["totp_enabled"] and verify_totp_secret(row["totp_secret"], code))


def totp_uri(username: str, secret: str) -> str:
    issuer = "Nexvary Panel"
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def step_up_active() -> bool:
    try:
        return bool(session.get("auth") and int(session.get("step_up_until", 0)) >= int(time.time()))
    except (TypeError, ValueError):
        return False


def grant_step_up() -> int:
    until = int(time.time()) + STEP_UP_TTL_SECONDS
    session["step_up_until"] = until
    session["step_up_user"] = session.get("user", "")
    return until


def clear_step_up() -> None:
    session.pop("step_up_until", None)
    session.pop("step_up_user", None)


def verify_step_up_credentials(password: str, otp: str = "") -> bool:
    username = str(session.get("user", ""))
    if not username or not isinstance(password, str) or not password:
        return False
    ok, role = authenticate(username, password)
    if not ok or role != session.get("role"):
        return False
    if totp_enabled_for(username) and not verify_totp(username, otp.strip()):
        return False
    return True


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


def step_up_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("auth"):
            return redirect(url_for("login"))
        if session.get("step_up_user") != session.get("user") or not step_up_active():
            if request.is_json or request.path.startswith("/api/"):
                return jsonify(ok=False, error="step-up authentication required"), 428
            flash("هذه العملية حساسة وتتطلب Step-Up Authentication أولًا.", "error")
            return redirect(url_for("home") + "#security")
        return fn(*args, **kwargs)
    return wrapped
