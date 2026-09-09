from __future__ import annotations

import time

from flask import flash, redirect, request, session, url_for

from .core import audit, db, notify, role_required
from .security import (
    clear_step_up,
    grant_step_up,
    new_totp_secret,
    step_up_active,
    totp_enabled_for,
    verify_step_up_credentials,
    verify_totp,
    verify_totp_secret,
)


SELF_ROLES = ("admin", "reseller", "operator", "viewer")


def _pending_secret(username: str) -> str:
    with db() as conn:
        row = conn.execute("SELECT totp_secret,totp_enabled FROM user_security WHERE username=?", (username,)).fetchone()
    return str(row["totp_secret"]) if row and not row["totp_enabled"] else ""


def register_security_routes(app):
    @app.post("/security/step-up")
    @role_required(*SELF_ROLES)
    def security_step_up():
        now = int(time.time())
        locked_until = int(session.get("step_up_locked_until", 0) or 0)
        if locked_until > now:
            flash("تم تعليق محاولات Step-Up مؤقتًا بعد عدة محاولات فاشلة.", "error")
            return redirect(url_for("home") + "#security")
        password = request.form.get("password", "")
        otp = request.form.get("otp", "").strip()
        if verify_step_up_credentials(password, otp):
            session.pop("step_up_failures", None)
            session.pop("step_up_locked_until", None)
            grant_step_up()
            audit("step-up-granted", "5-minute sensitive-operation window")
            flash("تم تفعيل نافذة العمليات الحساسة لمدة 5 دقائق.", "ok")
            return redirect(url_for("home") + "#security")
        failures = int(session.get("step_up_failures", 0) or 0) + 1
        session["step_up_failures"] = failures
        if failures >= 5:
            session["step_up_failures"] = 0
            session["step_up_locked_until"] = now + 300
            clear_step_up()
        audit("step-up-failed", f"attempt={min(failures, 5)}")
        flash("فشل Step-Up: تحقق من كلمة المرور ورمز 2FA إن كان مفعّلًا.", "error")
        return redirect(url_for("home") + "#security")

    @app.post("/security/step-up/clear")
    @role_required(*SELF_ROLES)
    def security_step_up_clear():
        if step_up_active():
            audit("step-up-cleared")
        clear_step_up()
        flash("تم إغلاق نافذة العمليات الحساسة.", "ok")
        return redirect(url_for("home") + "#security")

    @app.post("/2fa/start")
    @role_required(*SELF_ROLES)
    def two_factor_start():
        username = session.get("user", "")
        if totp_enabled_for(username):
            flash("المصادقة الثنائية مفعلة بالفعل على هذا الحساب.", "error")
            return redirect(url_for("home") + "#security")
        secret = new_totp_secret()
        with db() as conn:
            conn.execute(
                "INSERT INTO user_security(username,totp_secret,totp_enabled,updated_at) VALUES(?,?,0,?) "
                "ON CONFLICT(username) DO UPDATE SET totp_secret=excluded.totp_secret,totp_enabled=0,updated_at=excluded.updated_at",
                (username, secret, int(time.time())),
            )
        audit("2fa-enrollment-start")
        flash("تم إنشاء مفتاح 2FA مؤقت على الخادم. أضفه إلى تطبيق Authenticator ثم أدخل الرمز للتفعيل.", "ok")
        return redirect(url_for("home") + "#security")

    @app.post("/2fa/enable")
    @role_required(*SELF_ROLES)
    def two_factor_enable():
        username = session.get("user", "")
        secret = _pending_secret(username)
        code = request.form.get("otp", "").strip()
        if not secret or not verify_totp_secret(secret, code):
            audit("2fa-enable-failed")
            flash("رمز 2FA غير صحيح أو لا يوجد إعداد معلق.", "error")
            return redirect(url_for("home") + "#security")
        with db() as conn:
            conn.execute("UPDATE user_security SET totp_enabled=1,updated_at=? WHERE username=?", (int(time.time()), username))
        clear_step_up()
        audit("2fa-enabled")
        notify("ok", "Two-factor authentication enabled", username, "security", owner=username)
        flash("تم تفعيل المصادقة الثنائية بنجاح.", "ok")
        return redirect(url_for("home") + "#security")

    @app.post("/2fa/cancel")
    @role_required(*SELF_ROLES)
    def two_factor_cancel():
        username = session.get("user", "")
        with db() as conn:
            conn.execute("DELETE FROM user_security WHERE username=? AND totp_enabled=0", (username,))
        audit("2fa-enrollment-cancel")
        return redirect(url_for("home") + "#security")

    @app.post("/2fa/disable")
    @role_required(*SELF_ROLES)
    def two_factor_disable():
        username = session.get("user", "")
        code = request.form.get("otp", "").strip()
        if not totp_enabled_for(username) or not verify_totp(username, code):
            audit("2fa-disable-failed")
            flash("يلزم رمز 2FA صالح لتعطيل المصادقة الثنائية.", "error")
            return redirect(url_for("home") + "#security")
        with db() as conn:
            conn.execute("UPDATE user_security SET totp_secret='',totp_enabled=0,updated_at=? WHERE username=?", (int(time.time()), username))
        clear_step_up()
        audit("2fa-disabled")
        notify("warning", "Two-factor authentication disabled", username, "security", owner=username)
        flash("تم تعطيل المصادقة الثنائية لهذا الحساب.", "ok")
        return redirect(url_for("home") + "#security")
