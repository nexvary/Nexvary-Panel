from __future__ import annotations

import time

from flask import flash, redirect, request, session, url_for

from .core import audit, db, notify, role_required
from .security import new_totp_secret, totp_enabled_for, verify_totp, verify_totp_secret


def register_security_routes(app):
    @app.post("/2fa/start")
    @role_required("admin", "operator", "viewer")
    def two_factor_start():
        username = session.get("user", "")
        if totp_enabled_for(username):
            flash("المصادقة الثنائية مفعلة بالفعل على هذا الحساب.", "error")
            return redirect(url_for("home") + "#security")
        secret = new_totp_secret()
        session["totp_pending"] = secret
        session.modified = True
        audit("2fa-enrollment-start")
        flash("تم إنشاء مفتاح 2FA مؤقت. أضفه إلى تطبيق Authenticator ثم أدخل الرمز للتفعيل.", "ok")
        return redirect(url_for("home") + "#security")

    @app.post("/2fa/enable")
    @role_required("admin", "operator", "viewer")
    def two_factor_enable():
        username = session.get("user", "")
        secret = str(session.get("totp_pending", ""))
        code = request.form.get("otp", "").strip()
        if not secret or not verify_totp_secret(secret, code):
            audit("2fa-enable-failed")
            flash("رمز 2FA غير صحيح أو انتهت جلسة الإعداد.", "error")
            return redirect(url_for("home") + "#security")
        with db() as conn:
            conn.execute(
                "INSERT INTO user_security(username,totp_secret,totp_enabled,updated_at) VALUES(?,?,1,?) "
                "ON CONFLICT(username) DO UPDATE SET totp_secret=excluded.totp_secret,totp_enabled=1,updated_at=excluded.updated_at",
                (username, secret, int(time.time())),
            )
        session.pop("totp_pending", None)
        audit("2fa-enabled")
        notify("ok", "Two-factor authentication enabled", username, "security", owner=username)
        flash("تم تفعيل المصادقة الثنائية بنجاح.", "ok")
        return redirect(url_for("home") + "#security")

    @app.post("/2fa/cancel")
    @role_required("admin", "operator", "viewer")
    def two_factor_cancel():
        session.pop("totp_pending", None)
        return redirect(url_for("home") + "#security")

    @app.post("/2fa/disable")
    @role_required("admin", "operator", "viewer")
    def two_factor_disable():
        username = session.get("user", "")
        code = request.form.get("otp", "").strip()
        if not totp_enabled_for(username) or not verify_totp(username, code):
            audit("2fa-disable-failed")
            flash("يلزم رمز 2FA صالح لتعطيل المصادقة الثنائية.", "error")
            return redirect(url_for("home") + "#security")
        with db() as conn:
            conn.execute("UPDATE user_security SET totp_secret='',totp_enabled=0,updated_at=? WHERE username=?", (int(time.time()), username))
        audit("2fa-disabled")
        notify("warning", "Two-factor authentication disabled", username, "security", owner=username)
        flash("تم تعطيل المصادقة الثنائية لهذا الحساب.", "ok")
        return redirect(url_for("home") + "#security")
