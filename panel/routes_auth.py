from __future__ import annotations

import os
import time

import psutil
from flask import flash, jsonify, redirect, render_template, request, session, url_for

from .core import FAILED, audit, authenticate, csrf_token, db, login_required, service, visible_owner_clause
from .security import step_up_active, totp_enabled_for, totp_uri, verify_totp


def _trust_posture(*, enabled_2fa: bool, services: dict[str, bool], backups_count: int, disk_percent: float, critical_unread: int) -> dict:
    active_defense = bool(services.get("crowdsec") or services.get("fail2ban"))
    checks = [
        {"id": "identity", "label": "المصادقة الثنائية", "ok": enabled_2fa, "weight": 20, "view": "security"},
        {"id": "active-defense", "label": "الدفاع النشط ضد الهجمات", "ok": active_defense, "weight": 15, "view": "services"},
        {"id": "core", "label": "الخدمات الأساسية", "ok": bool(services.get("nginx") and services.get("mariadb")), "weight": 15, "view": "services"},
        {"id": "backup", "label": "نقطة استعادة متاحة", "ok": backups_count > 0, "weight": 15, "view": "backups"},
        {"id": "capacity", "label": "سعة القرص آمنة", "ok": disk_percent < 90, "weight": 10, "view": "services"},
        {"id": "alerts", "label": "لا تنبيهات حرجة معلقة", "ok": critical_unread == 0, "weight": 10, "view": "notifications"},
        {"id": "session", "label": "CSRF + Secure Session Policy", "ok": True, "weight": 15, "view": "security"},
    ]
    score = sum(item["weight"] for item in checks if item["ok"])
    level = "excellent" if score >= 90 else "good" if score >= 75 else "attention" if score >= 55 else "risk"
    return {"score": score, "level": level, "checks": checks, "passed": sum(1 for item in checks if item["ok"]), "total": len(checks)}


def register_auth_routes(app):
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            ip = (request.remote_addr or "unknown")[:80]
            now = time.time()
            rec = FAILED.get(ip, {"n": 0, "until": 0})
            if float(rec["until"]) > now:
                flash("محاولات كثيرة. حاول بعد عدة دقائق.", "error")
                return render_template("login.html"), 429
            username = request.form.get("username", "").strip()
            ok, role = authenticate(username, request.form.get("password", ""))
            if ok and totp_enabled_for(username):
                otp = request.form.get("otp", "").strip()
                if not verify_totp(username, otp):
                    ok = False
            if ok:
                FAILED.pop(ip, None)
                session.clear()
                session.permanent = True
                session.update(auth=True, user=username, role=role)
                csrf_token()
                audit("login", "successful")
                return redirect(url_for("home"))
            rec["n"] = int(rec["n"]) + 1
            if int(rec["n"]) >= 5:
                rec = {"n": 0, "until": now + 300}
            FAILED[ip] = rec
            flash("بيانات الدخول أو رمز التحقق غير صحيحة.", "error")
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        audit("logout")
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def home():
        owner_where, owner_args = visible_owner_clause()
        username = session.get("user", "")
        role = session.get("role")
        with db() as conn:
            sites = [dict(r) for r in conn.execute(f"SELECT * FROM sites WHERE {owner_where} ORDER BY id DESC", owner_args)]
            databases = [dict(r) for r in conn.execute(f"SELECT * FROM databases WHERE {owner_where} ORDER BY id DESC", owner_args)]
            backups = [dict(r) for r in conn.execute(f"SELECT * FROM backups WHERE {owner_where} ORDER BY id DESC LIMIT 20", owner_args)]
            deployments = [dict(r) for r in conn.execute(f"SELECT * FROM deployments WHERE {owner_where} ORDER BY id DESC LIMIT 30", owner_args)]
            wordpress_instances = [dict(r) for r in conn.execute(f"SELECT * FROM wordpress_instances WHERE {owner_where} ORDER BY id DESC", owner_args)]
            notifications = [dict(r) for r in conn.execute(f"SELECT * FROM notifications WHERE {owner_where} ORDER BY id DESC LIMIT 40", owner_args)]
            notifications_unread = conn.execute(f"SELECT COUNT(*) FROM notifications WHERE {owner_where} AND read_at IS NULL", owner_args).fetchone()[0]
            critical_unread = conn.execute(f"SELECT COUNT(*) FROM notifications WHERE {owner_where} AND read_at IS NULL AND level='critical'", owner_args).fetchone()[0]
            if role == "admin":
                audits = [dict(r) for r in conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 18")]
            else:
                audits = [dict(r) for r in conn.execute("SELECT * FROM audit WHERE actor=? ORDER BY id DESC LIMIT 18", (username,))]
            users = [dict(r) for r in conn.execute("SELECT username,role,enabled,created_at FROM users ORDER BY id DESC")] if role == "admin" else []
            sec = conn.execute("SELECT totp_secret,totp_enabled FROM user_security WHERE username=?", (username,)).fetchone()
        disk = psutil.disk_usage("/")
        metrics = {
            "cpu": round(psutil.cpu_percent(interval=0.15), 1),
            "ram": round(psutil.virtual_memory().percent, 1),
            "disk": round(disk.percent, 1),
            "load": os.getloadavg()[0] if hasattr(os, "getloadavg") else 0,
            "uptime_h": round((time.time() - psutil.boot_time()) / 3600, 1),
            "disk_free": disk.free,
        }
        services = {name: service(name) for name in ["nginx", "mariadb", "crowdsec", "fail2ban", "ssh", "docker"]}
        enabled = bool(sec and sec["totp_enabled"])
        pending_secret = str(sec["totp_secret"]) if sec and not sec["totp_enabled"] else ""
        trust_posture = _trust_posture(
            enabled_2fa=enabled,
            services=services,
            backups_count=len(backups),
            disk_percent=metrics["disk"],
            critical_unread=int(critical_unread),
        )
        return render_template(
            "index.html", sites=sites, databases=databases, backups=backups, deployments=deployments,
            wordpress_instances=wordpress_instances, notifications=notifications, notifications_unread=notifications_unread,
            audits=audits, users=users, metrics=metrics, services=services, role=role, username=username,
            totp_enabled=enabled, totp_pending=pending_secret, step_up_active=step_up_active(), trust_posture=trust_posture,
            totp_uri_value=totp_uri(username, pending_secret) if pending_secret else "",
        )

    @app.get("/api/metrics")
    @login_required
    def api_metrics():
        d = psutil.disk_usage("/")
        net = psutil.net_io_counters()
        return jsonify(cpu=round(psutil.cpu_percent(interval=0.1), 1), ram=round(psutil.virtual_memory().percent, 1),
                       disk=round(d.percent, 1), net={"bytes_sent": net.bytes_sent, "bytes_recv": net.bytes_recv})
