from __future__ import annotations

import re
import time

from flask import flash, redirect, request, session, url_for

from .config import DB_RE, DOMAIN_RE, PASSWORD_RE
from .core import agent_call, audit, can_manage_domain, db, role_required
from .hosting_policy import feature_allowed, package_limit


def _actor() -> tuple[str, str]:
    return str(session.get("user", ""))[:64], str(session.get("role", "viewer"))


def _quota_ok(table: str, limit_name: str) -> tuple[bool, int, int]:
    if table not in {"sites", "databases", "backups"}:
        raise ValueError("unsupported quota table")
    username, role = _actor()
    with db() as conn:
        used = int(conn.execute(f"SELECT COUNT(*) FROM {table} WHERE owner=?", (username,)).fetchone()[0])
    limit = package_limit(limit_name, username=username, role=role)
    return limit > 0 and used < limit, used, limit


def register_site_routes(app):
    @app.post("/sites")
    @role_required("admin", "operator")
    def create_site():
        domain = request.form.get("domain", "").lower().strip()
        kind = request.form.get("kind", "static").strip()
        target = request.form.get("target", "").strip()
        port_raw = request.form.get("app_port", "").strip()
        username, role = _actor()
        if not DOMAIN_RE.match(domain) or kind not in {"static", "php", "node", "python", "reverse"}:
            flash("اسم النطاق أو نوع الموقع غير صالح.", "error")
            return redirect(url_for("home") + "#sites")
        if not feature_allowed("domains.domains", username=username, role=role):
            flash("إدارة النطاقات معطلة في باقة الاستضافة الحالية.", "error")
            return redirect(url_for("home") + "#sites")
        runtime_feature = {"node": "software.node", "python": "software.python", "php": "software.php_manager"}.get(kind)
        if runtime_feature and not feature_allowed(runtime_feature, username=username, role=role):
            flash("بيئة التشغيل المطلوبة معطلة في باقة الاستضافة الحالية.", "error")
            return redirect(url_for("home") + "#sites")
        quota_ok, used, limit = _quota_ok("sites", "max_sites")
        if not quota_ok:
            flash(f"تم بلوغ حد المواقع في الباقة ({used}/{limit}).", "error")
            return redirect(url_for("home") + "#sites")
        app_port = None
        if kind in {"node", "python"}:
            try:
                app_port = int(port_raw)
            except ValueError:
                app_port = 0
            if not 1024 <= app_port <= 65535:
                flash("اختر منفذ تطبيق بين 1024 و65535.", "error")
                return redirect(url_for("home") + "#sites")
        if kind == "reverse" and not re.match(r"^https?://[A-Za-z0-9.\-:\[\]]+(?:/.*)?$", target):
            flash("Reverse Proxy URL غير صالح.", "error")
            return redirect(url_for("home") + "#sites")
        with db() as conn:
            if conn.execute("SELECT 1 FROM sites WHERE domain=?", (domain,)).fetchone():
                flash("هذا النطاق مسجل بالفعل في اللوحة.", "error")
                return redirect(url_for("home") + "#sites")
            reserved = conn.execute("SELECT username FROM hosting_accounts WHERE primary_domain=?", (domain,)).fetchone()
            if reserved and role != "admin" and str(reserved["username"]) != username:
                flash("هذا النطاق الأساسي محجوز لحساب استضافة آخر.", "error")
                return redirect(url_for("home") + "#sites")
        result = agent_call({"action": "site-create", "domain": domain, "kind": kind, "target": target, "app_port": app_port}, timeout=45)
        if not result.get("ok"):
            err = str(result.get("error", "unknown error"))
            audit("site-create-failed", f"{domain}: {err[-300:]}")
            flash("فشل إنشاء الموقع: " + err[-180:], "error")
        else:
            with db() as conn:
                conn.execute("INSERT OR IGNORE INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",
                             (domain, kind, target, app_port, username or "admin", int(time.time())))
            audit("site-create", f"{domain} {kind}")
            flash("تم إنشاء الموقع وربطه بـ NGINX.", "ok")
        return redirect(url_for("home") + "#sites")

    @app.post("/sites/toggle")
    @role_required("admin", "operator")
    def toggle_site():
        domain = request.form.get("domain", "").lower().strip()
        desired = request.form.get("desired", "disable")
        username, role = _actor()
        if not feature_allowed("domains.domains", username=username, role=role):
            flash("إدارة النطاقات معطلة في باقة الاستضافة الحالية.", "error")
            return redirect(url_for("home") + "#sites")
        if not DOMAIN_RE.match(domain) or desired not in {"enable", "disable"} or not can_manage_domain(domain):
            flash("طلب غير صالح أو لا تملك صلاحية الموقع.", "error")
            return redirect(url_for("home") + "#sites")
        result = agent_call({"action": "site-toggle", "domain": domain, "desired": desired}, timeout=20)
        if result.get("ok"):
            with db() as conn:
                conn.execute("UPDATE sites SET enabled=? WHERE domain=?", (1 if desired == "enable" else 0, domain))
            audit("site-toggle", f"{domain} {desired}")
            flash("تم تحديث حالة الموقع.", "ok")
        else:
            flash("تعذر تحديث حالة الموقع: " + str(result.get("error", ""))[-160:], "error")
        return redirect(url_for("home") + "#sites")

    @app.post("/ssl")
    @role_required("admin", "operator")
    def legacy_ssl_issue():
        domain = request.form.get("domain", "").lower().strip()
        email = request.form.get("email", "").strip()
        username, role = _actor()
        if not feature_allowed("security.ssl_tls", username=username, role=role):
            flash("SSL/TLS معطل في باقة الاستضافة الحالية.", "error")
            return redirect(url_for("home") + "#security")
        if not DOMAIN_RE.match(domain) or "@" not in email or len(email) > 254 or not can_manage_domain(domain):
            flash("تحقق من النطاق والبريد والصلاحية.", "error")
            return redirect(url_for("home") + "#security")
        result = agent_call({"action": "ssl", "domain": domain, "email": email}, timeout=140)
        audit("ssl-issued" if result.get("ok") else "ssl-failed", domain)
        flash("تم إصدار/تحديث شهادة SSL." if result.get("ok") else "تعذر إصدار SSL. تأكد أن DNS يشير إلى الخادم.",
              "ok" if result.get("ok") else "error")
        return redirect(url_for("home") + "#security")

    @app.post("/databases")
    @role_required("admin", "operator")
    def create_database():
        db_name = request.form.get("db_name", "").strip()
        db_user = request.form.get("db_user", "").strip()
        db_password = request.form.get("db_password", "")
        site_domain = request.form.get("site_domain", "").lower().strip()
        username, role = _actor()
        if not feature_allowed("databases.mariadb", username=username, role=role):
            flash("MariaDB معطلة في باقة الاستضافة الحالية.", "error")
            return redirect(url_for("home") + "#databases")
        quota_ok, used, limit = _quota_ok("databases", "max_databases")
        if not quota_ok:
            flash(f"تم بلوغ حد قواعد البيانات في الباقة ({used}/{limit}).", "error")
            return redirect(url_for("home") + "#databases")
        if not DB_RE.match(db_name) or not DB_RE.match(db_user) or not PASSWORD_RE.match(db_password):
            flash("بيانات قاعدة البيانات غير صالحة.", "error")
            return redirect(url_for("home") + "#databases")
        if site_domain and (not DOMAIN_RE.match(site_domain) or not can_manage_domain(site_domain)):
            flash("الموقع المرتبط غير صالح أو لا تملك صلاحيته.", "error")
            return redirect(url_for("home") + "#databases")
        with db() as conn:
            if conn.execute("SELECT 1 FROM databases WHERE db_name=? OR db_user=?", (db_name, db_user)).fetchone():
                flash("اسم قاعدة البيانات أو المستخدم مسجل بالفعل.", "error")
                return redirect(url_for("home") + "#databases")
        result = agent_call({"action": "db-create", "db_name": db_name, "db_user": db_user, "password": db_password}, timeout=25)
        if result.get("ok"):
            with db() as conn:
                conn.execute("INSERT OR IGNORE INTO databases(db_name,db_user,engine,site_domain,owner,created_at) VALUES(?,?,?,?,?,?)",
                             (db_name, db_user, "mariadb", site_domain, username or "admin", int(time.time())))
            audit("db-create", f"{db_name} / {db_user}")
            flash("تم إنشاء قاعدة البيانات والمستخدم. كلمة المرور لا تُخزن داخل اللوحة.", "ok")
        else:
            flash("فشل إنشاء قاعدة البيانات: " + str(result.get("error", ""))[-180:], "error")
        return redirect(url_for("home") + "#databases")

    @app.post("/backups")
    @role_required("admin", "operator")
    def create_backup():
        domain = request.form.get("domain", "").lower().strip()
        username, role = _actor()
        if not feature_allowed("files.backups", username=username, role=role):
            flash("النسخ الاحتياطي معطل في باقة الاستضافة الحالية.", "error")
            return redirect(url_for("home") + "#backups")
        quota_ok, used, limit = _quota_ok("backups", "max_backups")
        if not quota_ok:
            flash(f"تم بلوغ حد النسخ الاحتياطية في الباقة ({used}/{limit}).", "error")
            return redirect(url_for("home") + "#backups")
        if not DOMAIN_RE.match(domain) or not can_manage_domain(domain):
            flash("النطاق غير صالح أو لا تملك صلاحيته.", "error")
            return redirect(url_for("home") + "#backups")
        with db() as conn:
            db_row = conn.execute("SELECT db_name FROM databases WHERE site_domain=? ORDER BY id LIMIT 1", (domain,)).fetchone()
        payload = {"action": "backup-site", "domain": domain}
        if db_row:
            payload["db_name"] = db_row["db_name"]
        result = agent_call(payload, timeout=130)
        if result.get("ok"):
            meta = result.get("meta") or {}
            archive = str(meta.get("archive", ""))
            size = int(meta.get("size_bytes", 0) or 0)
            with db() as conn:
                conn.execute("INSERT INTO backups(domain,archive,size_bytes,owner,created_at) VALUES(?,?,?,?,?)",
                             (domain, archive, size, username or "admin", int(time.time())))
            audit("backup-create", f"{domain} {archive}")
            flash("تم إنشاء نسخة احتياطية محلية للموقع وإعداد NGINX.", "ok")
        else:
            flash("فشل النسخ الاحتياطي: " + str(result.get("error", ""))[-180:], "error")
        return redirect(url_for("home") + "#backups")
