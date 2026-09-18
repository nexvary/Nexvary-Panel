from __future__ import annotations

import re
import secrets
import sqlite3
import time

from flask import flash, jsonify, redirect, request, session, url_for

from .config import DOMAIN_RE, ROLES, USER_RE
from .core import agent_call, audit, can_manage_domain, db, notify, password_hash, role_required
from .maintenance_policy import docker_operation_for, restart_operation_for_target
from .security import clear_step_up, step_up_required


def _maintenance_receipt(operation_id: str, target: str, phase: str, change_id: str) -> None:
    """Write a bounded, correlation-friendly receipt without agent output/secrets."""
    audit(f"maintenance-{phase}", f"change={change_id} operation={operation_id} target={target}"[:700])


def register_ops_routes(app):
    @app.post("/services/restart")
    @role_required("admin")
    @step_up_required
    def restart_service():
        requested = request.form.get("name", "").strip()
        operation = restart_operation_for_target(requested)
        if operation is None or "admin" not in operation.roles or not operation.step_up:
            audit("maintenance-policy-deny", requested[:80] or "empty")
            flash("الخدمة غير مسموح بإدارتها من اللوحة.", "error")
            return redirect(url_for("home") + "#services")
        change_id = secrets.token_hex(8)
        _maintenance_receipt(operation.id, operation.target, "start", change_id)
        clear_step_up()
        result = agent_call({"action": operation.agent_action, "name": operation.target}, timeout=operation.timeout)
        _maintenance_receipt(operation.id, operation.target, "success" if result.get("ok") else "failure", change_id)
        notify("ok" if result.get("ok") else "critical", f"Service {operation.target} " + ("restarted" if result.get("ok") else "restart failed"),
               str(result.get("error", ""))[-300:], "service")
        flash("تمت إعادة تشغيل الخدمة." if result.get("ok") else "فشل تشغيل الخدمة: " + str(result.get("error", ""))[-150:],
              "ok" if result.get("ok") else "error")
        return redirect(url_for("home") + "#services")

    @app.get("/doctor")
    @role_required("admin", "operator")
    def doctor():
        result = agent_call({"action": "doctor"}, timeout=45)
        audit("doctor-run", "ok" if result.get("ok") else "failed")
        if result.get("ok"):
            report = result.get("checks") or {}
            failed = [c for c in report.get("checks", []) if not c.get("ok")]
            critical = [c for c in failed if c.get("severity") == "critical"]
            if critical:
                detail = "; ".join(f"{c.get('name')}: {c.get('detail')}" for c in critical)[:700]
                notify("critical", f"Doctor found {len(critical)} critical issue(s)", detail, "doctor", owner=session.get("user", "admin"))
            elif failed:
                detail = "; ".join(f"{c.get('name')}: {c.get('detail')}" for c in failed)[:700]
                notify("warning", f"Doctor found {len(failed)} warning(s)", detail, "doctor", owner=session.get("user", "admin"))
        else:
            notify("critical", "NEXVARY Doctor failed to run", str(result.get("error", ""))[-500:], "doctor", owner=session.get("user", "admin"))
        return jsonify(result)

    @app.get("/sites/logs")
    @role_required("admin", "operator", "viewer")
    def site_logs():
        domain = request.args.get("domain", "").lower().strip()
        if not DOMAIN_RE.match(domain) or not can_manage_domain(domain):
            return jsonify({"ok": False, "error": "site not allowed"}), 403
        return jsonify(agent_call({"action": "site-logs", "domain": domain}, timeout=15))

    @app.get("/docker")
    @role_required("admin", "operator", "viewer")
    def docker_list():
        return jsonify(agent_call({"action": "docker-list"}, timeout=15))

    @app.post("/docker/control")
    @role_required("admin", "operator")
    @step_up_required
    def docker_control():
        container = request.form.get("container", "").strip()
        desired = request.form.get("desired", "restart").strip()
        operation = docker_operation_for(desired)
        role = str(session.get("role", ""))
        if (not re.match(r"^[A-Za-z0-9_.-]{1,128}$", container) or operation is None
                or role not in operation.roles or not operation.step_up):
            audit("maintenance-policy-deny", f"docker {container[:80]} {desired[:20]}")
            flash("طلب Docker غير صالح أو غير مسموح.", "error")
            return redirect(url_for("home") + "#docker")
        change_id = secrets.token_hex(8)
        _maintenance_receipt(operation.id, container, "start", change_id)
        clear_step_up()
        result = agent_call({"action": operation.agent_action, "container": container, "desired": operation.target}, timeout=operation.timeout)
        _maintenance_receipt(operation.id, container, "success" if result.get("ok") else "failure", change_id)
        if not result.get("ok"):
            notify("critical", f"Docker {operation.target} failed", container, "docker")
        flash("تم تنفيذ أمر Docker." if result.get("ok") else "فشل أمر Docker: " + str(result.get("error", ""))[-160:],
              "ok" if result.get("ok") else "error")
        return redirect(url_for("home") + "#docker")

    @app.post("/users")
    @role_required("admin")
    def create_user():
        username = request.form.get("username", "").strip()
        role = request.form.get("role", "viewer").strip()
        password = request.form.get("password", "")
        if username == "admin" or not USER_RE.match(username) or role not in ROLES or role == "reseller" or len(password) < 14:
            flash("اسم المستخدم أو الدور أو كلمة المرور غير صالح. أنشئ الموزعين من مدير الحسابات والموزعين.", "error")
            return redirect(url_for("home") + "#users")
        salt = secrets.token_hex(16)
        try:
            with db() as conn:
                conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
                             (username, role, salt, password_hash(password, salt), int(time.time())))
            audit("user-create", f"{username} {role}")
            notify("info", "Panel user created", f"{username} · {role}", "access")
            flash("تم إنشاء مستخدم اللوحة.", "ok")
        except sqlite3.IntegrityError:
            flash("اسم المستخدم مستخدم بالفعل.", "error")
        return redirect(url_for("home") + "#users")

    @app.errorhandler(413)
    def too_large(_):
        return ("Request too large", 413)

    @app.errorhandler(500)
    def err500(_):
        return ("Internal server error", 500)
