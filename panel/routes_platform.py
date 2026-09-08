from __future__ import annotations

import re
import sqlite3
import time

from flask import flash, jsonify, redirect, request, session, url_for

from .config import DB_RE, DOMAIN_RE, PASSWORD_RE
from .core import agent_call, audit, can_manage_domain, db, notify, role_required

GIT_URL_RE = re.compile(r"^https://(?:github\.com|gitlab\.com|bitbucket\.org)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,120}$")


def _domain_allowed(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain)) and can_manage_domain(domain)


def _safe_rel_request(value: str, *, allow_root: bool = False) -> bool:
    if not isinstance(value, str) or len(value) > 500 or "\x00" in value or "\\" in value:
        return False
    value = value.strip()
    if value.startswith("/"):
        return False
    if not value:
        return allow_root
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return False
    return True


def register_platform_routes(app):
    @app.get("/api/files")
    @role_required("admin", "operator")
    def files_list():
        domain = request.args.get("domain", "").lower().strip()
        rel = request.args.get("path", "").strip()
        if not _domain_allowed(domain) or not _safe_rel_request(rel, allow_root=True):
            return jsonify(ok=False, error="site/path not allowed"), 403
        result = agent_call({"action": "file-list", "domain": domain, "path": rel}, timeout=20)
        audit("file-list", f"{domain}:{rel}")
        return jsonify(result)

    @app.get("/api/file")
    @role_required("admin", "operator")
    def file_read():
        domain = request.args.get("domain", "").lower().strip()
        rel = request.args.get("path", "").strip()
        if not _domain_allowed(domain) or not _safe_rel_request(rel):
            return jsonify(ok=False, error="site/path not allowed"), 403
        result = agent_call({"action": "file-read", "domain": domain, "path": rel}, timeout=20)
        audit("file-read", f"{domain}:{rel}")
        return jsonify(result)

    @app.post("/api/file/save")
    @role_required("admin", "operator")
    def file_save():
        data = request.get_json(silent=True) or {}
        domain = str(data.get("domain", "")).lower().strip()
        rel = str(data.get("path", "")).strip()
        content = data.get("content", "")
        if not _domain_allowed(domain) or not _safe_rel_request(rel) or not isinstance(content, str) or len(content.encode("utf-8")) > 512 * 1024:
            return jsonify(ok=False, error="invalid file request"), 400
        result = agent_call({"action": "file-write", "domain": domain, "path": rel, "content": content}, timeout=25)
        audit("file-write" if result.get("ok") else "file-write-failed", f"{domain}:{rel}")
        return jsonify(result), (200 if result.get("ok") else 400)

    @app.post("/api/file/mkdir")
    @role_required("admin", "operator")
    def file_mkdir():
        data = request.get_json(silent=True) or {}
        domain = str(data.get("domain", "")).lower().strip()
        rel = str(data.get("path", "")).strip()
        if not _domain_allowed(domain) or not _safe_rel_request(rel):
            return jsonify(ok=False, error="invalid folder request"), 400
        result = agent_call({"action": "file-mkdir", "domain": domain, "path": rel}, timeout=20)
        audit("file-mkdir" if result.get("ok") else "file-mkdir-failed", f"{domain}:{rel}")
        return jsonify(result), (200 if result.get("ok") else 400)

    @app.post("/api/file/delete")
    @role_required("admin", "operator")
    def file_delete():
        data = request.get_json(silent=True) or {}
        domain = str(data.get("domain", "")).lower().strip()
        rel = str(data.get("path", "")).strip()
        if not _domain_allowed(domain) or not _safe_rel_request(rel):
            return jsonify(ok=False, error="invalid delete request"), 400
        result = agent_call({"action": "file-delete", "domain": domain, "path": rel}, timeout=20)
        audit("file-delete" if result.get("ok") else "file-delete-failed", f"{domain}:{rel}")
        return jsonify(result), (200 if result.get("ok") else 400)

    @app.post("/git/deploy")
    @role_required("admin", "operator")
    def git_deploy():
        domain = request.form.get("domain", "").lower().strip()
        repo_url = request.form.get("repo_url", "").strip()
        branch = request.form.get("branch", "main").strip()
        target = request.form.get("target", "public").strip()
        if not _domain_allowed(domain) or not GIT_URL_RE.match(repo_url) or not BRANCH_RE.match(branch) or ".." in branch or target not in {"public", "app"}:
            flash("بيانات Git Deploy غير صالحة.", "error")
            return redirect(url_for("home") + "#deploy")
        now = int(time.time())
        owner = session.get("user", "admin")
        with db() as conn:
            cur = conn.execute("INSERT INTO deployments(domain,repo_url,branch,target,status,detail,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                               (domain, repo_url, branch, target, "running", "", owner, now, now))
            deploy_id = cur.lastrowid
        result = agent_call({"action": "git-deploy", "domain": domain, "repo_url": repo_url, "branch": branch, "target": target}, timeout=210)
        status = "success" if result.get("ok") else "failed"
        detail = str(result.get("output") or result.get("error") or "")[-700:]
        with db() as conn:
            conn.execute("UPDATE deployments SET status=?,detail=?,updated_at=? WHERE id=?", (status, detail, int(time.time()), deploy_id))
        audit("git-deploy" if result.get("ok") else "git-deploy-failed", f"{domain} {repo_url} {branch} -> {target}")
        notify("ok" if result.get("ok") else "critical", "Git Deploy " + ("completed" if result.get("ok") else "failed"), f"{domain} · {branch} → {target}", "deploy")
        flash("تم نشر المستودع بنجاح." if result.get("ok") else "فشل Git Deploy: " + str(result.get("error", ""))[-180:], "ok" if result.get("ok") else "error")
        return redirect(url_for("home") + "#deploy")

    @app.post("/backups/restore")
    @role_required("admin", "operator")
    def backup_restore():
        try:
            backup_id = int(request.form.get("backup_id", "0"))
        except ValueError:
            backup_id = 0
        with db() as conn:
            row = conn.execute("SELECT * FROM backups WHERE id=?", (backup_id,)).fetchone()
        if not row or not _domain_allowed(row["domain"]):
            flash("نقطة الاستعادة غير صالحة أو لا تملك صلاحيتها.", "error")
            return redirect(url_for("home") + "#backups")
        with db() as conn:
            db_row = conn.execute("SELECT db_name FROM databases WHERE site_domain=? ORDER BY id LIMIT 1", (row["domain"],)).fetchone()
        payload = {"action": "backup-restore", "domain": row["domain"], "archive": row["archive"]}
        if db_row:
            payload["db_name"] = db_row["db_name"]
        result = agent_call(payload, timeout=180)
        audit("backup-restore" if result.get("ok") else "backup-restore-failed", f"{row['domain']} {row['archive']}")
        notify("warning" if result.get("ok") else "critical", "Backup restore " + ("completed" if result.get("ok") else "failed"), row["domain"], "backup")
        flash("تمت الاستعادة مع إنشاء Safety Snapshot قبلها." if result.get("ok") else "فشلت الاستعادة: " + str(result.get("error", ""))[-180:], "ok" if result.get("ok") else "error")
        return redirect(url_for("home") + "#backups")

    @app.post("/wordpress/prepare")
    @role_required("admin", "operator")
    def wordpress_prepare():
        domain = request.form.get("domain", "").lower().strip()
        db_name = request.form.get("db_name", "").strip()
        db_user = request.form.get("db_user", "").strip()
        db_password = request.form.get("db_password", "")
        if not _domain_allowed(domain) or not DB_RE.match(db_name) or not DB_RE.match(db_user) or not PASSWORD_RE.match(db_password):
            flash("بيانات WordPress غير صالحة.", "error")
            return redirect(url_for("home") + "#wordpress")
        with db() as conn:
            site = conn.execute("SELECT kind FROM sites WHERE domain=?", (domain,)).fetchone()
            existing = conn.execute("SELECT db_name,db_user FROM databases WHERE db_name=?", (db_name,)).fetchone()
        if not site or site["kind"] != "php":
            flash("WordPress Manager يتطلب موقع PHP.", "error")
            return redirect(url_for("home") + "#wordpress")
        if not existing:
            db_result = agent_call({"action": "db-create", "db_name": db_name, "db_user": db_user, "password": db_password}, timeout=35)
            if not db_result.get("ok"):
                flash("تعذر إنشاء قاعدة WordPress: " + str(db_result.get("error", ""))[-160:], "error")
                return redirect(url_for("home") + "#wordpress")
            try:
                with db() as conn:
                    conn.execute("INSERT INTO databases(db_name,db_user,engine,site_domain,owner,created_at) VALUES(?,?,?,?,?,?)",
                                 (db_name, db_user, "mariadb", domain, session.get("user", "admin"), int(time.time())))
            except sqlite3.IntegrityError:
                pass
        elif existing["db_user"] != db_user:
            flash("اسم قاعدة البيانات مرتبط بمستخدم مختلف داخل اللوحة.", "error")
            return redirect(url_for("home") + "#wordpress")
        result = agent_call({"action": "wp-prepare", "domain": domain, "db_name": db_name, "db_user": db_user, "password": db_password}, timeout=180)
        if result.get("ok"):
            meta = result.get("meta") or {}
            now = int(time.time())
            with db() as conn:
                conn.execute("INSERT INTO wordpress_instances(domain,db_name,db_user,status,version,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(domain) DO UPDATE SET db_name=excluded.db_name,db_user=excluded.db_user,status=excluded.status,version=excluded.version,updated_at=excluded.updated_at",
                             (domain, db_name, db_user, "prepared", str(meta.get("version", ""))[:40], session.get("user", "admin"), now, now))
            audit("wordpress-prepare", domain)
            notify("ok", "WordPress Core prepared", domain, "wordpress")
            flash("تم تجهيز WordPress Core وwp-config.php. أكمل معالج الموقع من المتصفح.", "ok")
        else:
            audit("wordpress-prepare-failed", domain)
            flash("تعذر تجهيز WordPress: " + str(result.get("error", ""))[-180:], "error")
        return redirect(url_for("home") + "#wordpress")

    @app.post("/notifications/read-all")
    @role_required("admin", "operator", "viewer")
    def notifications_read_all():
        owner = session.get("user", "admin")
        with db() as conn:
            if session.get("role") == "admin":
                conn.execute("UPDATE notifications SET read_at=? WHERE read_at IS NULL", (int(time.time()),))
            else:
                conn.execute("UPDATE notifications SET read_at=? WHERE owner=? AND read_at IS NULL", (int(time.time()), owner))
        return redirect(url_for("home") + "#notifications")
