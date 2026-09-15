from __future__ import annotations

import re
import time

from flask import jsonify, request, session

from .config import DOMAIN_RE
from .core import audit, db, login_required, role_required, visible_owner_clause
from .hosting_policy import feature_allowed, package_for_user
from .security import step_up_required

TASK_TYPES = {
    "backup_site": "Site Backup",
    "git_deploy": "Registered Git Deploy",
}
CADENCES = {"hourly", "daily", "weekly"}


def _task_json(row) -> dict:
    return {
        "id": int(row["id"]),
        "owner": str(row["owner"]),
        "domain": str(row["domain"]),
        "task_type": str(row["task_type"]),
        "cadence": str(row["cadence"]),
        "hour_utc": int(row["hour_utc"]),
        "minute_utc": int(row["minute_utc"]),
        "weekday_utc": int(row["weekday_utc"]),
        "enabled": bool(row["enabled"]),
        "run_requested": bool(row["run_requested"]),
        "last_run": int(row["last_run"] or 0),
        "last_status": str(row["last_status"]),
        "last_detail": str(row["last_detail"] or ""),
        "created_at": int(row["created_at"]),
        "updated_at": int(row["updated_at"]),
    }


def _schedule_fields(data: dict, current: dict | None = None) -> tuple[str, int, int, int, int]:
    cadence = str(data.get("cadence", current.get("cadence") if current else "")).strip().lower()
    if cadence not in CADENCES:
        raise ValueError("invalid cadence")
    try:
        minute = int(data.get("minute_utc", current.get("minute_utc") if current else 0))
        hour = int(data.get("hour_utc", current.get("hour_utc") if current else 0))
        weekday = int(data.get("weekday_utc", current.get("weekday_utc") if current else 0))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid schedule fields") from exc
    if not 0 <= minute <= 59 or not 0 <= hour <= 23 or not 0 <= weekday <= 6:
        raise ValueError("schedule fields out of range")
    if cadence == "hourly":
        hour, weekday = 0, 0
    elif cadence == "daily":
        weekday = 0
    enabled_raw = data.get("enabled", current.get("enabled") if current else True)
    if not isinstance(enabled_raw, bool):
        raise ValueError("enabled must be boolean")
    return cadence, hour, minute, weekday, 1 if enabled_raw else 0


def _site_owner(conn, domain: str) -> str | None:
    row = conn.execute("SELECT owner FROM sites WHERE domain=?", (domain,)).fetchone()
    return str(row["owner"]) if row else None


def _role_for_owner(conn, owner: str) -> str:
    if owner == "admin":
        return "admin"
    row = conn.execute("SELECT role FROM users WHERE username=? AND enabled=1", (owner,)).fetchone()
    return str(row["role"]) if row else "viewer"


def _can_touch(owner: str) -> bool:
    return session.get("role") == "admin" or owner == session.get("user")


def register_schedule_routes(app):
    @app.get("/api/schedules")
    @login_required
    def schedules_list():
        if not feature_allowed("advanced.cron"):
            return jsonify(ok=False, error="Scheduled Tasks is disabled by hosting policy"), 403
        where, args = visible_owner_clause()
        username = str(session.get("user", ""))[:64]
        role = str(session.get("role", "viewer"))
        with db() as conn:
            rows = conn.execute(f"SELECT * FROM scheduled_tasks WHERE {where} ORDER BY id DESC", args).fetchall()
            package = package_for_user(conn, username, role)
            limit = int(package["max_cron_jobs"]) if package else 0
        return jsonify(ok=True, tasks=[_task_json(row) for row in rows], task_types=TASK_TYPES, cadences=sorted(CADENCES), max_cron_jobs=limit)

    @app.post("/api/schedules")
    @role_required("admin", "operator")
    @step_up_required
    def schedules_create():
        if not feature_allowed("advanced.cron"):
            return jsonify(ok=False, error="Scheduled Tasks is disabled by hosting policy"), 403
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        domain = str(data.get("domain", "")).strip().lower()
        task_type = str(data.get("task_type", "")).strip().lower()
        if not DOMAIN_RE.fullmatch(domain) or task_type not in TASK_TYPES:
            return jsonify(ok=False, error="invalid domain or task type"), 400
        try:
            cadence, hour, minute, weekday, enabled = _schedule_fields(data)
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        now = int(time.time())
        with db() as conn:
            owner = _site_owner(conn, domain)
            if not owner:
                return jsonify(ok=False, error="site is not registered"), 404
            if not _can_touch(owner):
                return jsonify(ok=False, error="site is outside your account"), 403
            if task_type == "git_deploy" and not conn.execute(
                "SELECT 1 FROM deployments WHERE owner=? AND domain=? LIMIT 1", (owner, domain)
            ).fetchone():
                return jsonify(ok=False, error="register a Git deployment for this site first"), 409
            owner_role = _role_for_owner(conn, owner)
            package = package_for_user(conn, owner, owner_role)
            max_jobs = int(package["max_cron_jobs"]) if package else 0
            used = int(conn.execute("SELECT COUNT(*) FROM scheduled_tasks WHERE owner=?", (owner,)).fetchone()[0])
            if used >= max_jobs:
                return jsonify(ok=False, error="hosting package scheduled-task quota reached"), 409
            cur = conn.execute(
                """INSERT INTO scheduled_tasks(
                     owner,domain,task_type,cadence,hour_utc,minute_utc,weekday_utc,enabled,run_requested,
                     last_run,last_status,last_detail,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,0,0,'never','',?,?)""",
                (owner, domain, task_type, cadence, hour, minute, weekday, enabled, now, now),
            )
            task_id = int(cur.lastrowid)
        audit("scheduled-task-create", f"task_id={task_id} owner={owner} domain={domain} type={task_type} cadence={cadence}")
        return jsonify(ok=True, id=task_id), 201

    @app.put("/api/schedules/<int:task_id>")
    @role_required("admin", "operator")
    @step_up_required
    def schedules_update(task_id: int):
        if not feature_allowed("advanced.cron"):
            return jsonify(ok=False, error="Scheduled Tasks is disabled by hosting policy"), 403
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        with db() as conn:
            row = conn.execute("SELECT * FROM scheduled_tasks WHERE id=?", (task_id,)).fetchone()
            if not row:
                return jsonify(ok=False, error="scheduled task not found"), 404
            current = _task_json(row)
            if not _can_touch(current["owner"]):
                return jsonify(ok=False, error="scheduled task is outside your account"), 403
            try:
                cadence, hour, minute, weekday, enabled = _schedule_fields(data, current)
            except ValueError as exc:
                return jsonify(ok=False, error=str(exc)), 400
            conn.execute(
                "UPDATE scheduled_tasks SET cadence=?,hour_utc=?,minute_utc=?,weekday_utc=?,enabled=?,updated_at=? WHERE id=?",
                (cadence, hour, minute, weekday, enabled, int(time.time()), task_id),
            )
        audit("scheduled-task-update", f"task_id={task_id} cadence={cadence} enabled={enabled}")
        return jsonify(ok=True)

    @app.post("/api/schedules/<int:task_id>/run")
    @role_required("admin", "operator")
    @step_up_required
    def schedules_run_now(task_id: int):
        if not feature_allowed("advanced.cron"):
            return jsonify(ok=False, error="Scheduled Tasks is disabled by hosting policy"), 403
        with db() as conn:
            row = conn.execute("SELECT owner,enabled FROM scheduled_tasks WHERE id=?", (task_id,)).fetchone()
            if not row:
                return jsonify(ok=False, error="scheduled task not found"), 404
            if not _can_touch(str(row["owner"])):
                return jsonify(ok=False, error="scheduled task is outside your account"), 403
            conn.execute(
                "UPDATE scheduled_tasks SET run_requested=1,last_status='queued',last_detail='',updated_at=? WHERE id=?",
                (int(time.time()), task_id),
            )
        audit("scheduled-task-run-request", f"task_id={task_id}")
        return jsonify(ok=True, queued=True)

    @app.delete("/api/schedules/<int:task_id>")
    @role_required("admin", "operator")
    @step_up_required
    def schedules_delete(task_id: int):
        if not feature_allowed("advanced.cron"):
            return jsonify(ok=False, error="Scheduled Tasks is disabled by hosting policy"), 403
        with db() as conn:
            row = conn.execute("SELECT owner,domain,task_type FROM scheduled_tasks WHERE id=?", (task_id,)).fetchone()
            if not row:
                return jsonify(ok=False, error="scheduled task not found"), 404
            if not _can_touch(str(row["owner"])):
                return jsonify(ok=False, error="scheduled task is outside your account"), 403
            conn.execute("DELETE FROM scheduled_tasks WHERE id=?", (task_id,))
        audit("scheduled-task-delete", f"task_id={task_id} domain={row['domain']} type={row['task_type']}")
        return jsonify(ok=True)
