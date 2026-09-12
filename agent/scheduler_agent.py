#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import json
import os
import socket
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(os.environ.get("NVP_DB_PATH", "/var/lib/nexvary-panel/panel.db"))
AGENT_SOCK = os.environ.get("NVP_AGENT_SOCK", "/run/nexvary-panel/agent.sock")
POLL_SECONDS = 20
TASK_TYPES = {"backup_site", "git_deploy"}
CADENCES = {"hourly", "daily", "weekly"}


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _agent(payload: dict, timeout: int = 180) -> dict:
    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
    data = b""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(AGENT_SOCK)
            sock.sendall(raw)
            while not data.endswith(b"\n") and len(data) < 1024 * 1024:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data += chunk
    except (OSError, TimeoutError):
        return {"ok": False, "error": "privileged agent unavailable"}
    try:
        result = json.loads(data.decode()) if data else {}
    except Exception:
        result = {}
    return result if isinstance(result, dict) else {"ok": False, "error": "invalid agent response"}


def _same_hour(a: int, b: int) -> bool:
    if not a:
        return False
    return dt.datetime.fromtimestamp(a, dt.timezone.utc).replace(minute=0, second=0, microsecond=0) == dt.datetime.fromtimestamp(b, dt.timezone.utc).replace(minute=0, second=0, microsecond=0)


def _same_day(a: int, b: int) -> bool:
    if not a:
        return False
    return dt.datetime.fromtimestamp(a, dt.timezone.utc).date() == dt.datetime.fromtimestamp(b, dt.timezone.utc).date()


def _same_iso_week(a: int, b: int) -> bool:
    if not a:
        return False
    da = dt.datetime.fromtimestamp(a, dt.timezone.utc).date().isocalendar()[:2]
    db = dt.datetime.fromtimestamp(b, dt.timezone.utc).date().isocalendar()[:2]
    return da == db


def _due(row, now: int) -> bool:
    # A Step-Up-protected Run Now request is explicit and may run a paused recurring task.
    if row["run_requested"]:
        return True
    if not row["enabled"]:
        return False
    cadence = str(row["cadence"])
    if cadence not in CADENCES:
        return False
    current = dt.datetime.fromtimestamp(now, dt.timezone.utc)
    minute = int(row["minute_utc"])
    hour = int(row["hour_utc"])
    weekday = int(row["weekday_utc"])
    last = int(row["last_run"] or 0)
    if cadence == "hourly":
        return current.minute >= minute and not _same_hour(last, now)
    if cadence == "daily":
        return (current.hour, current.minute) >= (hour, minute) and not _same_day(last, now)
    return current.weekday() == weekday and (current.hour, current.minute) >= (hour, minute) and not _same_iso_week(last, now)


def _audit(conn: sqlite3.Connection, owner: str, task_id: int, status: str, detail: str) -> None:
    conn.execute(
        "INSERT INTO audit(ts,actor,action,detail,ip) VALUES(?,?,?,?,?)",
        (int(time.time()), "scheduler", "scheduled-task-run", f"owner={owner} task_id={task_id} status={status} {detail}"[:700], "local"),
    )


def _notify_failure(conn: sqlite3.Connection, owner: str, domain: str, task_type: str) -> None:
    now = int(time.time())
    title = f"Scheduled task failed: {task_type}"
    recent = conn.execute(
        "SELECT 1 FROM notifications WHERE owner=? AND source='scheduler' AND title=? AND created_at>? LIMIT 1",
        (owner, title, now - 600),
    ).fetchone()
    if not recent:
        conn.execute(
            "INSERT INTO notifications(level,title,detail,source,owner,created_at) VALUES('warning',?,?,?,?,?)",
            (title, f"Task for {domain} did not complete. Review Scheduled Tasks.", "scheduler", owner, now),
        )


def _run_task(conn: sqlite3.Connection, row, now: int) -> None:
    task_id = int(row["id"])
    owner = str(row["owner"])
    domain = str(row["domain"])
    task_type = str(row["task_type"])
    conn.execute(
        "UPDATE scheduled_tasks SET run_requested=0,last_run=?,last_status='running',last_detail='',updated_at=? WHERE id=?",
        (now, now, task_id),
    )
    conn.commit()

    if task_type == "backup_site":
        db_row = conn.execute(
            "SELECT db_name FROM databases WHERE owner=? AND site_domain=? ORDER BY id LIMIT 1", (owner, domain)
        ).fetchone()
        payload = {"action": "backup-site", "domain": domain}
        if db_row:
            payload["db_name"] = str(db_row["db_name"])
        result = _agent(payload, timeout=180)
        if result.get("ok"):
            meta = result.get("meta") or {}
            archive = str(meta.get("archive", ""))
            size = int(meta.get("size_bytes", 0) or 0)
            if archive:
                conn.execute(
                    "INSERT INTO backups(domain,archive,size_bytes,owner,created_at) VALUES(?,?,?,?,?)",
                    (domain, archive, size, owner, now),
                )
            status, detail = "ok", "backup completed"
        else:
            status, detail = "error", "backup failed"
    elif task_type == "git_deploy":
        dep = conn.execute(
            "SELECT id,repo_url,branch,target FROM deployments WHERE owner=? AND domain=? ORDER BY id DESC LIMIT 1",
            (owner, domain),
        ).fetchone()
        if not dep:
            status, detail = "error", "no registered deployment"
        else:
            result = _agent(
                {"action": "git-deploy", "domain": domain, "repo_url": dep["repo_url"], "branch": dep["branch"], "target": dep["target"]},
                timeout=180,
            )
            status = "ok" if result.get("ok") else "error"
            detail = "deployment completed" if status == "ok" else "deployment failed"
            conn.execute(
                "UPDATE deployments SET status=?,detail=?,updated_at=? WHERE id=?",
                ("deployed" if status == "ok" else "failed", f"scheduled: {detail}", now, int(dep["id"])),
            )
    else:
        status, detail = "error", "task type is not allowed"

    conn.execute(
        "UPDATE scheduled_tasks SET last_status=?,last_detail=?,updated_at=? WHERE id=?",
        (status, detail, int(time.time()), task_id),
    )
    _audit(conn, owner, task_id, status, detail)
    if status != "ok":
        _notify_failure(conn, owner, domain, task_type)
    conn.commit()


def tick() -> None:
    if not DB_PATH.exists():
        return
    now = int(time.time())
    with _db() as conn:
        try:
            rows = conn.execute(
                "SELECT * FROM scheduled_tasks WHERE enabled=1 OR run_requested=1 ORDER BY id LIMIT 500"
            ).fetchall()
        except sqlite3.OperationalError:
            return
        for row in rows:
            if str(row["task_type"]) in TASK_TYPES and _due(row, now):
                _run_task(conn, row, now)


def main() -> None:
    while True:
        try:
            tick()
        except Exception:
            pass
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
