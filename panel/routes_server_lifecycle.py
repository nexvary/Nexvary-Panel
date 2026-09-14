from __future__ import annotations

import hashlib
import json
import re
import time

from flask import jsonify, request, session

from .core import audit, db
from .security import role_required, step_up_required
from .server_client import server_call

PREVIEW_TTL_SECONDS = 15 * 60
MAINTENANCE_KINDS = {"system-updates", "reboot"}
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?=.+\..+)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def _provider(action: str, *, timeout: int = 20) -> tuple[dict, int]:
    result = server_call({"action": action}, timeout=timeout)
    if not result.get("ok"):
        return {"ok": False, "error": str(result.get("error", "server lifecycle provider unavailable"))[:180]}, 503
    return result, 200


def _snapshot_for(kind: str) -> tuple[dict, str] | tuple[None, str]:
    if kind == "system-updates":
        result = server_call({"action": "server-updates-preview"}, timeout=90)
        if not result.get("ok"):
            return None, str(result.get("error", "update preview unavailable"))[:180]
        snapshot = {
            "count": int(result.get("count", 0)),
            "packages": list(result.get("packages") or [])[:200],
            "reboot_required": bool(result.get("reboot_required")),
            "generated_at": int(result.get("generated_at", int(time.time()))),
        }
        fingerprint = str(result.get("fingerprint", ""))[:128]
        if not fingerprint:
            fingerprint = hashlib.sha256(json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return snapshot, fingerprint

    result = server_call({"action": "server-overview"}, timeout=15)
    if not result.get("ok"):
        return None, str(result.get("error", "server overview unavailable"))[:180]
    snapshot = {
        "hostname": str(result.get("hostname", ""))[:253],
        "os": str(result.get("os", ""))[:160],
        "kernel": str(result.get("kernel", ""))[:160],
        "uptime_seconds": int(result.get("uptime_seconds", 0)),
        "reboot_required": bool(result.get("reboot_required")),
        "time": result.get("time") if isinstance(result.get("time"), dict) else {},
    }
    fingerprint = hashlib.sha256(json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return snapshot, fingerprint


def _hostname_fingerprint(hostname: object) -> str:
    normalized = str(hostname or "").strip().lower().rstrip(".")
    return hashlib.sha256(normalized.encode()).hexdigest()


def register_server_lifecycle_routes(app):
    @app.get("/api/server-lifecycle/overview")
    @role_required("admin")
    def server_lifecycle_overview():
        result, status = _provider("server-overview", timeout=15)
        return jsonify(result), status

    @app.get("/api/server-lifecycle/network")
    @role_required("admin")
    def server_lifecycle_network():
        result, status = _provider("server-network", timeout=15)
        return jsonify(result), status

    @app.get("/api/server-lifecycle/processes")
    @role_required("admin")
    def server_lifecycle_processes():
        result, status = _provider("server-processes", timeout=15)
        return jsonify(result), status

    @app.get("/api/server-lifecycle/updates")
    @role_required("admin")
    def server_lifecycle_updates():
        result, status = _provider("server-updates-preview", timeout=90)
        return jsonify(result), status

    @app.post("/api/server-lifecycle/time/enable-ntp")
    @role_required("admin")
    @step_up_required
    def server_lifecycle_enable_ntp():
        result = server_call({"action": "server-time-enable-ntp"}, timeout=25)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "NTP enable failed"))[:180]), 503
        audit("server-time-enable-ntp", "scope=server-lifecycle")
        return jsonify(ok=True, time=result.get("time") or {})

    @app.post("/api/server-lifecycle/hostname/preview")
    @role_required("admin")
    @step_up_required
    def server_lifecycle_hostname_preview():
        data = request.get_json(silent=True) or {}
        hostname = str(data.get("hostname", "")).strip().lower().rstrip(".")
        if not HOSTNAME_RE.fullmatch(hostname):
            return jsonify(ok=False, error="hostname must be a valid FQDN"), 400
        result = server_call({"action": "server-overview"}, timeout=15)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "server overview unavailable"))[:180]), 503
        current = str(result.get("hostname", "")).strip().lower().rstrip(".")
        if current == hostname:
            return jsonify(ok=False, error="requested hostname is already active"), 409
        snapshot = {"current_hostname": current, "desired_hostname": hostname}
        fingerprint = _hostname_fingerprint(current)
        now = int(time.time())
        expires_at = now + PREVIEW_TTL_SECONDS
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO server_maintenance_previews(kind,fingerprint,snapshot_json,status,requested_by,created_at,expires_at) VALUES('hostname',?,?, 'preview',?,?,?)",
                (fingerprint, json.dumps(snapshot, separators=(",", ":")), str(session.get("user", "admin"))[:64], now, expires_at),
            )
            preview_id = int(cur.lastrowid)
        audit("server-hostname-preview", f"id={preview_id} from={current} to={hostname}")
        return jsonify(ok=True, preview={"id": preview_id, "kind": "hostname", "fingerprint": fingerprint, "snapshot": snapshot, "status": "preview", "expires_at": expires_at}), 201

    @app.get("/api/server-lifecycle/maintenance")
    @role_required("admin")
    def server_lifecycle_maintenance_list():
        now = int(time.time())
        with db() as conn:
            conn.execute("UPDATE server_maintenance_previews SET status='expired' WHERE status='preview' AND expires_at<?", (now,))
            rows = conn.execute(
                "SELECT id,kind,fingerprint,snapshot_json,status,requested_by,created_at,expires_at,cancelled_at,applied_at FROM server_maintenance_previews ORDER BY id DESC LIMIT 30"
            ).fetchall()
        items = []
        for row in rows:
            try:
                snapshot = json.loads(row["snapshot_json"] or "{}")
            except Exception:
                snapshot = {}
            items.append({
                "id": int(row["id"]),
                "kind": str(row["kind"]),
                "fingerprint": str(row["fingerprint"]),
                "snapshot": snapshot if isinstance(snapshot, dict) else {},
                "status": str(row["status"]),
                "requested_by": str(row["requested_by"]),
                "created_at": int(row["created_at"]),
                "expires_at": int(row["expires_at"]),
                "cancelled_at": int(row["cancelled_at"]),
                "applied_at": int(row["applied_at"]),
            })
        return jsonify(ok=True, previews=items)

    @app.post("/api/server-lifecycle/maintenance/preview")
    @role_required("admin")
    @step_up_required
    def server_lifecycle_maintenance_preview():
        data = request.get_json(silent=True) or {}
        kind = str(data.get("kind", "")).strip().lower()
        if kind not in MAINTENANCE_KINDS:
            return jsonify(ok=False, error="maintenance kind must be system-updates or reboot"), 400
        snapshot, fingerprint_or_error = _snapshot_for(kind)
        if snapshot is None:
            return jsonify(ok=False, error=fingerprint_or_error), 503
        now = int(time.time())
        expires_at = now + PREVIEW_TTL_SECONDS
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO server_maintenance_previews(kind,fingerprint,snapshot_json,status,requested_by,created_at,expires_at) VALUES(?,?,?,'preview',?,?,?)",
                (kind, fingerprint_or_error, json.dumps(snapshot, separators=(",", ":")), str(session.get("user", "admin"))[:64], now, expires_at),
            )
            preview_id = int(cur.lastrowid)
        audit("server-maintenance-preview", f"id={preview_id} kind={kind} fingerprint={fingerprint_or_error[:16]}")
        return jsonify(ok=True, preview={"id": preview_id, "kind": kind, "fingerprint": fingerprint_or_error, "snapshot": snapshot, "status": "preview", "expires_at": expires_at}), 201

    @app.post("/api/server-lifecycle/maintenance/<int:preview_id>/apply")
    @role_required("admin")
    @step_up_required
    def server_lifecycle_maintenance_apply(preview_id: int):
        now = int(time.time())
        with db() as conn:
            row = conn.execute("SELECT * FROM server_maintenance_previews WHERE id=?", (preview_id,)).fetchone()
            if not row:
                return jsonify(ok=False, error="maintenance preview not found"), 404
            if str(row["status"]) != "preview":
                return jsonify(ok=False, error="maintenance preview is not active"), 409
            if int(row["expires_at"]) < now:
                conn.execute("UPDATE server_maintenance_previews SET status='expired' WHERE id=?", (preview_id,))
                return jsonify(ok=False, error="maintenance preview expired"), 409
            if str(row["kind"]) != "hostname":
                return jsonify(ok=False, error="this maintenance kind is preview-only"), 409
            try:
                snapshot = json.loads(row["snapshot_json"] or "{}")
            except Exception:
                return jsonify(ok=False, error="maintenance preview snapshot is invalid"), 409
            desired = str(snapshot.get("desired_hostname", "")).strip().lower().rstrip(".")
            current_at_preview = str(snapshot.get("current_hostname", "")).strip().lower().rstrip(".")
            if not HOSTNAME_RE.fullmatch(desired) or not current_at_preview:
                return jsonify(ok=False, error="maintenance preview snapshot is invalid"), 409
            expected_fingerprint = str(row["fingerprint"])

        current = server_call({"action": "server-overview"}, timeout=15)
        if not current.get("ok"):
            return jsonify(ok=False, error=str(current.get("error", "server overview unavailable"))[:180]), 503
        current_hostname = str(current.get("hostname", "")).strip().lower().rstrip(".")
        if _hostname_fingerprint(current_hostname) != expected_fingerprint or current_hostname != current_at_preview:
            return jsonify(ok=False, error="server hostname changed since preview; create a new preview"), 409

        result = server_call({"action": "server-hostname-set", "hostname": desired}, timeout=45)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "hostname change failed"))[:180]), 503
        with db() as conn:
            conn.execute("UPDATE server_maintenance_previews SET status='applied',applied_at=? WHERE id=?", (now, preview_id))
        audit("server-hostname-apply", f"id={preview_id} from={current_at_preview} to={desired}")
        return jsonify(ok=True, id=preview_id, status="applied", hostname=str(result.get("hostname", desired))[:253], previous_hostname=str(result.get("previous_hostname", current_at_preview))[:253])

    @app.post("/api/server-lifecycle/maintenance/<int:preview_id>/cancel")
    @role_required("admin")
    @step_up_required
    def server_lifecycle_maintenance_cancel(preview_id: int):
        now = int(time.time())
        with db() as conn:
            row = conn.execute("SELECT status FROM server_maintenance_previews WHERE id=?", (preview_id,)).fetchone()
            if not row:
                return jsonify(ok=False, error="maintenance preview not found"), 404
            if str(row["status"]) != "preview":
                return jsonify(ok=False, error="maintenance preview is not active"), 409
            conn.execute("UPDATE server_maintenance_previews SET status='cancelled',cancelled_at=? WHERE id=?", (now, preview_id))
        audit("server-maintenance-cancel", f"id={preview_id}")
        return jsonify(ok=True, id=preview_id, status="cancelled")
