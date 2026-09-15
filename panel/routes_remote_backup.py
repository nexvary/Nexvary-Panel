from __future__ import annotations

from flask import jsonify, request, session

from .core import audit, db, notify
from .provider_client import provider_call
from .security import role_required, step_up_required


def register_remote_backup_routes(app):
    @app.post("/api/remote-backup/push")
    @role_required("admin")
    @step_up_required
    def remote_backup_push():
        data = request.get_json(silent=True) or {}
        try:
            target_id = int(data.get("target_id", 0))
            backup_id = int(data.get("backup_id", 0))
        except (TypeError, ValueError):
            return jsonify(ok=False, error="invalid backup/target id"), 400
        owner = str(session.get("user", ""))[:64]
        with db() as conn:
            target = conn.execute("SELECT * FROM integration_targets WHERE id=? AND owner=?", (target_id, owner)).fetchone()
            backup = conn.execute("SELECT * FROM backups WHERE id=?", (backup_id,)).fetchone()
        if not target or not target["enabled"]:
            return jsonify(ok=False, error="integration target not found or disabled"), 404
        if target["provider"] != "rclone" or target["capability"] != "cloud-remotes" or target["secret_kind"] != "rclone":
            return jsonify(ok=False, error="target is not an encrypted rclone backup target"), 409
        if not backup:
            return jsonify(ok=False, error="backup point not found"), 404

        result = provider_call({
            "action": "rclone-upload-backup",
            "domain": backup["domain"],
            "archive": backup["archive"],
            "secret_id": target["secret_id"],
            "endpoint": target["endpoint"],
        }, timeout=1810)
        detail = f"backup_id={backup_id} target_id={target_id} domain={backup['domain']}"
        if result.get("ok"):
            meta = result.get("meta") or {}
            audit("remote-backup-push", detail + f" bytes={int(meta.get('bytes', 0) or 0)}")
            notify("ok", "Encrypted remote backup completed", f"{backup['domain']} → {target['name']}", "backup", owner=owner)
            return jsonify(ok=True, meta=meta)
        audit("remote-backup-push-failed", detail)
        notify("critical", "Encrypted remote backup failed", f"{backup['domain']} → {target['name']}", "backup", owner=owner)
        return jsonify(ok=False, error=str(result.get("error", "remote backup failed"))[-500:]), 502

    @app.get("/api/remote-backup/targets/<int:target_id>/preflight")
    @role_required("admin")
    def remote_backup_preflight(target_id: int):
        owner = str(session.get("user", ""))[:64]
        with db() as conn:
            target = conn.execute("SELECT * FROM integration_targets WHERE id=? AND owner=?", (target_id, owner)).fetchone()
        if not target or target["provider"] != "rclone" or target["secret_kind"] != "rclone":
            return jsonify(ok=False, error="rclone target not found"), 404
        result = provider_call({"action": "rclone-preflight", "secret_id": target["secret_id"], "endpoint": target["endpoint"]}, timeout=20)
        return jsonify(result), (200 if result.get("ok") else 409)
