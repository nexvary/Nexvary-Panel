from __future__ import annotations

import time

from flask import jsonify, request, session

from .core import audit, db
from .extension_registry import BY_ID, EXTENSIONS
from .security import role_required, step_up_required


def _matched_extension(path: str):
    for item in EXTENSIONS:
        for prefix in item.api_prefixes:
            if path == prefix or path.startswith(prefix + "/"):
                return item
    return None


def _enabled(extension_id: str) -> bool:
    with db() as conn:
        row = conn.execute("SELECT enabled FROM extension_states WHERE extension_id=?", (extension_id,)).fetchone()
    return bool(row and int(row["enabled"]))


def register_extension_routes(app):
    @app.before_request
    def extension_kill_switch():
        if not session.get("auth") or request.path.startswith("/api/extensions"):
            return None
        item = _matched_extension(request.path)
        if item is not None and not _enabled(item.extension_id):
            return jsonify(ok=False, error=f"extension disabled: {item.extension_id}"), 503
        return None

    @app.get("/api/extensions")
    @role_required("admin")
    def extension_list():
        with db() as conn:
            state = {
                str(row["extension_id"]): {
                    "enabled": bool(row["enabled"]),
                    "updated_by": str(row["updated_by"]),
                    "updated_at": int(row["updated_at"]),
                }
                for row in conn.execute("SELECT extension_id,enabled,updated_by,updated_at FROM extension_states").fetchall()
            }
        rows = []
        for item in EXTENSIONS:
            row = item.as_dict()
            row["state"] = state.get(item.extension_id, {"enabled": item.default_enabled, "updated_by": "system", "updated_at": 0})
            rows.append(row)
        return jsonify(ok=True, execution_model="curated-manifests-no-arbitrary-code", extensions=rows)

    @app.put("/api/extensions/<extension_id>")
    @role_required("admin")
    @step_up_required
    def extension_update(extension_id: str):
        item = BY_ID.get(str(extension_id))
        if item is None:
            return jsonify(ok=False, error="extension not found"), 404
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict) or not isinstance(data.get("enabled"), bool):
            return jsonify(ok=False, error="enabled must be boolean"), 400
        enabled = bool(data["enabled"])
        actor = str(session.get("user", "admin"))[:64]
        now = int(time.time())
        with db() as conn:
            conn.execute(
                "UPDATE extension_states SET enabled=?,updated_by=?,updated_at=? WHERE extension_id=?",
                (1 if enabled else 0, actor, now, item.extension_id),
            )
        audit("extension-state", f"extension={item.extension_id} enabled={int(enabled)}")
        return jsonify(ok=True, extension_id=item.extension_id, enabled=enabled, updated_at=now)
