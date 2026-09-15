from __future__ import annotations

from flask import jsonify, request, session

from .core import audit, notify
from .security import role_required, step_up_active, step_up_required
from .vault_client import vault_call


def register_vault_routes(app):
    @app.get("/api/vault/metadata")
    @role_required("admin")
    def vault_metadata():
        result = vault_call({"action": "metadata"})
        if not result.get("ok"):
            return jsonify(ok=False, error=result.get("error", "vault unavailable"), entries=[]), 503
        entries = result.get("entries", [])
        if not isinstance(entries, list):
            entries = []
        # Never return credential values or filesystem paths to the browser.
        safe = [
            {
                "id": str(row.get("id", ""))[:48],
                "kind": str(row.get("kind", ""))[:24],
                "bytes": int(row.get("bytes", 0) or 0),
                "updated_at": int(row.get("updated_at", 0) or 0),
            }
            for row in entries if isinstance(row, dict)
        ]
        return jsonify(ok=True, entries=safe, step_up=step_up_active())

    @app.post("/api/vault/put")
    @role_required("admin")
    @step_up_required
    def vault_put():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        secret_id = str(data.get("id", ""))
        kind = str(data.get("kind", ""))
        value = data.get("value", "")
        if not isinstance(value, str):
            return jsonify(ok=False, error="invalid secret value"), 400
        result = vault_call({"action": "put", "id": secret_id, "kind": kind, "value": value})
        if not result.get("ok"):
            audit("vault-put-failed", f"kind={kind[:24]} id={secret_id[:48]}")
            return jsonify(ok=False, error=result.get("error", "vault write failed")), 400
        audit("vault-put", f"kind={kind[:24]} id={secret_id[:48]}")
        notify("ok", "Credential stored in Secret Vault", f"{kind}:{secret_id}", "security", owner=session.get("user", ""))
        return jsonify(ok=True, entry=result.get("entry", {}))

    @app.post("/api/vault/delete")
    @role_required("admin")
    @step_up_required
    def vault_delete():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        secret_id = str(data.get("id", ""))
        kind = str(data.get("kind", ""))
        result = vault_call({"action": "delete", "id": secret_id, "kind": kind})
        if not result.get("ok"):
            audit("vault-delete-failed", f"kind={kind[:24]} id={secret_id[:48]}")
            return jsonify(ok=False, error=result.get("error", "vault delete failed")), 400
        audit("vault-delete", f"kind={kind[:24]} id={secret_id[:48]}")
        notify("warning", "Credential deleted from Secret Vault", f"{kind}:{secret_id}", "security", owner=session.get("user", ""))
        return jsonify(ok=True, deleted=bool(result.get("deleted")))
