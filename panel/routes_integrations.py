from __future__ import annotations

import ipaddress
import re
import time
from urllib.parse import urlsplit

from flask import jsonify, request, session

from .core import audit, db, notify
from .providers import REGISTRY, provider_snapshot
from .security import role_required, step_up_required
from .vault_client import vault_call

TARGET_TYPES = {
    "restic": {"capability": "encrypted-snapshots", "secret_kind": "restic", "endpoint": "restic-s3"},
    "rclone": {"capability": "cloud-remotes", "secret_kind": "rclone", "endpoint": "rclone-remote"},
    "powerdns": {"capability": "authoritative-dns", "secret_kind": "powerdns", "endpoint": "https-api"},
}
RCLONE_ENDPOINT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}:[^\x00\r\n]{0,300}$")


def _valid_name(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid target name")
    value = value.strip()
    if not 3 <= len(value) <= 64 or any(ord(ch) < 32 for ch in value):
        raise ValueError("target name must be 3-64 printable characters")
    return value


def _publicish_host(host: str | None) -> bool:
    if not host:
        return False
    host = host.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        return False
    try:
        ip = ipaddress.ip_address(host)
        return bool(ip.is_global)
    except ValueError:
        return bool(re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9.-]+", host))


def _https_endpoint(value: str) -> bool:
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return bool(
        len(value) <= 500 and parts.scheme == "https" and _publicish_host(parts.hostname)
        and parts.username is None and parts.password is None and not parts.fragment
    )


def _validate_endpoint(provider: str, value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid endpoint")
    value = value.strip()
    if provider == "restic":
        if not value.startswith("s3:https://") or not _https_endpoint(value[3:]):
            raise ValueError("restic target must use s3:https:// without embedded credentials")
    elif provider == "rclone":
        if not RCLONE_ENDPOINT_RE.fullmatch(value) or "../" in value or value.endswith(":"):
            raise ValueError("rclone target must be remote:path")
    elif provider == "powerdns":
        if not _https_endpoint(value):
            raise ValueError("PowerDNS endpoint must be a public HTTPS API URL")
    else:
        raise ValueError("unsupported integration provider")
    return value


def _provider_spec(provider: str):
    return next((item for item in REGISTRY if item.provider_id == provider), None)


def _safe_target(row) -> dict:
    return {
        "id": int(row["id"]),
        "name": row["name"],
        "provider": row["provider"],
        "capability": row["capability"],
        "endpoint": row["endpoint"],
        "secret_kind": row["secret_kind"],
        "secret_id": row["secret_id"],
        "enabled": bool(row["enabled"]),
        "created_at": int(row["created_at"]),
        "updated_at": int(row["updated_at"]),
    }


def register_integration_routes(app):
    @app.get("/api/integrations/targets")
    @role_required("admin")
    def integration_targets():
        owner = str(session.get("user", ""))[:64]
        with db() as conn:
            rows = conn.execute("SELECT * FROM integration_targets WHERE owner=? ORDER BY id DESC", (owner,)).fetchall()
        return jsonify(ok=True, targets=[_safe_target(row) for row in rows], types=TARGET_TYPES)

    @app.post("/api/integrations/targets")
    @role_required("admin")
    @step_up_required
    def integration_target_create():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        try:
            name = _valid_name(data.get("name"))
            provider = str(data.get("provider", "")).strip().lower()
            target_type = TARGET_TYPES.get(provider)
            if not target_type:
                raise ValueError("unsupported integration provider")
            spec = _provider_spec(provider)
            if not spec or target_type["capability"] not in spec.capabilities:
                raise ValueError("provider capability contract mismatch")
            endpoint = _validate_endpoint(provider, data.get("endpoint"))
            secret_id = str(data.get("secret_id", "")).strip()
            if not re.fullmatch(r"[a-z][a-z0-9_-]{2,47}", secret_id):
                raise ValueError("invalid Secret Vault reference")
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400

        vault = vault_call({"action": "metadata"})
        if not vault.get("ok"):
            return jsonify(ok=False, error="Secret Vault unavailable; target was not created"), 503
        secret_present = any(
            isinstance(row, dict) and row.get("id") == secret_id and row.get("kind") == target_type["secret_kind"]
            for row in vault.get("entries", [])
        )
        if not secret_present:
            return jsonify(ok=False, error="referenced credential does not exist in Secret Vault"), 409

        now = int(time.time())
        owner = str(session.get("user", ""))[:64]
        try:
            with db() as conn:
                cur = conn.execute(
                    "INSERT INTO integration_targets(name,provider,capability,endpoint,secret_kind,secret_id,enabled,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?,?)",
                    (name, provider, target_type["capability"], endpoint, target_type["secret_kind"], secret_id, owner, now, now),
                )
                row = conn.execute("SELECT * FROM integration_targets WHERE id=?", (cur.lastrowid,)).fetchone()
        except Exception as exc:
            if "UNIQUE" in str(exc).upper():
                return jsonify(ok=False, error="target name already exists"), 409
            raise
        audit("integration-target-create", f"provider={provider} name={name} secret_ref={target_type['secret_kind']}:{secret_id}")
        notify("ok", "Integration target created", f"{provider}:{name}", "fusion", owner=owner)
        return jsonify(ok=True, target=_safe_target(row)), 201

    @app.post("/api/integrations/targets/<int:target_id>/toggle")
    @role_required("admin")
    @step_up_required
    def integration_target_toggle(target_id: int):
        owner = str(session.get("user", ""))[:64]
        with db() as conn:
            row = conn.execute("SELECT * FROM integration_targets WHERE id=? AND owner=?", (target_id, owner)).fetchone()
            if not row:
                return jsonify(ok=False, error="target not found"), 404
            enabled = 0 if row["enabled"] else 1
            conn.execute("UPDATE integration_targets SET enabled=?,updated_at=? WHERE id=?", (enabled, int(time.time()), target_id))
        audit("integration-target-toggle", f"id={target_id} enabled={enabled}")
        return jsonify(ok=True, enabled=bool(enabled))

    @app.delete("/api/integrations/targets/<int:target_id>")
    @role_required("admin")
    @step_up_required
    def integration_target_delete(target_id: int):
        owner = str(session.get("user", ""))[:64]
        with db() as conn:
            row = conn.execute("SELECT name,provider FROM integration_targets WHERE id=? AND owner=?", (target_id, owner)).fetchone()
            if not row:
                return jsonify(ok=False, error="target not found"), 404
            conn.execute("DELETE FROM integration_targets WHERE id=? AND owner=?", (target_id, owner))
        audit("integration-target-delete", f"id={target_id} provider={row['provider']} name={row['name']}")
        return jsonify(ok=True, deleted=True)

    @app.get("/api/integrations/targets/<int:target_id>/preflight")
    @role_required("admin")
    def integration_target_preflight(target_id: int):
        owner = str(session.get("user", ""))[:64]
        with db() as conn:
            row = conn.execute("SELECT * FROM integration_targets WHERE id=? AND owner=?", (target_id, owner)).fetchone()
        if not row:
            return jsonify(ok=False, error="target not found"), 404
        target = _safe_target(row)
        snap = provider_snapshot()
        provider = next((item for item in snap["providers"] if item["provider_id"] == target["provider"]), None)
        vault = vault_call({"action": "metadata"})
        secret_present = bool(vault.get("ok") and any(
            isinstance(item, dict) and item.get("id") == target["secret_id"] and item.get("kind") == target["secret_kind"]
            for item in vault.get("entries", [])
        ))
        installed = bool(provider and provider.get("installed"))
        capability_ok = bool(provider and target["capability"] in provider.get("capabilities", []))
        ready = bool(target["enabled"] and installed and capability_ok and secret_present)
        return jsonify(
            ok=True,
            ready=ready,
            checks={
                "enabled": target["enabled"],
                "provider_installed": installed,
                "capability_contract": capability_ok,
                "credential_present": secret_present,
                "endpoint_syntax": True,
            },
            provider={"id": target["provider"], "version": (provider or {}).get("version", "")},
            note="Preflight is local-only: no provider network request is executed.",
        )
