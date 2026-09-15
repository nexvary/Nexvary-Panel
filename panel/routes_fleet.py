from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request

from flask import jsonify, request, session

from .agent_client import agent_call
from .config import VERSION
from .core import audit, db
from .provider_client import provider_call
from .security import role_required, step_up_required
from .server_client import server_call

NODE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{2,63}$")
SECRET_REF_RE = re.compile(r"^[a-z][a-z0-9_-]{2,47}$")
TOKEN_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{2,63}$")
CAPABILITY_KEY_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
REQUEST_ID_RE = re.compile(r"^[a-f0-9]{32}$")
FINGERPRINT_RE = re.compile(r"^[a-f0-9]{64}$")
MAX_FLEET_NODES = 100
MAX_PROBE_BATCH = 25
ALLOWED_PORTS = {443, 8443}
REQUEST_TTL_SECONDS = 300
PLAN_OPERATIONS = {
    "restart-nginx": "service.nginx.restart",
    "restart-mariadb": "service.mariadb.restart",
    "enable-ntp": "server.time.ntp",
    "system-updates": "server.updates.apply",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _global_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(address.is_global)


def _resolve_public(host: str, port: int) -> tuple[str, ...]:
    if _global_ip(host):
        return (host,)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("private/local fleet endpoints are blocked")
    if host == "localhost" or host.endswith((".localhost", ".local")):
        raise ValueError("private/local fleet endpoints are blocked")
    if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9.-]+", host):
        raise ValueError("invalid endpoint host")
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("fleet endpoint hostname could not be resolved") from exc
    addresses = sorted({str(answer[4][0]).split("%", 1)[0] for answer in answers if answer and answer[4]})
    if not addresses:
        raise ValueError("fleet endpoint hostname has no usable address")
    if any(not _global_ip(address) for address in addresses):
        raise ValueError("fleet endpoint resolves to a private/local address")
    return tuple(addresses)


def _public_https(value: str) -> str:
    try:
        parts = urllib.parse.urlsplit(str(value).strip())
    except ValueError as exc:
        raise ValueError("invalid HTTPS endpoint") from exc
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment or parts.query:
        raise ValueError("endpoint must be public HTTPS without credentials, query or fragment")
    try:
        port = int(parts.port or 443)
    except ValueError as exc:
        raise ValueError("invalid fleet endpoint port") from exc
    if port not in ALLOWED_PORTS:
        raise ValueError("fleet endpoint port must be 443 or 8443")
    host = parts.hostname.rstrip(".").lower()
    _resolve_public(host, port)
    host_for_url = f"[{host}]" if ":" in host else host
    netloc = host_for_url if port == 443 else f"{host_for_url}:{port}"
    path = (parts.path or "").rstrip("/")
    if len(path) > 180 or ".." in path.split("/"):
        raise ValueError("invalid fleet endpoint path")
    return urllib.parse.urlunsplit(("https", netloc, path, "", ""))


def _safe_capabilities(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, object] = {}
    for key, raw in list(value.items())[:64]:
        name = str(key)[:64]
        if not CAPABILITY_KEY_RE.fullmatch(name):
            continue
        if isinstance(raw, bool):
            result[name] = raw
        elif isinstance(raw, int) and not isinstance(raw, bool):
            result[name] = max(-1_000_000, min(1_000_000, raw))
        elif isinstance(raw, float):
            result[name] = round(max(-1_000_000.0, min(1_000_000.0, raw)), 3)
        elif isinstance(raw, str):
            result[name] = raw[:120]
        elif isinstance(raw, list):
            result[name] = [str(item)[:80] for item in raw[:40] if isinstance(item, (str, int, float, bool))]
    return result


def _probe_endpoint(endpoint: str) -> dict:
    endpoint = _public_https(endpoint)
    url = endpoint.rstrip("/") + "/api/fleet/v1/health"
    opener = urllib.request.build_opener(_NoRedirect())
    started = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "Nexvary-Fleet/0.8"}, method="GET")
        with opener.open(req, timeout=5) as response:
            if int(getattr(response, "status", 200)) != 200:
                raise ValueError("unexpected fleet health status")
            raw = response.read(64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                raise ValueError("fleet health response too large")
        body = json.loads(raw.decode("utf-8")) if raw else {}
        if not isinstance(body, dict):
            raise ValueError("fleet health response must be an object")
        healthy = body.get("ok") is True
        capabilities = _safe_capabilities(body.get("capabilities", {}))
        version = str(body.get("version", ""))[:40]
        status = "online" if healthy else "degraded"
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError, urllib.error.HTTPError):
        status = "offline"
        capabilities = {}
        version = ""
    latency = max(0, min(60_000, int((time.monotonic() - started) * 1000)))
    return {"status": status, "remote_version": version, "capabilities": capabilities, "latency_ms": latency}


def _store_probe(conn, node, result: dict, checked_at: int) -> None:
    status = str(result.get("status", "offline"))
    version = str(result.get("remote_version", ""))[:40]
    capabilities = _safe_capabilities(result.get("capabilities", {}))
    latency = max(0, min(60_000, int(result.get("latency_ms", 0) or 0)))
    conn.execute(
        "INSERT INTO fleet_probes(node_id,status,remote_version,capabilities_json,latency_ms,checked_at) VALUES(?,?,?,?,?,?)",
        (int(node["id"]), status, version, json.dumps(capabilities, separators=(",", ":"), sort_keys=True), latency, checked_at),
    )
    conn.execute(
        "UPDATE fleet_nodes SET status=?,last_seen=?,updated_at=? WHERE id=?",
        (status, checked_at if status in {"online", "degraded"} else int(node["last_seen"]), checked_at, int(node["id"])),
    )


def _latest_probe(conn, node_id: int) -> dict | None:
    row = conn.execute(
        "SELECT status,remote_version,capabilities_json,latency_ms,checked_at FROM fleet_probes WHERE node_id=? ORDER BY id DESC LIMIT 1",
        (node_id,),
    ).fetchone()
    if not row:
        return None
    try:
        capabilities = json.loads(row["capabilities_json"] or "{}")
    except (TypeError, json.JSONDecodeError):
        capabilities = {}
    return {
        "status": str(row["status"]),
        "remote_version": str(row["remote_version"]),
        "capabilities": _safe_capabilities(capabilities),
        "latency_ms": int(row["latency_ms"]),
        "checked_at": int(row["checked_at"]),
    }


def _node_payload(conn, row) -> dict:
    latest = _latest_probe(conn, int(row["id"]))
    return {
        "id": int(row["id"]),
        "name": str(row["name"]),
        "endpoint": str(row["endpoint"]),
        "credential_configured": bool(str(row["credential_ref"] or "")),
        "enabled": bool(row["enabled"]),
        "status": str(row["status"]),
        "last_seen": int(row["last_seen"]),
        "created_at": int(row["created_at"]),
        "updated_at": int(row["updated_at"]),
        "latest_probe": latest,
    }


def _admin_owner() -> str:
    return str(session.get("user", "admin"))[:64]


def _select_nodes(conn, raw_ids: object) -> tuple[list, str | None]:
    owner = _admin_owner()
    if raw_ids is None:
        rows = conn.execute("SELECT * FROM fleet_nodes WHERE owner=? AND enabled=1 ORDER BY name", (owner,)).fetchall()
        if len(rows) > MAX_PROBE_BATCH:
            return [], f"fleet has {len(rows)} enabled nodes; select at most {MAX_PROBE_BATCH} node_ids per batch"
        return list(rows), None
    if not isinstance(raw_ids, list) or not 1 <= len(raw_ids) <= MAX_PROBE_BATCH:
        return [], f"node_ids must contain 1-{MAX_PROBE_BATCH} nodes"
    try:
        ids = [int(value) for value in raw_ids]
    except (TypeError, ValueError):
        return [], "node_ids must be integers"
    if any(value < 1 for value in ids) or len(ids) != len(set(ids)):
        return [], "node_ids must be unique positive integers"
    placeholders = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT * FROM fleet_nodes WHERE owner=? AND enabled=1 AND id IN ({placeholders}) ORDER BY name",
        (owner, *ids),
    ).fetchall()
    if len(rows) != len(ids):
        return [], "one or more fleet nodes are missing, disabled or outside your scope"
    return list(rows), None


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _authenticate_machine_token(token: str) -> dict | None:
    if not re.fullmatch(r"nvp_fleet_[A-Za-z0-9_-]{40,180}", token):
        return None
    digest = _token_hash(token)
    with db() as conn:
        rows = conn.execute("SELECT id,label,token_hash,owner FROM fleet_inbound_tokens WHERE enabled=1 ORDER BY id LIMIT 200").fetchall()
    for row in rows:
        if hmac.compare_digest(str(row["token_hash"]), digest):
            return {"id": int(row["id"]), "label": str(row["label"]), "owner": str(row["owner"])}
    return None


def _safe_result(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    return {
        str(key)[:64]: raw
        for key, raw in list(value.items())[:32]
        if isinstance(raw, (str, int, float, bool, type(None)))
    }


def _execute_inbound(operation: str, payload: dict) -> dict:
    if operation == "restart-nginx":
        result = agent_call({"action": "service-restart", "name": "nginx"}, timeout=45)
    elif operation == "restart-mariadb":
        result = agent_call({"action": "service-restart", "name": "mariadb"}, timeout=45)
    elif operation == "enable-ntp":
        result = server_call({"action": "server-time-enable-ntp"}, timeout=30)
    elif operation == "system-updates":
        fingerprint = str(payload.get("fingerprint", "")).strip().lower()
        if not FINGERPRINT_RE.fullmatch(fingerprint):
            return {"ok": False, "error": "system-updates requires the reviewed 64-character fingerprint"}
        result = server_call({"action": "server-updates-apply", "fingerprint": fingerprint}, timeout=1900)
    else:
        return {"ok": False, "error": "fleet operation not allowed"}
    if not isinstance(result, dict) or not result.get("ok"):
        return {"ok": False, "error": str(result.get("error", "fleet local provider failed"))[:180] if isinstance(result, dict) else "fleet local provider failed"}
    return {"ok": True, "result": _safe_result(result)}


def register_fleet_routes(app):
    @app.before_request
    def fleet_legacy_guard():
        path = request.path.rstrip("/")
        if session.get("role") == "admin" and (path == "/api/advanced/fleet" or re.fullmatch(r"/api/advanced/fleet/\d+(?:/probe)?", path)):
            if request.method in {"POST", "DELETE", "PUT", "PATCH"}:
                return jsonify(ok=False, error="legacy Fleet API retired; use /api/fleet endpoints"), 410
        return None

    @app.get("/api/fleet/v1/health")
    def fleet_machine_health():
        return jsonify(
            ok=True,
            version=VERSION,
            protocol="fleet-v1",
            capabilities={key: True for key in PLAN_OPERATIONS.values()},
        )

    @app.post("/api/fleet/v1/apply")
    def fleet_machine_apply():
        auth = str(request.headers.get("Authorization", ""))
        token = auth[7:] if auth.startswith("Bearer ") else ""
        identity = _authenticate_machine_token(token)
        if not identity:
            return jsonify(ok=False, error="fleet authentication failed"), 401
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid fleet request"), 400
        operation = str(data.get("operation", "")).strip().lower()
        request_id = str(data.get("request_id", "")).strip().lower()
        payload = data.get("payload") if isinstance(data.get("payload"), dict) else {}
        try:
            issued_at = int(data.get("issued_at", 0) or 0)
        except (TypeError, ValueError):
            issued_at = 0
        if operation not in PLAN_OPERATIONS or not REQUEST_ID_RE.fullmatch(request_id):
            return jsonify(ok=False, error="invalid fleet operation or request id"), 400
        if str(request.headers.get("Idempotency-Key", "")) != request_id:
            return jsonify(ok=False, error="fleet idempotency key mismatch"), 400
        now = int(time.time())
        if abs(now - issued_at) > REQUEST_TTL_SECONDS:
            return jsonify(ok=False, error="fleet request timestamp outside allowed window"), 409
        owner = str(identity["owner"])[:64]
        with db() as conn:
            existing = conn.execute("SELECT operation,status,detail_json FROM fleet_jobs WHERE request_id=? AND direction='inbound' AND owner=?", (request_id, owner)).fetchone()
            if existing:
                try:
                    detail = json.loads(existing["detail_json"] or "{}")
                except Exception:
                    detail = {}
                if str(existing["operation"]) != operation:
                    return jsonify(ok=False, error="request id already used for a different operation"), 409
                return jsonify(ok=str(existing["status"]) == "applied", request_id=request_id, operation=operation, status=str(existing["status"]), result=_safe_result(detail.get("result", {}))), 200
            conn.execute(
                "INSERT INTO fleet_jobs(request_id,node_id,direction,operation,status,detail_json,owner,created_at,updated_at) VALUES(?,NULL,'inbound',?,'running','{}',?,?,?)",
                (request_id, operation, owner, now, now),
            )
        execution = _execute_inbound(operation, payload)
        status = "applied" if execution.get("ok") else "failed"
        detail = {"result": _safe_result(execution.get("result", {}))}
        if not execution.get("ok"):
            detail["error"] = str(execution.get("error", "fleet operation failed"))[:180]
        with db() as conn:
            conn.execute("UPDATE fleet_jobs SET status=?,detail_json=?,updated_at=? WHERE request_id=?", (status, json.dumps(detail, separators=(",", ":")), int(time.time()), request_id))
            conn.execute("UPDATE fleet_inbound_tokens SET last_used=? WHERE id=?", (int(time.time()), int(identity["id"])))
        audit("fleet-inbound-apply" if execution.get("ok") else "fleet-inbound-failed", f"request={request_id} operation={operation} peer={identity['label']}")
        if not execution.get("ok"):
            return jsonify(ok=False, request_id=request_id, operation=operation, status=status, error=detail["error"]), 503
        return jsonify(ok=True, request_id=request_id, operation=operation, status=status, result=detail["result"])

    @app.get("/api/fleet")
    @role_required("admin")
    def fleet_overview():
        owner = _admin_owner()
        with db() as conn:
            rows = conn.execute("SELECT * FROM fleet_nodes WHERE owner=? ORDER BY name", (owner,)).fetchall()
            nodes = [_node_payload(conn, row) for row in rows]
        counts = {"total": len(nodes), "online": 0, "degraded": 0, "offline": 0, "unknown": 0}
        for node in nodes:
            state = str(node["status"])
            counts[state if state in counts else "unknown"] += 1
        return jsonify(ok=True, nodes=nodes, counts=counts, batch_limit=MAX_PROBE_BATCH, remote_apply_supported=True)

    @app.post("/api/fleet")
    @role_required("admin")
    @step_up_required
    def fleet_create():
        data = request.get_json(silent=True) or {}
        name = str(data.get("name", "")).strip()
        endpoint_raw = str(data.get("endpoint", "")).strip()
        credential_ref = str(data.get("credential_ref", "")).strip().lower()
        if not NODE_NAME_RE.fullmatch(name):
            return jsonify(ok=False, error="invalid fleet node name"), 400
        if credential_ref and not SECRET_REF_RE.fullmatch(credential_ref):
            return jsonify(ok=False, error="invalid fleet credential reference"), 400
        try:
            endpoint = _public_https(endpoint_raw)
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        owner = _admin_owner()
        now = int(time.time())
        try:
            with db() as conn:
                used = int(conn.execute("SELECT COUNT(*) FROM fleet_nodes WHERE owner=?", (owner,)).fetchone()[0])
                if used >= MAX_FLEET_NODES:
                    return jsonify(ok=False, error=f"fleet node limit reached ({MAX_FLEET_NODES})"), 409
                cur = conn.execute(
                    "INSERT INTO fleet_nodes(name,endpoint,credential_ref,enabled,owner,status,last_seen,created_at,updated_at) VALUES(?,?,?,1,?,'unknown',0,?,?)",
                    (name, endpoint, credential_ref, owner, now, now),
                )
                node_id = int(cur.lastrowid)
        except sqlite3.IntegrityError:
            return jsonify(ok=False, error="fleet node name already exists"), 409
        audit("fleet-node-create", f"id={node_id} name={name} endpoint={endpoint} credential={'yes' if credential_ref else 'no'}")
        return jsonify(ok=True, id=node_id, name=name, endpoint=endpoint, credential_configured=bool(credential_ref)), 201

    @app.patch("/api/fleet/<int:node_id>/credential")
    @role_required("admin")
    @step_up_required
    def fleet_set_credential(node_id: int):
        data = request.get_json(silent=True) or {}
        credential_ref = str(data.get("credential_ref", "")).strip().lower()
        if not SECRET_REF_RE.fullmatch(credential_ref):
            return jsonify(ok=False, error="invalid fleet credential reference"), 400
        owner = _admin_owner()
        with db() as conn:
            row = conn.execute("SELECT name FROM fleet_nodes WHERE id=? AND owner=?", (node_id, owner)).fetchone()
            if not row:
                return jsonify(ok=False, error="fleet node not found"), 404
            conn.execute("UPDATE fleet_nodes SET credential_ref=?,updated_at=? WHERE id=? AND owner=?", (credential_ref, int(time.time()), node_id, owner))
        audit("fleet-node-credential", f"id={node_id} name={row['name']} ref={credential_ref}")
        return jsonify(ok=True, id=node_id, credential_configured=True)

    @app.post("/api/fleet/auth/tokens")
    @role_required("admin")
    @step_up_required
    def fleet_create_inbound_token():
        data = request.get_json(silent=True) or {}
        label = str(data.get("label", "")).strip()
        if not TOKEN_LABEL_RE.fullmatch(label):
            return jsonify(ok=False, error="invalid fleet token label"), 400
        token = "nvp_fleet_" + secrets.token_urlsafe(48)
        digest = _token_hash(token)
        owner = _admin_owner()
        now = int(time.time())
        try:
            with db() as conn:
                cur = conn.execute(
                    "INSERT INTO fleet_inbound_tokens(label,token_hash,enabled,owner,created_at,last_used) VALUES(?,?,1,?,?,0)",
                    (label, digest, owner, now),
                )
                token_id = int(cur.lastrowid)
        except sqlite3.IntegrityError:
            return jsonify(ok=False, error="fleet token label already exists"), 409
        audit("fleet-token-create", f"id={token_id} label={label}")
        return jsonify(ok=True, id=token_id, label=label, token_once=token, store_as={"kind": "fleet", "suggested_id": f"fleet-{token_id}"}), 201

    @app.get("/api/fleet/auth/tokens")
    @role_required("admin")
    def fleet_list_inbound_tokens():
        owner = _admin_owner()
        with db() as conn:
            rows = conn.execute("SELECT id,label,enabled,created_at,last_used FROM fleet_inbound_tokens WHERE owner=? ORDER BY id DESC", (owner,)).fetchall()
        return jsonify(ok=True, tokens=[{"id": int(row["id"]), "label": str(row["label"]), "enabled": bool(row["enabled"]), "created_at": int(row["created_at"]), "last_used": int(row["last_used"])} for row in rows])

    @app.delete("/api/fleet/auth/tokens/<int:token_id>")
    @role_required("admin")
    @step_up_required
    def fleet_revoke_inbound_token(token_id: int):
        owner = _admin_owner()
        with db() as conn:
            row = conn.execute("SELECT label FROM fleet_inbound_tokens WHERE id=? AND owner=?", (token_id, owner)).fetchone()
            if not row:
                return jsonify(ok=False, error="fleet token not found"), 404
            conn.execute("UPDATE fleet_inbound_tokens SET enabled=0 WHERE id=? AND owner=?", (token_id, owner))
        audit("fleet-token-revoke", f"id={token_id} label={row['label']}")
        return jsonify(ok=True, id=token_id, enabled=False)

    @app.post("/api/fleet/<int:node_id>/probe")
    @role_required("admin")
    def fleet_probe(node_id: int):
        owner = _admin_owner()
        with db() as conn:
            node = conn.execute("SELECT * FROM fleet_nodes WHERE id=? AND owner=? AND enabled=1", (node_id, owner)).fetchone()
        if not node:
            return jsonify(ok=False, error="fleet node not found"), 404
        result = _probe_endpoint(str(node["endpoint"]))
        now = int(time.time())
        with db() as conn:
            _store_probe(conn, node, result, now)
            updated = conn.execute("SELECT * FROM fleet_nodes WHERE id=?", (node_id,)).fetchone()
            payload = _node_payload(conn, updated)
        return jsonify(ok=True, node=payload)

    @app.post("/api/fleet/probe-all")
    @role_required("admin")
    def fleet_probe_all():
        data = request.get_json(silent=True) or {}
        raw_ids = data.get("node_ids") if isinstance(data, dict) else None
        with db() as conn:
            nodes, error = _select_nodes(conn, raw_ids)
        if error:
            return jsonify(ok=False, error=error), 400 if raw_ids is not None else 409
        results = []
        for node in nodes:
            result = _probe_endpoint(str(node["endpoint"]))
            now = int(time.time())
            with db() as conn:
                _store_probe(conn, node, result, now)
                updated = conn.execute("SELECT * FROM fleet_nodes WHERE id=?", (int(node["id"]),)).fetchone()
                results.append(_node_payload(conn, updated))
        return jsonify(ok=True, probed=len(results), nodes=results)

    @app.post("/api/fleet/plan")
    @role_required("admin")
    def fleet_plan():
        data = request.get_json(silent=True) or {}
        operation = str(data.get("operation", "")).strip().lower() if isinstance(data, dict) else ""
        required = PLAN_OPERATIONS.get(operation)
        if not required:
            return jsonify(ok=False, error="unsupported fleet operation"), 400
        raw_ids = data.get("node_ids") if isinstance(data, dict) else None
        with db() as conn:
            nodes, error = _select_nodes(conn, raw_ids)
            if error:
                return jsonify(ok=False, error=error), 400 if raw_ids is not None else 409
            plans = []
            for node in nodes:
                latest = _latest_probe(conn, int(node["id"]))
                caps = latest.get("capabilities", {}) if latest else {}
                online = bool(latest and latest.get("status") == "online")
                capable = bool(caps.get(required)) if isinstance(caps, dict) else False
                credential = bool(str(node["credential_ref"] or ""))
                ready = online and capable and credential
                reason = "ready"
                if not online:
                    reason = "node is not online"
                elif not capable:
                    reason = f"missing capability: {required}"
                elif not credential:
                    reason = "fleet credential reference is not configured"
                plans.append({
                    "id": int(node["id"]),
                    "name": str(node["name"]),
                    "status": latest.get("status", "unknown") if latest else "unknown",
                    "remote_version": latest.get("remote_version", "") if latest else "",
                    "required_capability": required,
                    "credential_configured": credential,
                    "ready": ready,
                    "reason": reason,
                })
        return jsonify(ok=True, operation=operation, required_capability=required, nodes=plans, ready_count=sum(1 for plan in plans if plan["ready"]), blocked_count=sum(1 for plan in plans if not plan["ready"]), apply_supported=True, policy="allow-listed node operations only; credentials remain inside the root-owned Secret Vault")

    @app.post("/api/fleet/apply")
    @role_required("admin")
    @step_up_required
    def fleet_apply():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid fleet apply request"), 400
        operation = str(data.get("operation", "")).strip().lower()
        required = PLAN_OPERATIONS.get(operation)
        if not required:
            return jsonify(ok=False, error="unsupported fleet operation"), 400
        payload = data.get("payload") if isinstance(data.get("payload"), dict) else {}
        if len(json.dumps(payload, separators=(",", ":")).encode("utf-8")) > 4096:
            return jsonify(ok=False, error="fleet operation payload too large"), 400
        if operation == "system-updates" and not FINGERPRINT_RE.fullmatch(str(payload.get("fingerprint", "")).strip().lower()):
            return jsonify(ok=False, error="system-updates requires the reviewed remote fingerprint"), 400
        raw_ids = data.get("node_ids")
        with db() as conn:
            nodes, error = _select_nodes(conn, raw_ids)
            if error:
                return jsonify(ok=False, error=error), 400
            selected = []
            for node in nodes:
                latest = _latest_probe(conn, int(node["id"]))
                caps = latest.get("capabilities", {}) if latest else {}
                if not latest or latest.get("status") != "online" or not bool(caps.get(required)) or not str(node["credential_ref"] or ""):
                    return jsonify(ok=False, error=f"fleet node is not ready for apply: {node['name']}"), 409
                selected.append(dict(node))
        owner = _admin_owner()
        jobs = []
        for node in selected:
            request_id = secrets.token_hex(16)
            issued_at = int(time.time())
            with db() as conn:
                cur = conn.execute(
                    "INSERT INTO fleet_jobs(request_id,node_id,direction,operation,status,detail_json,owner,created_at,updated_at) VALUES(?,?,'outbound',?,'running','{}',?,?,?)",
                    (request_id, int(node["id"]), operation, owner, issued_at, issued_at),
                )
                job_id = int(cur.lastrowid)
            result = provider_call({"action": "fleet-apply", "endpoint": str(node["endpoint"]), "secret_id": str(node["credential_ref"]), "operation": operation, "request_id": request_id, "issued_at": issued_at, "payload": payload}, timeout=1910)
            status = "applied" if result.get("ok") else "failed"
            detail = {"result": _safe_result(result.get("result", {}))}
            if not result.get("ok"):
                detail["error"] = str(result.get("error", "remote fleet apply failed"))[:180]
            with db() as conn:
                conn.execute("UPDATE fleet_jobs SET status=?,detail_json=?,updated_at=? WHERE id=?", (status, json.dumps(detail, separators=(",", ":")), int(time.time()), job_id))
            jobs.append({"id": job_id, "request_id": request_id, "node_id": int(node["id"]), "name": str(node["name"]), "status": status, "error": detail.get("error", "")})
            audit("fleet-outbound-apply" if result.get("ok") else "fleet-outbound-failed", f"request={request_id} node={node['id']} operation={operation}")
        return jsonify(ok=all(job["status"] == "applied" for job in jobs), operation=operation, applied_count=sum(1 for job in jobs if job["status"] == "applied"), failed_count=sum(1 for job in jobs if job["status"] == "failed"), jobs=jobs), (200 if all(job["status"] == "applied" for job in jobs) else 207)

    @app.get("/api/fleet/jobs")
    @role_required("admin")
    def fleet_jobs():
        owner = _admin_owner()
        with db() as conn:
            rows = conn.execute("SELECT id,request_id,node_id,direction,operation,status,detail_json,created_at,updated_at FROM fleet_jobs WHERE owner=? ORDER BY id DESC LIMIT 100", (owner,)).fetchall()
        items = []
        for row in rows:
            try:
                detail = json.loads(row["detail_json"] or "{}")
            except Exception:
                detail = {}
            items.append({"id": int(row["id"]), "request_id": str(row["request_id"]), "node_id": row["node_id"], "direction": str(row["direction"]), "operation": str(row["operation"]), "status": str(row["status"]), "detail": detail if isinstance(detail, dict) else {}, "created_at": int(row["created_at"]), "updated_at": int(row["updated_at"])})
        return jsonify(ok=True, jobs=items)

    @app.delete("/api/fleet/<int:node_id>")
    @role_required("admin")
    @step_up_required
    def fleet_delete(node_id: int):
        owner = _admin_owner()
        with db() as conn:
            row = conn.execute("SELECT name FROM fleet_nodes WHERE id=? AND owner=?", (node_id, owner)).fetchone()
            if not row:
                return jsonify(ok=False, error="fleet node not found"), 404
            conn.execute("DELETE FROM fleet_nodes WHERE id=? AND owner=?", (node_id, owner))
        audit("fleet-node-delete", f"id={node_id} name={row['name']}")
        return jsonify(ok=True)
