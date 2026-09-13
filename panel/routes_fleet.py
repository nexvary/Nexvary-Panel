from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from flask import jsonify, request, session

from .core import audit, db
from .security import role_required, step_up_required

NODE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{2,63}$")
CAPABILITY_KEY_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
MAX_FLEET_NODES = 100
MAX_PROBE_BATCH = 25
ALLOWED_PORTS = {443, 8443}
PLAN_OPERATIONS = {
    "upgrade-panel": "panel.upgrade",
    "renew-autossl": "autossl",
    "reload-nginx": "nginx",
    "flush-mail-queue": "mail",
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
    netloc = host if port == 443 else f"{host}:{port}"
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
    url = endpoint.rstrip("/") + "/api/health"
    opener = urllib.request.build_opener(_NoRedirect())
    started = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "Nexvary-Fleet/0.7"}, method="GET")
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


def register_fleet_routes(app):
    @app.before_request
    def fleet_legacy_guard():
        path = request.path.rstrip("/")
        if path == "/api/advanced/fleet" or re.fullmatch(r"/api/advanced/fleet/\d+(?:/probe)?", path):
            if request.method in {"POST", "DELETE", "PUT", "PATCH"}:
                return jsonify(ok=False, error="legacy Fleet API retired; use /api/fleet endpoints"), 410
        return None

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
        return jsonify(ok=True, nodes=nodes, counts=counts, batch_limit=MAX_PROBE_BATCH, remote_apply_supported=False)

    @app.post("/api/fleet")
    @role_required("admin")
    @step_up_required
    def fleet_create():
        data = request.get_json(silent=True) or {}
        name = str(data.get("name", "")).strip()
        endpoint_raw = str(data.get("endpoint", "")).strip()
        if not NODE_NAME_RE.fullmatch(name):
            return jsonify(ok=False, error="invalid fleet node name"), 400
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
                    "INSERT INTO fleet_nodes(name,endpoint,enabled,owner,status,last_seen,created_at,updated_at) VALUES(?,?,1,?,'unknown',0,?,?)",
                    (name, endpoint, owner, now, now),
                )
                node_id = int(cur.lastrowid)
        except Exception as exc:
            if exc.__class__.__name__ == "IntegrityError":
                return jsonify(ok=False, error="fleet node name already exists"), 409
            raise
        audit("fleet-node-create", f"id={node_id} name={name} endpoint={endpoint}")
        return jsonify(ok=True, id=node_id, name=name, endpoint=endpoint), 201

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
                plans.append(
                    {
                        "id": int(node["id"]),
                        "name": str(node["name"]),
                        "status": latest.get("status", "unknown") if latest else "unknown",
                        "remote_version": latest.get("remote_version", "") if latest else "",
                        "required_capability": required,
                        "ready": online and capable,
                        "reason": "ready" if online and capable else ("node is not online" if not online else f"missing capability: {required}"),
                    }
                )
        return jsonify(
            ok=True,
            operation=operation,
            required_capability=required,
            nodes=plans,
            ready_count=sum(1 for plan in plans if plan["ready"]),
            blocked_count=sum(1 for plan in plans if not plan["ready"]),
            apply_supported=False,
            policy="preview-only until authenticated node-to-node execution is introduced; no remote command is sent by this endpoint",
        )

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
