from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
import time
import urllib.parse
import urllib.request

import dns.resolver
from flask import jsonify, request, session

from .config import DOMAIN_RE, DB_RE, PASSWORD_RE
from .core import audit, db
from .hosting_policy import enabled_features, package_for_user
from .ops_client import ops_call
from .security import role_required, step_up_required

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}$")
RECORD_TYPES = {"A", "AAAA", "CNAME", "TXT", "MX"}
NODE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{2,63}$")


def _owner_role(conn, owner: str) -> str:
    if owner == "admin":
        return "admin"
    row = conn.execute("SELECT role FROM users WHERE username=?", (owner,)).fetchone()
    return str(row["role"]) if row else "operator"


def _feature(conn, owner: str, feature_id: str) -> bool:
    role = _owner_role(conn, owner)
    package = package_for_user(conn, owner, role)
    package_id = int(package["id"]) if package else None
    return feature_id in enabled_features(conn, package_id, role)


def _site_scope(conn, domain: str) -> tuple[bool, str | None]:
    domain = str(domain).strip().lower()
    if not DOMAIN_RE.fullmatch(domain):
        return False, None
    row = conn.execute("SELECT owner,enabled FROM sites WHERE domain=?", (domain,)).fetchone()
    if not row or not row["enabled"]:
        return False, None
    owner = str(row["owner"])
    if session.get("role") == "admin" or owner == session.get("user"):
        return True, owner
    return False, owner


def _public_https(value: str) -> str:
    try:
        parts = urllib.parse.urlsplit(str(value).strip())
    except ValueError:
        raise ValueError("invalid HTTPS endpoint")
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError("endpoint must be public HTTPS without embedded credentials")
    host = parts.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith((".localhost", ".local")):
        raise ValueError("private/local fleet endpoints are blocked")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9.-]+", host):
            raise ValueError("invalid endpoint host")
    else:
        if not address.is_global:
            raise ValueError("private/local fleet endpoints are blocked")
    return urllib.parse.urlunsplit(parts).rstrip("/")


def _dns_target(conn, domain: str):
    return conn.execute(
        """SELECT b.domain,b.target_id,t.provider,t.endpoint,t.secret_kind,t.secret_id,t.enabled
           FROM dns_zone_bindings b JOIN integration_targets t ON t.id=b.target_id
           WHERE b.domain=?""",
        (domain,),
    ).fetchone()


def _visible_where() -> tuple[str, tuple]:
    if session.get("role") == "admin":
        return "1=1", ()
    return "owner=?", (str(session.get("user", ""))[:64],)


def _safe_dns_payload(data: dict) -> dict:
    operation = str(data.get("operation", "create")).lower()
    record_type = str(data.get("record_type", "")).upper()
    record_name = str(data.get("record_name", "")).strip().rstrip(".").lower()
    record_value = str(data.get("record_value", "")).strip()
    provider_record_id = str(data.get("provider_record_id", "")).strip()
    if operation not in {"create", "update", "delete"} or record_type not in RECORD_TYPES:
        raise ValueError("invalid DNS operation or record type")
    if not record_name or len(record_name) > 253 or not record_value or len(record_value) > 4096 or any(c in record_value for c in "\r\n\x00"):
        raise ValueError("invalid DNS record")
    try:
        ttl = int(data.get("ttl", 300)); priority = int(data.get("priority", 0))
    except (TypeError, ValueError):
        raise ValueError("invalid DNS record options")
    if not 60 <= ttl <= 86400 or not 0 <= priority <= 65535:
        raise ValueError("invalid DNS record options")
    if operation in {"update", "delete"} and not provider_record_id and str(data.get("provider", "")) == "cloudflare":
        raise ValueError("Cloudflare update/delete requires provider_record_id")
    return {"operation": operation, "record_type": record_type, "record_name": record_name, "record_value": record_value, "ttl": ttl, "priority": priority, "provider_record_id": provider_record_id}


def register_advanced_ops_routes(app):
    @app.get("/api/advanced/status")
    @role_required("admin", "operator")
    def advanced_status():
        where, args = _visible_where()
        with db() as conn:
            sites = [dict(r) for r in conn.execute(f"SELECT domain,owner,kind FROM sites WHERE enabled=1 AND {where} ORDER BY domain", args).fetchall()]
            pg = [dict(r) for r in conn.execute(f"SELECT id,db_name,db_user,site_domain,owner,created_at FROM postgres_resources WHERE {where} ORDER BY id DESC", args).fetchall()]
            bundles = [dict(r) for r in conn.execute(f"SELECT id,domain,archive,size_bytes,sha256,status,owner,created_at FROM migration_bundles WHERE {where} ORDER BY id DESC LIMIT 100", args).fetchall()]
            bindings = [dict(r) for r in conn.execute("SELECT b.domain,b.target_id,t.name,t.provider,t.endpoint FROM dns_zone_bindings b JOIN integration_targets t ON t.id=b.target_id ORDER BY b.domain").fetchall()] if session.get("role") == "admin" else [dict(r) for r in conn.execute("SELECT b.domain,b.target_id,t.name,t.provider,t.endpoint FROM dns_zone_bindings b JOIN integration_targets t ON t.id=b.target_id JOIN sites s ON s.domain=b.domain WHERE s.owner=? ORDER BY b.domain", (session.get("user"),)).fetchall()]
            fleet = [dict(r) for r in conn.execute("SELECT id,name,endpoint,enabled,status,last_seen,created_at,updated_at FROM fleet_nodes WHERE owner=? ORDER BY name", (session.get("user"),)).fetchall()] if session.get("role") == "admin" else []
        provider = ops_call({"action": "status"}, timeout=5)
        php = ops_call({"action": "php-list"}, timeout=5)
        services = ops_call({"action": "service-status"}, timeout=8) if session.get("role") == "admin" else {"ok": True, "services": []}
        return jsonify(ok=True, provider={"online": bool(provider.get("ok")), "capabilities": provider.get("capabilities", {})}, sites=sites, postgres=pg, migrations=bundles, dns_bindings=bindings, php_versions=php.get("versions", []) if php.get("ok") else [], services=services.get("services", []) if services.get("ok") else [], fleet=fleet)

    @app.post("/api/advanced/dns/bind")
    @role_required("admin")
    @step_up_required
    def dns_bind():
        data = request.get_json(silent=True) or {}
        domain = str(data.get("domain", "")).strip().lower()
        try: target_id = int(data.get("target_id", 0))
        except (TypeError, ValueError): target_id = 0
        with db() as conn:
            allowed, owner = _site_scope(conn, domain)
            if not allowed or not owner:
                return jsonify(ok=False, error="managed site not found"), 404
            target = conn.execute("SELECT * FROM integration_targets WHERE id=? AND enabled=1 AND provider IN ('cloudflare','powerdns')", (target_id,)).fetchone()
            if not target:
                return jsonify(ok=False, error="DNS integration target not found"), 404
            conn.execute("INSERT INTO dns_zone_bindings(domain,target_id,owner,updated_at) VALUES(?,?,?,?) ON CONFLICT(domain) DO UPDATE SET target_id=excluded.target_id,owner=excluded.owner,updated_at=excluded.updated_at", (domain, target_id, owner, int(time.time())))
        audit("dns-zone-bind", f"domain={domain} target_id={target_id} provider={target['provider']}")
        return jsonify(ok=True, domain=domain, target_id=target_id)

    @app.post("/api/advanced/dns/preview")
    @role_required("admin", "operator")
    def dns_preview():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict): return jsonify(ok=False, error="invalid request"), 400
        domain = str(data.get("domain", "")).strip().lower()
        try: payload = _safe_dns_payload(data)
        except ValueError as exc: return jsonify(ok=False, error=str(exc)), 400
        with db() as conn:
            allowed, owner = _site_scope(conn, domain)
            if not allowed or not owner: return jsonify(ok=False, error="DNS zone outside your scope"), 403
            if not _feature(conn, owner, "domains.zone_editor"): return jsonify(ok=False, error="domains.zone_editor disabled by hosting policy"), 403
            target = _dns_target(conn, domain)
            if not target or not target["enabled"]: return jsonify(ok=False, error="DNS zone has no active provider binding"), 409
            name = payload["record_name"]
            if name == "@": name = domain
            if name != domain and not name.endswith("." + domain): return jsonify(ok=False, error="record name must remain inside the bound zone"), 400
            cur = conn.execute("INSERT INTO dns_changes(domain,target_id,operation,record_type,record_name,record_value,ttl,priority,provider_record_id,status,owner,created_at) VALUES(?,?,?,?,?,?,?,?,?,'preview',?,?)", (domain, int(target["target_id"]), payload["operation"], payload["record_type"], name, payload["record_value"], payload["ttl"], payload["priority"], payload["provider_record_id"], owner, int(time.time())))
            change_id = int(cur.lastrowid)
        return jsonify(ok=True, change={"id": change_id, "domain": domain, **payload, "record_name": name, "provider": target["provider"], "status": "preview"})

    @app.post("/api/advanced/dns/<int:change_id>/apply")
    @role_required("admin", "operator")
    @step_up_required
    def dns_apply(change_id: int):
        with db() as conn:
            row = conn.execute("SELECT * FROM dns_changes WHERE id=?", (change_id,)).fetchone()
            if not row: return jsonify(ok=False, error="DNS change not found"), 404
            allowed, owner = _site_scope(conn, row["domain"])
            if not allowed or owner != row["owner"]: return jsonify(ok=False, error="DNS change outside your scope"), 403
            if row["status"] != "preview": return jsonify(ok=False, error="DNS change is not in preview state"), 409
            target = _dns_target(conn, row["domain"])
            if not target or int(target["target_id"]) != int(row["target_id"]): return jsonify(ok=False, error="DNS provider binding changed; create a new preview"), 409
        result = ops_call({"action": "dns-apply", "provider": target["provider"], "endpoint": target["endpoint"], "secret_id": target["secret_id"], "domain": row["domain"], "operation": row["operation"], "record_type": row["record_type"], "record_name": row["record_name"], "record_value": row["record_value"], "ttl": row["ttl"], "priority": row["priority"], "provider_record_id": row["provider_record_id"]}, timeout=35)
        if not result.get("ok"): return jsonify(ok=False, error=str(result.get("error", "DNS provider failed"))[:180]), 503
        with db() as conn:
            conn.execute("UPDATE dns_changes SET status='applied',snapshot_json=?,provider_record_id=?,applied_at=? WHERE id=?", (json.dumps(result.get("snapshot", {}), separators=(",", ":")), str(result.get("provider_record_id", row["provider_record_id"]))[:160], int(time.time()), change_id))
        audit("dns-change-apply", f"id={change_id} domain={row['domain']} type={row['record_type']} op={row['operation']}")
        return jsonify(ok=True, id=change_id, status="applied")

    @app.post("/api/advanced/dns/<int:change_id>/rollback")
    @role_required("admin", "operator")
    @step_up_required
    def dns_rollback(change_id: int):
        with db() as conn:
            row = conn.execute("SELECT * FROM dns_changes WHERE id=?", (change_id,)).fetchone()
            if not row or row["status"] != "applied": return jsonify(ok=False, error="applied DNS change not found"), 404
            allowed, owner = _site_scope(conn, row["domain"])
            if not allowed or owner != row["owner"]: return jsonify(ok=False, error="DNS change outside your scope"), 403
            target = _dns_target(conn, row["domain"])
        try: snapshot = json.loads(row["snapshot_json"] or "{}")
        except Exception: return jsonify(ok=False, error="stored DNS rollback snapshot is invalid"), 409
        result = ops_call({"action": "dns-rollback", "provider": target["provider"], "endpoint": target["endpoint"], "secret_id": target["secret_id"], "snapshot": snapshot}, timeout=35)
        if not result.get("ok"): return jsonify(ok=False, error=str(result.get("error", "DNS rollback failed"))[:180]), 503
        with db() as conn: conn.execute("UPDATE dns_changes SET status='rolled_back' WHERE id=?", (change_id,))
        audit("dns-change-rollback", f"id={change_id} domain={row['domain']}")
        return jsonify(ok=True, id=change_id, status="rolled_back")

    @app.get("/api/advanced/ssl")
    @role_required("admin", "operator")
    def ssl_status():
        domain = str(request.args.get("domain", "")).strip().lower()
        with db() as conn:
            allowed, owner = _site_scope(conn, domain)
            if not allowed or not owner: return jsonify(ok=False, error="site outside your scope"), 403
            if not _feature(conn, owner, "security.ssl_tls"): return jsonify(ok=False, error="security.ssl_tls disabled by hosting policy"), 403
        result = ops_call({"action": "ssl-status", "domain": domain}, timeout=10)
        return jsonify(result), (200 if result.get("ok") else 503)

    @app.post("/api/advanced/ssl/issue")
    @role_required("admin", "operator")
    @step_up_required
    def ssl_issue():
        data = request.get_json(silent=True) or {}; domain = str(data.get("domain", "")).strip().lower(); email = str(data.get("email", "")).strip().lower()
        if not EMAIL_RE.fullmatch(email): return jsonify(ok=False, error="valid contact email required"), 400
        with db() as conn:
            allowed, owner = _site_scope(conn, domain)
            if not allowed or not owner: return jsonify(ok=False, error="site outside your scope"), 403
            if not _feature(conn, owner, "security.ssl_tls"): return jsonify(ok=False, error="security.ssl_tls disabled by hosting policy"), 403
        result = ops_call({"action": "ssl-issue", "domain": domain, "email": email}, timeout=240)
        now = int(time.time())
        with db() as conn: conn.execute("INSERT INTO ssl_jobs(domain,action,contact_email,status,detail,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", (domain, "issue", email, "success" if result.get("ok") else "failed", str(result.get("detail", result.get("error", "")))[:1000], owner, now, now))
        audit("ssl-issue", f"domain={domain} status={'ok' if result.get('ok') else 'failed'}")
        return jsonify(result), (200 if result.get("ok") else 503)

    @app.post("/api/advanced/ssl/renew")
    @role_required("admin", "operator")
    @step_up_required
    def ssl_renew():
        data = request.get_json(silent=True) or {}; domain = str(data.get("domain", "")).strip().lower()
        with db() as conn:
            allowed, owner = _site_scope(conn, domain)
            if not allowed or not owner: return jsonify(ok=False, error="site outside your scope"), 403
        result = ops_call({"action": "ssl-renew", "domain": domain}, timeout=240)
        audit("ssl-renew", f"domain={domain} status={'ok' if result.get('ok') else 'failed'}")
        return jsonify(result), (200 if result.get("ok") else 503)

    @app.get("/api/advanced/mail/queue")
    @role_required("admin")
    def mail_queue():
        result = ops_call({"action": "mail-queue"}, timeout=12)
        return jsonify(result), (200 if result.get("ok") else 503)

    @app.post("/api/advanced/mail/flush")
    @role_required("admin")
    @step_up_required
    def mail_flush():
        result = ops_call({"action": "mail-flush"}, timeout=20)
        if result.get("ok"): audit("mail-queue-flush", "Postfix queue flush requested")
        return jsonify(result), (200 if result.get("ok") else 503)

    @app.get("/api/advanced/mail/deliverability")
    @role_required("admin", "operator")
    def mail_deliverability():
        domain = str(request.args.get("domain", "")).strip().lower()
        with db() as conn:
            allowed, owner = _site_scope(conn, domain)
            if not allowed or not owner: return jsonify(ok=False, error="domain outside your scope"), 403
            if not _feature(conn, owner, "email.deliverability"): return jsonify(ok=False, error="email.deliverability disabled by hosting policy"), 403
        resolver = dns.resolver.Resolver(); resolver.lifetime = 4
        def query(name, rdtype):
            try: return [str(x).strip('"') for x in resolver.resolve(name, rdtype)]
            except Exception: return []
        mx = query(domain, "MX"); txt = query(domain, "TXT"); dmarc = query("_dmarc." + domain, "TXT")
        spf = [x for x in txt if x.lower().startswith("v=spf1")]
        return jsonify(ok=True, domain=domain, mx=mx[:20], spf=spf[:5], dmarc=dmarc[:5], score=int(bool(mx))*35 + int(bool(spf))*35 + int(bool(dmarc))*30)

    @app.post("/api/advanced/php")
    @role_required("admin", "operator")
    @step_up_required
    def php_set():
        data = request.get_json(silent=True) or {}; domain = str(data.get("domain", "")).strip().lower(); version = str(data.get("version", "")).strip()
        with db() as conn:
            allowed, owner = _site_scope(conn, domain)
            if not allowed or not owner: return jsonify(ok=False, error="site outside your scope"), 403
            if not _feature(conn, owner, "software.php_manager"): return jsonify(ok=False, error="software.php_manager disabled by hosting policy"), 403
        result = ops_call({"action": "php-set", "domain": domain, "version": version}, timeout=30)
        if not result.get("ok"): return jsonify(result), 503
        with db() as conn: conn.execute("INSERT INTO php_runtime_assignments(domain,version,owner,updated_at) VALUES(?,?,?,?) ON CONFLICT(domain) DO UPDATE SET version=excluded.version,owner=excluded.owner,updated_at=excluded.updated_at", (domain, version, owner, int(time.time())))
        audit("php-runtime-set", f"domain={domain} version={version}")
        return jsonify(result)

    @app.post("/api/advanced/postgres")
    @role_required("admin", "operator")
    @step_up_required
    def postgres_create():
        data = request.get_json(silent=True) or {}; db_name = str(data.get("db_name", "")).strip(); db_user = str(data.get("db_user", "")).strip(); password = str(data.get("password", "")); domain = str(data.get("site_domain", "")).strip().lower()
        if not DB_RE.fullmatch(db_name) or not DB_RE.fullmatch(db_user) or not PASSWORD_RE.fullmatch(password): return jsonify(ok=False, error="invalid PostgreSQL database, user or password"), 400
        with db() as conn:
            allowed, owner = _site_scope(conn, domain)
            if not allowed or not owner: return jsonify(ok=False, error="site outside your scope"), 403
            if not _feature(conn, owner, "databases.postgresql"): return jsonify(ok=False, error="databases.postgresql disabled by hosting policy"), 403
            package = package_for_user(conn, owner, _owner_role(conn, owner)); limit = int(package["max_databases"]) if package else 0
            used = int(conn.execute("SELECT COUNT(*) FROM databases WHERE owner=?", (owner,)).fetchone()[0]) + int(conn.execute("SELECT COUNT(*) FROM postgres_resources WHERE owner=?", (owner,)).fetchone()[0])
            if limit <= 0 or used >= limit: return jsonify(ok=False, error="database quota reached"), 409
        result = ops_call({"action": "postgres-create", "db_name": db_name, "db_user": db_user, "password": password}, timeout=45)
        if not result.get("ok"): return jsonify(result), 503
        try:
            with db() as conn: conn.execute("INSERT INTO postgres_resources(db_name,db_user,site_domain,owner,created_at) VALUES(?,?,?,?,?)", (db_name, db_user, domain, owner, int(time.time())))
        except sqlite3.IntegrityError: return jsonify(ok=False, error="PostgreSQL resource metadata conflict"), 409
        audit("postgres-create", f"db={db_name} user={db_user} domain={domain} owner={owner}")
        return jsonify(ok=True, db_name=db_name, db_user=db_user), 201

    @app.delete("/api/advanced/postgres/<int:resource_id>")
    @role_required("admin", "operator")
    @step_up_required
    def postgres_delete(resource_id: int):
        with db() as conn:
            row = conn.execute("SELECT * FROM postgres_resources WHERE id=?", (resource_id,)).fetchone()
            if not row: return jsonify(ok=False, error="PostgreSQL resource not found"), 404
            if session.get("role") != "admin" and row["owner"] != session.get("user"): return jsonify(ok=False, error="resource outside your scope"), 403
        result = ops_call({"action": "postgres-delete", "db_name": row["db_name"], "db_user": row["db_user"]}, timeout=45)
        if not result.get("ok"): return jsonify(result), 503
        with db() as conn: conn.execute("DELETE FROM postgres_resources WHERE id=?", (resource_id,))
        audit("postgres-delete", f"db={row['db_name']} user={row['db_user']} owner={row['owner']}")
        return jsonify(ok=True)

    @app.post("/api/advanced/migrations/export")
    @role_required("admin", "operator")
    @step_up_required
    def migration_export():
        data = request.get_json(silent=True) or {}; domain = str(data.get("domain", "")).strip().lower(); db_name = str(data.get("db_name", "")).strip()
        with db() as conn:
            allowed, owner = _site_scope(conn, domain)
            if not allowed or not owner: return jsonify(ok=False, error="site outside your scope"), 403
            if not _feature(conn, owner, "files.backups"): return jsonify(ok=False, error="files.backups disabled by hosting policy"), 403
            if db_name and not conn.execute("SELECT 1 FROM databases WHERE db_name=? AND owner=? AND site_domain=?", (db_name, owner, domain)).fetchone(): return jsonify(ok=False, error="database is not bound to this site"), 403
        result = ops_call({"action": "migration-export", "domain": domain, "db_name": db_name}, timeout=180)
        if not result.get("ok"): return jsonify(result), 503
        with db() as conn:
            cur = conn.execute("INSERT INTO migration_bundles(domain,archive,size_bytes,sha256,status,owner,created_at) VALUES(?,?,?,?, 'ready',?,?)", (domain, result["archive"], int(result.get("size_bytes", 0)), str(result.get("sha256", "")), owner, int(time.time())))
            bundle_id = int(cur.lastrowid)
        audit("migration-export", f"id={bundle_id} domain={domain} owner={owner}")
        return jsonify(ok=True, id=bundle_id, size_bytes=result.get("size_bytes", 0), sha256=result.get("sha256", "")), 201

    @app.post("/api/advanced/migrations/<int:bundle_id>/restore")
    @role_required("admin", "operator")
    @step_up_required
    def migration_restore(bundle_id: int):
        data = request.get_json(silent=True) or {}; db_name = str(data.get("db_name", "")).strip()
        with db() as conn:
            row = conn.execute("SELECT * FROM migration_bundles WHERE id=?", (bundle_id,)).fetchone()
            if not row: return jsonify(ok=False, error="migration bundle not found"), 404
            if session.get("role") != "admin" and row["owner"] != session.get("user"): return jsonify(ok=False, error="bundle outside your scope"), 403
            if db_name and not conn.execute("SELECT 1 FROM databases WHERE db_name=? AND owner=? AND site_domain=?", (db_name, row["owner"], row["domain"])).fetchone(): return jsonify(ok=False, error="database is not bound to this site"), 403
        result = ops_call({"action": "migration-restore", "domain": row["domain"], "archive": row["archive"], "db_name": db_name}, timeout=180)
        if not result.get("ok"): return jsonify(result), 503
        audit("migration-restore", f"id={bundle_id} domain={row['domain']} rollback={result.get('rollback','')}")
        return jsonify(ok=True, rollback=result.get("rollback", ""))

    @app.post("/api/advanced/services")
    @role_required("admin")
    @step_up_required
    def service_action():
        data = request.get_json(silent=True) or {}; name = str(data.get("name", "")); operation = str(data.get("operation", ""))
        result = ops_call({"action": "service-action", "name": name, "operation": operation}, timeout=45)
        if result.get("ok"): audit("service-control", f"service={name} operation={operation}")
        return jsonify(result), (200 if result.get("ok") else 503)

    @app.post("/api/advanced/fleet")
    @role_required("admin")
    @step_up_required
    def fleet_create():
        data = request.get_json(silent=True) or {}; name = str(data.get("name", "")).strip(); endpoint = str(data.get("endpoint", "")).strip()
        if not NODE_NAME_RE.fullmatch(name): return jsonify(ok=False, error="invalid fleet node name"), 400
        try: endpoint = _public_https(endpoint)
        except ValueError as exc: return jsonify(ok=False, error=str(exc)), 400
        now = int(time.time()); owner = str(session.get("user", "admin"))[:64]
        try:
            with db() as conn: cur = conn.execute("INSERT INTO fleet_nodes(name,endpoint,enabled,owner,status,last_seen,created_at,updated_at) VALUES(?,?,1,?,'unknown',0,?,?)", (name, endpoint, owner, now, now)); node_id = int(cur.lastrowid)
        except sqlite3.IntegrityError: return jsonify(ok=False, error="fleet node name already exists"), 409
        audit("fleet-node-create", f"id={node_id} name={name} endpoint={endpoint}")
        return jsonify(ok=True, id=node_id, name=name, endpoint=endpoint), 201

    @app.post("/api/advanced/fleet/<int:node_id>/probe")
    @role_required("admin")
    def fleet_probe(node_id: int):
        owner = str(session.get("user", "admin"))[:64]
        with db() as conn: row = conn.execute("SELECT * FROM fleet_nodes WHERE id=? AND owner=? AND enabled=1", (node_id, owner)).fetchone()
        if not row: return jsonify(ok=False, error="fleet node not found"), 404
        try:
            endpoint = _public_https(row["endpoint"]); req = urllib.request.Request(endpoint + "/api/health", headers={"Accept": "application/json", "User-Agent": "Nexvary-Fleet/0.7"}, method="GET")
            with urllib.request.urlopen(req, timeout=5) as response: raw = response.read(64 * 1024)
            body = json.loads(raw.decode()) if raw else {}; healthy = bool(isinstance(body, dict) and body.get("ok", True)); status = "online" if healthy else "degraded"
        except Exception: status = "offline"; body = {}
        now = int(time.time())
        with db() as conn: conn.execute("UPDATE fleet_nodes SET status=?,last_seen=?,updated_at=? WHERE id=?", (status, now if status != "offline" else int(row["last_seen"]), now, node_id))
        return jsonify(ok=True, id=node_id, status=status, remote_version=str(body.get("version", ""))[:40] if isinstance(body, dict) else "")

    @app.delete("/api/advanced/fleet/<int:node_id>")
    @role_required("admin")
    @step_up_required
    def fleet_delete(node_id: int):
        owner = str(session.get("user", "admin"))[:64]
        with db() as conn:
            row = conn.execute("SELECT name FROM fleet_nodes WHERE id=? AND owner=?", (node_id, owner)).fetchone()
            if not row: return jsonify(ok=False, error="fleet node not found"), 404
            conn.execute("DELETE FROM fleet_nodes WHERE id=? AND owner=?", (node_id, owner))
        audit("fleet-node-delete", f"id={node_id} name={row['name']}")
        return jsonify(ok=True)
