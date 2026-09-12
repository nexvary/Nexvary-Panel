from __future__ import annotations

import re
import sqlite3
import time

from flask import jsonify, request, session

from .config import DB_RE, DOMAIN_RE
from .core import audit, db
from .hosting_policy import feature_allowed, package_limit
from .security import role_required, step_up_required
from .wordpress_client import wordpress_call

SNAPSHOT_RE = re.compile(r"^[0-9]{10}-[a-f0-9]{8}$")


def _owner_role(conn, owner: str) -> str:
    if owner == "admin":
        return "admin"
    row = conn.execute("SELECT role FROM users WHERE username=?", (owner,)).fetchone()
    return str(row["role"]) if row else "operator"


def _source_context(conn, domain: str):
    if not DOMAIN_RE.fullmatch(domain):
        return None, None, None
    site = conn.execute("SELECT domain,kind,owner,enabled FROM sites WHERE domain=?", (domain,)).fetchone()
    instance = conn.execute("SELECT domain,db_name,db_user,status,version,owner FROM wordpress_instances WHERE domain=?", (domain,)).fetchone()
    if not site or not instance:
        return None, None, None
    owner = str(site["owner"])
    if str(instance["owner"]) != owner:
        return None, None, None
    if session.get("role") != "admin" and owner != str(session.get("user", "")):
        return None, None, None
    role = _owner_role(conn, owner)
    if not feature_allowed("software.wordpress", username=owner, role=role, connection=conn):
        return site, instance, None
    return site, instance, role


def _provider_error(result: dict):
    error = str(result.get("error", "wordpress staging provider unavailable"))[:180]
    conflict = {
        "staging-target-not-empty",
        "staging-target-must-differ",
        "staging-database-must-differ",
        "wordpress-staging-tree-too-large",
    }
    status = 409 if error in conflict else 503
    return jsonify(ok=False, error=error), status


def _mapping_row(conn, source_domain: str):
    return conn.execute(
        "SELECT id,source_domain,target_domain,source_db,target_db,db_user,owner,status,last_publish_snapshot,created_at,updated_at "
        "FROM wordpress_staging WHERE source_domain=?",
        (source_domain,),
    ).fetchone()


def register_wordpress_staging_routes(app):
    @app.get("/api/wordpress/staging")
    @role_required("admin", "operator", "viewer")
    def wordpress_staging_status():
        source = str(request.args.get("domain", "")).strip().lower().rstrip(".")
        with db() as conn:
            site, instance, role = _source_context(conn, source)
            if not site or not instance:
                return jsonify(ok=False, error="WordPress site outside your scope"), 403
            if role is None:
                return jsonify(ok=False, error="software.wordpress disabled by hosting policy"), 403
            owner = str(site["owner"])
            mapping = _mapping_row(conn, source)
            rows = conn.execute(
                "SELECT domain,kind,enabled FROM sites WHERE owner=? AND kind='php' AND domain<>? ORDER BY domain",
                (owner, source),
            ).fetchall()
            targets = []
            for row in rows:
                domain = str(row["domain"])
                other_stage = conn.execute("SELECT source_domain FROM wordpress_staging WHERE target_domain=?", (domain,)).fetchone()
                wp_row = conn.execute("SELECT status FROM wordpress_instances WHERE domain=?", (domain,)).fetchone()
                allowed = (not other_stage or (mapping and domain == str(mapping["target_domain"]))) and (not wp_row or (mapping and domain == str(mapping["target_domain"])))
                if allowed:
                    targets.append(dict(row))
            used_db = int(conn.execute("SELECT COUNT(*) FROM databases WHERE owner=?", (owner,)).fetchone()[0])
            db_limit = package_limit("max_databases", username=owner, role=role, connection=conn)
        return jsonify(
            ok=True,
            source_domain=source,
            mapping=dict(mapping) if mapping else None,
            targets=targets,
            database_quota={"used": used_db, "limit": db_limit, "remaining": max(0, db_limit - used_db)},
        )

    @app.post("/api/wordpress/staging/clone")
    @role_required("admin", "operator")
    @step_up_required
    def wordpress_staging_clone():
        data = request.get_json(silent=True) or {}
        source = str(data.get("source_domain", "")).strip().lower().rstrip(".")
        target = str(data.get("target_domain", "")).strip().lower().rstrip(".")
        target_db = str(data.get("target_db", "")).strip()
        if not DOMAIN_RE.fullmatch(source) or not DOMAIN_RE.fullmatch(target) or source == target or not DB_RE.fullmatch(target_db):
            return jsonify(ok=False, error="invalid WordPress staging request"), 400

        with db() as conn:
            site, instance, role = _source_context(conn, source)
            if not site or not instance:
                return jsonify(ok=False, error="WordPress site outside your scope"), 403
            if role is None:
                return jsonify(ok=False, error="software.wordpress disabled by hosting policy"), 403
            owner = str(site["owner"])
            target_site = conn.execute("SELECT domain,kind,owner,enabled FROM sites WHERE domain=?", (target,)).fetchone()
            if not target_site or str(target_site["owner"]) != owner or str(target_site["kind"]) != "php":
                return jsonify(ok=False, error="staging target must be a PHP site owned by the same account"), 403
            mapping = _mapping_row(conn, source)
            if mapping:
                if str(mapping["target_domain"]) != target or str(mapping["target_db"]) != target_db:
                    return jsonify(ok=False, error="this source already has a different staging target"), 409
                replace = True
            else:
                replace = False
                if conn.execute("SELECT 1 FROM wordpress_staging WHERE target_domain=? OR target_db=?", (target, target_db)).fetchone():
                    return jsonify(ok=False, error="staging target is already reserved"), 409
                if conn.execute("SELECT 1 FROM wordpress_instances WHERE domain=?", (target,)).fetchone():
                    return jsonify(ok=False, error="target site already contains a registered WordPress instance"), 409
                if conn.execute("SELECT 1 FROM databases WHERE db_name=?", (target_db,)).fetchone():
                    return jsonify(ok=False, error="staging database name is already registered"), 409
                used_db = int(conn.execute("SELECT COUNT(*) FROM databases WHERE owner=?", (owner,)).fetchone()[0])
                db_limit = package_limit("max_databases", username=owner, role=role, connection=conn)
                if db_limit <= 0 or used_db >= db_limit:
                    return jsonify(ok=False, error=f"database quota reached ({used_db}/{db_limit})"), 409

        result = wordpress_call(
            {"action": "staging-clone", "source_domain": source, "target_domain": target, "target_db": target_db, "replace": replace},
            timeout=240,
        )
        if not result.get("ok"):
            audit("wordpress-staging-clone", f"source={source} target={target} status=failed")
            return _provider_error(result)

        now = int(time.time())
        source_db = str(result.get("source_db", instance["db_name"]))[:32]
        db_user = str(result.get("db_user", instance["db_user"]))[:32]
        version = str(result.get("version", instance["version"] or ""))[:40]
        try:
            with db() as conn:
                if not replace:
                    conn.execute(
                        "INSERT INTO databases(db_name,db_user,engine,site_domain,owner,created_at) VALUES(?,?,?,?,?,?)",
                        (target_db, db_user, "mariadb", target, owner, now),
                    )
                    conn.execute(
                        "INSERT INTO wordpress_instances(domain,db_name,db_user,status,version,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                        (target, target_db, db_user, "staging", version, owner, now, now),
                    )
                    conn.execute(
                        "INSERT INTO wordpress_staging(source_domain,target_domain,source_db,target_db,db_user,owner,status,last_publish_snapshot,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (source, target, source_db, target_db, db_user, owner, "ready", "", now, now),
                    )
                else:
                    conn.execute("UPDATE wordpress_instances SET status='staging',version=?,updated_at=? WHERE domain=?", (version, now, target))
                    conn.execute("UPDATE wordpress_staging SET source_db=?,db_user=?,status='ready',updated_at=? WHERE source_domain=?", (source_db, db_user, now, source))
        except sqlite3.IntegrityError:
            audit("wordpress-staging-clone", f"source={source} target={target} status=metadata-conflict")
            return jsonify(ok=False, error="staging was cloned but panel metadata conflicted; manual reconciliation required"), 500

        audit("wordpress-staging-refresh" if replace else "wordpress-staging-create", f"source={source} target={target} db={target_db}")
        return jsonify(
            ok=True,
            source_domain=source,
            target_domain=target,
            target_db=target_db,
            version=version,
            refreshed=replace,
            rewrite_scope=str(result.get("rewrite_scope", "home-siteurl")),
        )

    @app.post("/api/wordpress/staging/publish-preview")
    @role_required("admin", "operator", "viewer")
    def wordpress_staging_publish_preview():
        data = request.get_json(silent=True) or {}
        source = str(data.get("source_domain", "")).strip().lower().rstrip(".")
        with db() as conn:
            site, instance, role = _source_context(conn, source)
            mapping = _mapping_row(conn, source) if site and instance else None
            if not site or not instance or not mapping:
                return jsonify(ok=False, error="staging mapping not found or outside your scope"), 404
            if role is None:
                return jsonify(ok=False, error="software.wordpress disabled by hosting policy"), 403
            target = str(mapping["target_domain"])
        result = wordpress_call({"action": "staging-preview", "source_domain": source, "target_domain": target}, timeout=45)
        if not result.get("ok"):
            return _provider_error(result)
        return jsonify(result)

    @app.post("/api/wordpress/staging/publish")
    @role_required("admin", "operator")
    @step_up_required
    def wordpress_staging_publish():
        data = request.get_json(silent=True) or {}
        source = str(data.get("source_domain", "")).strip().lower().rstrip(".")
        with db() as conn:
            site, instance, role = _source_context(conn, source)
            mapping = _mapping_row(conn, source) if site and instance else None
            if not site or not instance or not mapping:
                return jsonify(ok=False, error="staging mapping not found or outside your scope"), 404
            if role is None:
                return jsonify(ok=False, error="software.wordpress disabled by hosting policy"), 403
            target = str(mapping["target_domain"])
        result = wordpress_call({"action": "staging-publish", "source_domain": source, "target_domain": target}, timeout=300)
        if not result.get("ok"):
            audit("wordpress-staging-publish", f"source={source} target={target} status=failed")
            return _provider_error(result)
        snapshot = str(result.get("snapshot_id", ""))[:32]
        if not SNAPSHOT_RE.fullmatch(snapshot):
            return jsonify(ok=False, error="publish completed without a valid rollback snapshot"), 502
        version = str(result.get("version", ""))[:40]
        now = int(time.time())
        with db() as conn:
            conn.execute("UPDATE wordpress_staging SET status='published',last_publish_snapshot=?,updated_at=? WHERE source_domain=?", (snapshot, now, source))
            conn.execute("UPDATE wordpress_instances SET status='active',version=?,updated_at=? WHERE domain=?", (version, now, source))
        audit("wordpress-staging-publish", f"source={source} target={target} snapshot={snapshot}")
        return jsonify(ok=True, source_domain=source, target_domain=target, snapshot_id=snapshot, version=version, safety="rollback-ready")

    @app.post("/api/wordpress/staging/publish-rollback")
    @role_required("admin", "operator")
    @step_up_required
    def wordpress_staging_publish_rollback():
        data = request.get_json(silent=True) or {}
        source = str(data.get("source_domain", "")).strip().lower().rstrip(".")
        snapshot = str(data.get("snapshot_id", "")).strip().lower()
        if not SNAPSHOT_RE.fullmatch(snapshot):
            return jsonify(ok=False, error="invalid WordPress publish snapshot"), 400
        with db() as conn:
            site, instance, role = _source_context(conn, source)
            mapping = _mapping_row(conn, source) if site and instance else None
            if not site or not instance or not mapping:
                return jsonify(ok=False, error="staging mapping not found or outside your scope"), 404
            if role is None:
                return jsonify(ok=False, error="software.wordpress disabled by hosting policy"), 403
            if str(mapping["last_publish_snapshot"]) != snapshot:
                return jsonify(ok=False, error="only the latest tracked publish snapshot can be rolled back"), 409
        result = wordpress_call({"action": "staging-publish-rollback", "source_domain": source, "snapshot_id": snapshot}, timeout=240)
        if not result.get("ok"):
            audit("wordpress-staging-publish-rollback", f"source={source} snapshot={snapshot} status=failed")
            return _provider_error(result)
        version = str(result.get("version", ""))[:40]
        now = int(time.time())
        with db() as conn:
            conn.execute("UPDATE wordpress_staging SET status='rolled-back',updated_at=? WHERE source_domain=?", (now, source))
            conn.execute("UPDATE wordpress_instances SET version=?,updated_at=? WHERE domain=?", (version, now, source))
        audit("wordpress-staging-publish-rollback", f"source={source} snapshot={snapshot}")
        return jsonify(ok=True, source_domain=source, snapshot_id=snapshot, version=version, rolled_back=True)
