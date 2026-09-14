from __future__ import annotations

import sqlite3
import time

from flask import jsonify, request, session

from .core import audit, db
from .database_client import database_call
from .hosting_policy import feature_allowed, package_limit
from .postgres_client import postgres_call
from .security import role_required, step_up_required

ENGINES = {"mariadb", "postgresql"}


def _actor() -> tuple[str, str]:
    return str(session.get("user", ""))[:64], str(session.get("role", "viewer"))


def _target_role(owner: str) -> str:
    return "admin" if owner == "admin" else "operator"


def _can_manage(owner: str) -> bool:
    actor, role = _actor()
    return role == "admin" or actor == owner


def _feature(engine: str, owner: str, *, connection=None) -> bool:
    feature_id = "databases.mariadb" if engine == "mariadb" else "databases.postgresql"
    role = _target_role(owner)
    return feature_allowed(feature_id, username=owner, role=role, connection=connection) and feature_allowed(
        "files.backups", username=owner, role=role, connection=connection
    )


def _database_row(conn, engine: str, db_name: str):
    if engine == "mariadb":
        return conn.execute(
            "SELECT db_name,db_user,owner,site_domain FROM databases WHERE engine='mariadb' AND db_name=?",
            (db_name,),
        ).fetchone()
    return conn.execute(
        "SELECT db_name,db_user,owner,site_domain FROM postgres_resources WHERE db_name=?",
        (db_name,),
    ).fetchone()


def _provider_call(engine: str, payload: dict, timeout: int = 180) -> dict:
    if engine == "mariadb":
        return database_call(payload, timeout=timeout)
    return postgres_call(payload, timeout=timeout)


def _visible_databases(conn, actor: str, role: str) -> list[dict]:
    if role == "admin":
        maria = conn.execute(
            "SELECT db_name,db_user,owner,site_domain FROM databases WHERE engine='mariadb' ORDER BY owner,db_name"
        ).fetchall()
        postgres = conn.execute(
            "SELECT db_name,db_user,owner,site_domain FROM postgres_resources ORDER BY owner,db_name"
        ).fetchall()
    else:
        maria = conn.execute(
            "SELECT db_name,db_user,owner,site_domain FROM databases WHERE engine='mariadb' AND owner=? ORDER BY db_name",
            (actor,),
        ).fetchall()
        postgres = conn.execute(
            "SELECT db_name,db_user,owner,site_domain FROM postgres_resources WHERE owner=? ORDER BY db_name",
            (actor,),
        ).fetchall()
    return [dict(row) | {"engine": "mariadb"} for row in maria] + [
        dict(row) | {"engine": "postgresql"} for row in postgres
    ]


def register_database_lifecycle_routes(app):
    @app.get("/api/database-lifecycle")
    @role_required("admin", "operator", "viewer")
    def database_lifecycle_catalog():
        actor, role = _actor()
        with db() as conn:
            databases = _visible_databases(conn, actor, role)
            if role == "admin":
                rows = conn.execute(
                    """SELECT id,engine,db_name,archive,size_bytes,sha256,owner,kind,created_at,restored_at
                       FROM database_snapshots ORDER BY id DESC LIMIT 250"""
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT id,engine,db_name,archive,size_bytes,sha256,owner,kind,created_at,restored_at
                       FROM database_snapshots WHERE owner=? ORDER BY id DESC LIMIT 250""",
                    (actor,),
                ).fetchall()
            used = int(conn.execute("SELECT COUNT(*) FROM database_snapshots WHERE owner=?", (actor,)).fetchone()[0])
            limit = package_limit("max_backups", username=actor, role=role, connection=conn)
        return jsonify(
            ok=True,
            databases=databases,
            snapshots=[dict(row) for row in rows],
            quota={"used": used, "limit": limit, "remaining": max(0, limit - used)},
            policy={"server_managed_only": True, "arbitrary_paths": False, "restore_safety_snapshot": True},
        )

    @app.post("/api/database-lifecycle/snapshots")
    @role_required("admin", "operator")
    @step_up_required
    def database_snapshot_create():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        engine = str(data.get("engine", "")).strip().lower()
        db_name = str(data.get("db_name", "")).strip()
        if engine not in ENGINES or not db_name:
            return jsonify(ok=False, error="invalid database snapshot request"), 400
        with db() as conn:
            row = _database_row(conn, engine, db_name)
            if not row:
                return jsonify(ok=False, error="database not found"), 404
            owner = str(row["owner"])
            if not _can_manage(owner):
                return jsonify(ok=False, error="database outside your scope"), 403
            if not _feature(engine, owner, connection=conn):
                return jsonify(ok=False, error="database snapshot disabled by hosting policy"), 403
            used = int(conn.execute("SELECT COUNT(*) FROM database_snapshots WHERE owner=?", (owner,)).fetchone()[0])
            limit = package_limit("max_backups", username=owner, role=_target_role(owner), connection=conn)
            if limit <= 0 or used >= limit:
                return jsonify(ok=False, error="snapshot quota reached"), 409
        result = _provider_call(engine, {"action": "snapshot-create", "db_name": db_name}, timeout=240)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "database snapshot failed"))[:180]), 502
        archive = str(result.get("archive", ""))[:180]
        digest = str(result.get("sha256", ""))[:128]
        size = max(0, int(result.get("size_bytes", 0) or 0))
        now = int(time.time())
        try:
            with db() as conn:
                cur = conn.execute(
                    """INSERT INTO database_snapshots(engine,db_name,archive,size_bytes,sha256,owner,kind,created_at)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (engine, db_name, archive, size, digest, owner, "manual", now),
                )
                snapshot_id = int(cur.lastrowid)
        except sqlite3.IntegrityError:
            _provider_call(engine, {"action": "snapshot-delete", "archive": archive}, timeout=30)
            return jsonify(ok=False, error="snapshot metadata conflict"), 409
        audit("database-snapshot-create", f"engine={engine} db={db_name} owner={owner} id={snapshot_id} bytes={size}")
        return jsonify(ok=True, id=snapshot_id, engine=engine, db_name=db_name, archive=archive, size_bytes=size, sha256=digest), 201

    @app.post("/api/database-lifecycle/snapshots/<int:snapshot_id>/restore")
    @role_required("admin", "operator")
    @step_up_required
    def database_snapshot_restore(snapshot_id: int):
        with db() as conn:
            snap = conn.execute("SELECT * FROM database_snapshots WHERE id=?", (snapshot_id,)).fetchone()
            if not snap:
                return jsonify(ok=False, error="snapshot not found"), 404
            owner = str(snap["owner"])
            if not _can_manage(owner):
                return jsonify(ok=False, error="snapshot outside your scope"), 403
            engine = str(snap["engine"])
            db_name = str(snap["db_name"])
            current = _database_row(conn, engine, db_name)
            if not current or str(current["owner"]) != owner:
                return jsonify(ok=False, error="managed database ownership changed; restore blocked"), 409
            if not _feature(engine, owner, connection=conn):
                return jsonify(ok=False, error="database restore disabled by hosting policy"), 403
            archive = str(snap["archive"])
        result = _provider_call(
            engine,
            {"action": "snapshot-restore", "db_name": db_name, "archive": archive},
            timeout=360,
        )
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "database restore failed"))[:180]), 502
        rollback_archive = str(result.get("rollback_archive", ""))[:180]
        rollback_size = max(0, int(result.get("rollback_size_bytes", 0) or 0))
        rollback_sha = str(result.get("rollback_sha256", ""))[:128]
        now = int(time.time())
        rollback_id = None
        with db() as conn:
            conn.execute("UPDATE database_snapshots SET restored_at=? WHERE id=?", (now, snapshot_id))
            if rollback_archive:
                cur = conn.execute(
                    """INSERT OR IGNORE INTO database_snapshots(engine,db_name,archive,size_bytes,sha256,owner,kind,created_at)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (engine, db_name, rollback_archive, rollback_size, rollback_sha, owner, "pre-restore", now),
                )
                rollback_id = int(cur.lastrowid) if cur.lastrowid else None
        audit("database-snapshot-restore", f"engine={engine} db={db_name} owner={owner} snapshot={snapshot_id} rollback={rollback_id or 0}")
        return jsonify(ok=True, id=snapshot_id, restored=True, rollback_snapshot_id=rollback_id)

    @app.delete("/api/database-lifecycle/snapshots/<int:snapshot_id>")
    @role_required("admin", "operator")
    @step_up_required
    def database_snapshot_delete(snapshot_id: int):
        with db() as conn:
            snap = conn.execute("SELECT * FROM database_snapshots WHERE id=?", (snapshot_id,)).fetchone()
        if not snap or not _can_manage(str(snap["owner"])):
            return jsonify(ok=False, error="snapshot not found"), 404
        engine = str(snap["engine"])
        result = _provider_call(engine, {"action": "snapshot-delete", "archive": str(snap["archive"])}, timeout=30)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "snapshot delete failed"))[:180]), 502
        with db() as conn:
            conn.execute("DELETE FROM database_snapshots WHERE id=?", (snapshot_id,))
        audit("database-snapshot-delete", f"engine={engine} db={snap['db_name']} owner={snap['owner']} id={snapshot_id}")
        return jsonify(ok=True, id=snapshot_id)
