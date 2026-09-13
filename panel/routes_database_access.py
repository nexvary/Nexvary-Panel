from __future__ import annotations

import sqlite3
import time

from flask import jsonify, request, session

from .config import DB_RE, PASSWORD_RE, USER_RE
from .core import audit, db
from .database_access_schema import FULL_PRIVILEGES, POSTGRES_PROFILES
from .database_client import database_call
from .hosting_policy import feature_allowed, package_limit
from .postgres_client import postgres_call
from .security import role_required, step_up_required


def _actor() -> tuple[str, str]:
    return str(session.get("user", ""))[:64], str(session.get("role", "viewer"))


def _target_role(owner: str) -> str:
    return "admin" if owner == "admin" else "operator"


def _policy(owner: str) -> bool:
    return feature_allowed("databases.mariadb", username=owner, role=_target_role(owner))


def _postgres_policy(owner: str) -> bool:
    return feature_allowed("databases.postgresql", username=owner, role=_target_role(owner))


def _can_manage(owner: str) -> bool:
    actor, role = _actor()
    return role == "admin" or owner == actor


def _resolve_owner(data: dict) -> str | None:
    actor, role = _actor()
    requested = str(data.get("owner", actor)).strip()[:64]
    if role != "admin":
        return actor
    if requested == "admin":
        return "admin"
    if not USER_RE.fullmatch(requested):
        return None
    with db() as conn:
        row = conn.execute("SELECT username FROM users WHERE username=?", (requested,)).fetchone()
    return requested if row else None


def _split_privileges(value: str) -> list[str]:
    return [item for item in (part.strip().upper() for part in value.split(",")) if item in FULL_PRIVILEGES]


def _catalog(conn, owner_filter: str | None) -> tuple[list[dict], list[dict], list[dict]]:
    if owner_filter is None:
        databases = [dict(row) for row in conn.execute(
            "SELECT db_name,db_user,engine,site_domain,owner,created_at FROM databases WHERE engine='mariadb' ORDER BY owner,db_name"
        ).fetchall()]
        users = [dict(row) for row in conn.execute(
            "SELECT username,engine,owner,created_at,updated_at FROM database_access_users WHERE engine='mariadb' ORDER BY owner,username"
        ).fetchall()]
        grant_rows = conn.execute(
            "SELECT id,db_name,db_user,privileges,owner,created_at,updated_at FROM database_access_grants ORDER BY owner,db_name,db_user"
        ).fetchall()
    else:
        databases = [dict(row) for row in conn.execute(
            "SELECT db_name,db_user,engine,site_domain,owner,created_at FROM databases WHERE engine='mariadb' AND owner=? ORDER BY db_name",
            (owner_filter,),
        ).fetchall()]
        users = [dict(row) for row in conn.execute(
            "SELECT username,engine,owner,created_at,updated_at FROM database_access_users WHERE engine='mariadb' AND owner=? ORDER BY username",
            (owner_filter,),
        ).fetchall()]
        grant_rows = conn.execute(
            "SELECT id,db_name,db_user,privileges,owner,created_at,updated_at FROM database_access_grants WHERE owner=? ORDER BY db_name,db_user",
            (owner_filter,),
        ).fetchall()
    grants = []
    for row in grant_rows:
        item = dict(row)
        item["privileges"] = _split_privileges(str(row["privileges"]))
        grants.append(item)
    return databases, users, grants


def _postgres_catalog(conn, owner_filter: str | None) -> tuple[list[dict], list[dict], list[dict]]:
    if owner_filter is None:
        databases = [dict(row) for row in conn.execute(
            "SELECT id,db_name,db_user,site_domain,owner,created_at FROM postgres_resources ORDER BY owner,db_name"
        ).fetchall()]
        roles = [dict(row) for row in conn.execute(
            "SELECT username,owner,managed_owner_role,created_at,updated_at FROM postgres_access_roles ORDER BY owner,username"
        ).fetchall()]
        grants = [dict(row) for row in conn.execute(
            "SELECT id,db_name,db_user,profile,owner,created_at,updated_at FROM postgres_access_grants ORDER BY owner,db_name,db_user"
        ).fetchall()]
    else:
        databases = [dict(row) for row in conn.execute(
            "SELECT id,db_name,db_user,site_domain,owner,created_at FROM postgres_resources WHERE owner=? ORDER BY db_name", (owner_filter,)
        ).fetchall()]
        roles = [dict(row) for row in conn.execute(
            "SELECT username,owner,managed_owner_role,created_at,updated_at FROM postgres_access_roles WHERE owner=? ORDER BY username", (owner_filter,)
        ).fetchall()]
        grants = [dict(row) for row in conn.execute(
            "SELECT id,db_name,db_user,profile,owner,created_at,updated_at FROM postgres_access_grants WHERE owner=? ORDER BY db_name,db_user", (owner_filter,)
        ).fetchall()]
    for role in roles:
        role["managed_owner_role"] = bool(role["managed_owner_role"])
    return databases, roles, grants


def register_database_access_routes(app):
    @app.get("/api/database-access")
    @role_required("admin", "operator", "viewer")
    def database_access_catalog():
        actor, role = _actor()
        if not feature_allowed("databases.mariadb", username=actor, role=role):
            return jsonify(ok=False, error="databases.mariadb disabled by hosting policy"), 403
        with db() as conn:
            databases, users, grants = _catalog(conn, None if role == "admin" else actor)
        limit = max(0, package_limit("max_databases", username=actor, role=role) * 2)
        used = len(users) if role != "admin" else sum(1 for row in users if row["owner"] == actor)
        provider = database_call({"action": "status"}, timeout=6)
        return jsonify(
            ok=True,
            databases=databases,
            users=users,
            grants=grants,
            privilege_catalog=list(FULL_PRIVILEGES),
            quota={"used": used, "limit": limit, "remaining": max(0, limit - used)},
            provider={"online": bool(provider.get("ok")), "engine": "mariadb", "version": str(provider.get("version", ""))[:80]},
        )

    @app.post("/api/database-access/users")
    @role_required("admin", "operator")
    @step_up_required
    def database_access_user_create():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        owner = _resolve_owner(data)
        if not DB_RE.fullmatch(username) or not PASSWORD_RE.fullmatch(password) or owner is None:
            return jsonify(ok=False, error="invalid database user request"), 400
        if not _policy(owner):
            return jsonify(ok=False, error="databases.mariadb disabled by hosting policy"), 403
        limit = max(0, package_limit("max_databases", username=owner, role=_target_role(owner)) * 2)
        with db() as conn:
            used = int(conn.execute("SELECT COUNT(*) FROM database_access_users WHERE owner=? AND engine='mariadb'", (owner,)).fetchone()[0])
            if limit <= 0 or used >= limit:
                return jsonify(ok=False, error="database user quota reached"), 409
            if conn.execute("SELECT 1 FROM database_access_users WHERE username=?", (username,)).fetchone():
                return jsonify(ok=False, error="database user already registered"), 409
        result = database_call({"action": "user-create", "data": {"username": username, "password": password}}, timeout=25)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "database user create failed"))[:180]), 502
        now = int(time.time())
        try:
            with db() as conn:
                conn.execute(
                    "INSERT INTO database_access_users(username,engine,owner,created_at,updated_at) VALUES(?,?,?,?,?)",
                    (username, "mariadb", owner, now, now),
                )
        except sqlite3.IntegrityError:
            return jsonify(ok=False, error="database user already registered"), 409
        audit("database-user-create", f"user={username} owner={owner} engine=mariadb")
        return jsonify(ok=True, username=username, owner=owner), 201

    @app.put("/api/database-access/users/<username>/password")
    @role_required("admin", "operator")
    @step_up_required
    def database_access_password_rotate(username: str):
        username = username.strip()
        data = request.get_json(silent=True) or {}
        password = str(data.get("password", "")) if isinstance(data, dict) else ""
        if not DB_RE.fullmatch(username) or not PASSWORD_RE.fullmatch(password):
            return jsonify(ok=False, error="invalid database password request"), 400
        with db() as conn:
            row = conn.execute("SELECT owner FROM database_access_users WHERE username=? AND engine='mariadb'", (username,)).fetchone()
        if not row or not _can_manage(str(row["owner"])):
            return jsonify(ok=False, error="database user not found"), 404
        result = database_call({"action": "user-rotate", "data": {"username": username, "password": password}}, timeout=25)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "database password rotation failed"))[:180]), 502
        with db() as conn:
            conn.execute("UPDATE database_access_users SET updated_at=? WHERE username=?", (int(time.time()), username))
        audit("database-user-password-rotate", f"user={username} owner={row['owner']}")
        return jsonify(ok=True, username=username)

    @app.put("/api/database-access/grants")
    @role_required("admin", "operator")
    @step_up_required
    def database_access_grant_replace():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        db_name = str(data.get("db_name", "")).strip()
        username = str(data.get("username", "")).strip()
        raw_privileges = data.get("privileges")
        if not DB_RE.fullmatch(db_name) or not DB_RE.fullmatch(username) or not isinstance(raw_privileges, list):
            return jsonify(ok=False, error="invalid database grant request"), 400
        privileges: list[str] = []
        for value in raw_privileges:
            name = str(value).strip().upper()
            if name not in FULL_PRIVILEGES:
                return jsonify(ok=False, error="unsupported database privilege"), 400
            if name not in privileges:
                privileges.append(name)
        with db() as conn:
            database_row = conn.execute("SELECT owner FROM databases WHERE db_name=? AND engine='mariadb'", (db_name,)).fetchone()
            user_row = conn.execute("SELECT owner FROM database_access_users WHERE username=? AND engine='mariadb'", (username,)).fetchone()
            current = conn.execute("SELECT privileges FROM database_access_grants WHERE db_name=? AND db_user=?", (db_name, username)).fetchone()
        if not database_row or not user_row:
            return jsonify(ok=False, error="database or database user not found"), 404
        owner = str(database_row["owner"])
        if owner != str(user_row["owner"]):
            return jsonify(ok=False, error="cross-owner database grants are blocked"), 409
        if not _can_manage(owner):
            return jsonify(ok=False, error="database outside your scope"), 403
        if not _policy(owner):
            return jsonify(ok=False, error="databases.mariadb disabled by hosting policy"), 403
        previous = _split_privileges(str(current["privileges"])) if current else []
        result = database_call(
            {"action": "grant-replace", "data": {"db_name": db_name, "username": username, "privileges": privileges, "previous_privileges": previous}},
            timeout=30,
        )
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "database grant update failed"))[:180]), 502
        now = int(time.time())
        with db() as conn:
            if privileges:
                conn.execute(
                    """INSERT INTO database_access_grants(db_name,db_user,privileges,owner,created_at,updated_at)
                       VALUES(?,?,?,?,?,?) ON CONFLICT(db_name,db_user) DO UPDATE SET
                       privileges=excluded.privileges,owner=excluded.owner,updated_at=excluded.updated_at""",
                    (db_name, username, ",".join(privileges), owner, now, now),
                )
            else:
                conn.execute("DELETE FROM database_access_grants WHERE db_name=? AND db_user=?", (db_name, username))
        audit("database-grant-replace", f"db={db_name} user={username} owner={owner} privileges={','.join(privileges) or 'none'}")
        return jsonify(ok=True, db_name=db_name, username=username, privileges=privileges)

    @app.delete("/api/database-access/users/<username>")
    @role_required("admin", "operator")
    @step_up_required
    def database_access_user_delete(username: str):
        username = username.strip()
        if not DB_RE.fullmatch(username):
            return jsonify(ok=False, error="invalid database user"), 400
        with db() as conn:
            row = conn.execute("SELECT owner FROM database_access_users WHERE username=? AND engine='mariadb'", (username,)).fetchone()
            grants = int(conn.execute("SELECT COUNT(*) FROM database_access_grants WHERE db_user=?", (username,)).fetchone()[0])
        if not row or not _can_manage(str(row["owner"])):
            return jsonify(ok=False, error="database user not found"), 404
        if grants:
            return jsonify(ok=False, error="revoke database grants before deleting this user"), 409
        result = database_call({"action": "user-drop", "data": {"username": username}}, timeout=25)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "database user delete failed"))[:180]), 502
        with db() as conn:
            conn.execute("DELETE FROM database_access_users WHERE username=?", (username,))
        audit("database-user-delete", f"user={username} owner={row['owner']}")
        return jsonify(ok=True, username=username)

    @app.get("/api/database-access/postgresql")
    @role_required("admin", "operator", "viewer")
    def postgres_access_catalog():
        actor, role = _actor()
        if not feature_allowed("databases.postgresql", username=actor, role=role):
            return jsonify(ok=False, error="databases.postgresql disabled by hosting policy"), 403
        with db() as conn:
            databases, roles, grants = _postgres_catalog(conn, None if role == "admin" else actor)
        limit = max(0, package_limit("max_databases", username=actor, role=role) * 2)
        used = len(roles) if role != "admin" else sum(1 for row in roles if row["owner"] == actor and not row["managed_owner_role"])
        provider = postgres_call({"action": "status"}, timeout=6)
        return jsonify(
            ok=True,
            databases=databases,
            roles=roles,
            grants=grants,
            profiles=list(POSTGRES_PROFILES),
            quota={"used": used, "limit": limit, "remaining": max(0, limit - used)},
            provider={"online": bool(provider.get("ok") and provider.get("available")), "engine": "postgresql"},
        )

    @app.post("/api/database-access/postgresql/roles")
    @role_required("admin", "operator")
    @step_up_required
    def postgres_access_role_create():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        owner = _resolve_owner(data)
        if not DB_RE.fullmatch(username) or not PASSWORD_RE.fullmatch(password) or owner is None:
            return jsonify(ok=False, error="invalid PostgreSQL role request"), 400
        if not _postgres_policy(owner):
            return jsonify(ok=False, error="databases.postgresql disabled by hosting policy"), 403
        limit = max(0, package_limit("max_databases", username=owner, role=_target_role(owner)) * 2)
        with db() as conn:
            used = int(conn.execute("SELECT COUNT(*) FROM postgres_access_roles WHERE owner=? AND managed_owner_role=0", (owner,)).fetchone()[0])
            if limit <= 0 or used >= limit:
                return jsonify(ok=False, error="PostgreSQL role quota reached"), 409
            if conn.execute("SELECT 1 FROM postgres_access_roles WHERE username=?", (username,)).fetchone():
                return jsonify(ok=False, error="PostgreSQL role already registered"), 409
        result = postgres_call({"action": "role-create", "username": username, "password": password}, timeout=30)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "PostgreSQL role create failed"))[:180]), 502
        now = int(time.time())
        try:
            with db() as conn:
                conn.execute("INSERT INTO postgres_access_roles(username,owner,managed_owner_role,created_at,updated_at) VALUES(?,?,0,?,?)", (username, owner, now, now))
        except sqlite3.IntegrityError:
            return jsonify(ok=False, error="PostgreSQL role already registered"), 409
        audit("postgres-role-create", f"user={username} owner={owner}")
        return jsonify(ok=True, username=username, owner=owner), 201

    @app.put("/api/database-access/postgresql/roles/<username>/password")
    @role_required("admin", "operator")
    @step_up_required
    def postgres_access_role_rotate(username: str):
        username = username.strip()
        data = request.get_json(silent=True) or {}
        password = str(data.get("password", "")) if isinstance(data, dict) else ""
        if not DB_RE.fullmatch(username) or not PASSWORD_RE.fullmatch(password):
            return jsonify(ok=False, error="invalid PostgreSQL password request"), 400
        with db() as conn:
            row = conn.execute("SELECT owner FROM postgres_access_roles WHERE username=?", (username,)).fetchone()
        if not row or not _can_manage(str(row["owner"])):
            return jsonify(ok=False, error="PostgreSQL role not found"), 404
        result = postgres_call({"action": "role-rotate", "username": username, "password": password}, timeout=30)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "PostgreSQL password rotation failed"))[:180]), 502
        with db() as conn:
            conn.execute("UPDATE postgres_access_roles SET updated_at=? WHERE username=?", (int(time.time()), username))
        audit("postgres-role-password-rotate", f"user={username} owner={row['owner']}")
        return jsonify(ok=True, username=username)

    @app.put("/api/database-access/postgresql/grants")
    @role_required("admin", "operator")
    @step_up_required
    def postgres_access_grant_profile():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        db_name = str(data.get("db_name", "")).strip()
        username = str(data.get("username", "")).strip()
        profile = str(data.get("profile", "")).strip().lower()
        allowed_profiles = set(POSTGRES_PROFILES) | {"none"}
        if not DB_RE.fullmatch(db_name) or not DB_RE.fullmatch(username) or profile not in allowed_profiles:
            return jsonify(ok=False, error="invalid PostgreSQL grant profile"), 400
        with db() as conn:
            database_row = conn.execute("SELECT db_user,owner FROM postgres_resources WHERE db_name=?", (db_name,)).fetchone()
            role_row = conn.execute("SELECT owner,managed_owner_role FROM postgres_access_roles WHERE username=?", (username,)).fetchone()
        if not database_row or not role_row:
            return jsonify(ok=False, error="PostgreSQL database or role not found"), 404
        owner = str(database_row["owner"])
        if owner != str(role_row["owner"]):
            return jsonify(ok=False, error="cross-owner PostgreSQL grants are blocked"), 409
        if username == str(database_row["db_user"]) or bool(role_row["managed_owner_role"]):
            return jsonify(ok=False, error="database owner role privileges are managed by ownership"), 409
        if not _can_manage(owner):
            return jsonify(ok=False, error="PostgreSQL database outside your scope"), 403
        if not _postgres_policy(owner):
            return jsonify(ok=False, error="databases.postgresql disabled by hosting policy"), 403
        result = postgres_call({"action": "grant-profile", "db_name": db_name, "username": username, "profile": profile}, timeout=55)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "PostgreSQL grant update failed"))[:180]), 502
        now = int(time.time())
        with db() as conn:
            if profile == "none":
                conn.execute("DELETE FROM postgres_access_grants WHERE db_name=? AND db_user=?", (db_name, username))
            else:
                conn.execute(
                    """INSERT INTO postgres_access_grants(db_name,db_user,profile,owner,created_at,updated_at)
                       VALUES(?,?,?,?,?,?) ON CONFLICT(db_name,db_user) DO UPDATE SET
                       profile=excluded.profile,owner=excluded.owner,updated_at=excluded.updated_at""",
                    (db_name, username, profile, owner, now, now),
                )
        audit("postgres-grant-profile", f"db={db_name} user={username} owner={owner} profile={profile}")
        return jsonify(ok=True, db_name=db_name, username=username, profile=profile)

    @app.delete("/api/database-access/postgresql/roles/<username>")
    @role_required("admin", "operator")
    @step_up_required
    def postgres_access_role_delete(username: str):
        username = username.strip()
        if not DB_RE.fullmatch(username):
            return jsonify(ok=False, error="invalid PostgreSQL role"), 400
        with db() as conn:
            row = conn.execute("SELECT owner,managed_owner_role FROM postgres_access_roles WHERE username=?", (username,)).fetchone()
            grants = int(conn.execute("SELECT COUNT(*) FROM postgres_access_grants WHERE db_user=?", (username,)).fetchone()[0])
            owned = int(conn.execute("SELECT COUNT(*) FROM postgres_resources WHERE db_user=?", (username,)).fetchone()[0])
        if not row or not _can_manage(str(row["owner"])):
            return jsonify(ok=False, error="PostgreSQL role not found"), 404
        if bool(row["managed_owner_role"]) or owned:
            return jsonify(ok=False, error="database owner role cannot be deleted independently"), 409
        if grants:
            return jsonify(ok=False, error="revoke PostgreSQL grant profiles before deleting this role"), 409
        result = postgres_call({"action": "role-drop", "username": username}, timeout=35)
        if not result.get("ok"):
            return jsonify(ok=False, error=str(result.get("error", "PostgreSQL role delete failed"))[:180]), 502
        with db() as conn:
            conn.execute("DELETE FROM postgres_access_roles WHERE username=?", (username,))
        audit("postgres-role-delete", f"user={username} owner={row['owner']}")
        return jsonify(ok=True, username=username)
