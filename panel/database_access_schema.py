from __future__ import annotations

import time

from .db_layer import db

FULL_PRIVILEGES = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "CREATE",
    "DROP",
    "INDEX",
    "ALTER",
    "REFERENCES",
    "CREATE TEMPORARY TABLES",
    "LOCK TABLES",
    "EXECUTE",
    "CREATE VIEW",
    "SHOW VIEW",
    "TRIGGER",
)
POSTGRES_PROFILES = ("readonly", "readwrite", "developer")


def ensure_postgres_access_bridge(conn, now: int | None = None) -> None:
    """Adopt PostgreSQL resources and keep future create/delete flows synchronized."""
    table = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='postgres_resources'").fetchone()
    if not table:
        return
    now = int(now or time.time())
    conn.executescript(
        """
        CREATE TRIGGER IF NOT EXISTS trg_nvp_postgres_access_insert
        AFTER INSERT ON postgres_resources
        BEGIN
          INSERT OR IGNORE INTO postgres_access_roles(username,owner,managed_owner_role,created_at,updated_at)
          VALUES(NEW.db_user,NEW.owner,1,NEW.created_at,CAST(strftime('%s','now') AS INTEGER));
        END;

        CREATE TRIGGER IF NOT EXISTS trg_nvp_postgres_access_delete
        AFTER DELETE ON postgres_resources
        BEGIN
          DELETE FROM postgres_access_grants WHERE db_name=OLD.db_name;
          DELETE FROM postgres_access_roles
           WHERE username=OLD.db_user AND managed_owner_role=1
             AND NOT EXISTS(SELECT 1 FROM postgres_resources WHERE db_user=OLD.db_user);
        END;
        """
    )
    for row in conn.execute("SELECT db_user,owner,created_at FROM postgres_resources").fetchall():
        username = str(row["db_user"] or "").strip()
        owner = str(row["owner"] or "admin")[:64]
        created = int(row["created_at"] or now)
        if username:
            conn.execute(
                """INSERT OR IGNORE INTO postgres_access_roles
                   (username,owner,managed_owner_role,created_at,updated_at) VALUES(?,?,1,?,?)""",
                (username, owner, created, now),
            )


def ensure_database_access_schema() -> None:
    now = int(time.time())
    privilege_text = ",".join(FULL_PRIVILEGES)
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS database_access_users (
              username TEXT PRIMARY KEY,
              engine TEXT NOT NULL DEFAULT 'mariadb',
              owner TEXT NOT NULL DEFAULT 'admin',
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_database_access_users_owner
              ON database_access_users(owner,engine);

            CREATE TABLE IF NOT EXISTS database_access_grants (
              id INTEGER PRIMARY KEY,
              db_name TEXT NOT NULL,
              db_user TEXT NOT NULL,
              privileges TEXT NOT NULL,
              owner TEXT NOT NULL DEFAULT 'admin',
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              UNIQUE(db_name,db_user)
            );
            CREATE INDEX IF NOT EXISTS idx_database_access_grants_owner
              ON database_access_grants(owner,db_name,db_user);

            CREATE TABLE IF NOT EXISTS postgres_access_roles (
              username TEXT PRIMARY KEY,
              owner TEXT NOT NULL DEFAULT 'admin',
              managed_owner_role INTEGER NOT NULL DEFAULT 0,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_postgres_access_roles_owner
              ON postgres_access_roles(owner,managed_owner_role,username);

            CREATE TABLE IF NOT EXISTS postgres_access_grants (
              id INTEGER PRIMARY KEY,
              db_name TEXT NOT NULL,
              db_user TEXT NOT NULL,
              profile TEXT NOT NULL,
              owner TEXT NOT NULL DEFAULT 'admin',
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              UNIQUE(db_name,db_user)
            );
            CREATE INDEX IF NOT EXISTS idx_postgres_access_grants_owner
              ON postgres_access_grants(owner,db_name,db_user);
            """
        )

        # Any MariaDB database provisioned through the legacy create workflow is adopted immediately.
        conn.executescript(
            f"""
            CREATE TRIGGER IF NOT EXISTS trg_nvp_database_access_insert
            AFTER INSERT ON databases
            WHEN NEW.engine='mariadb'
            BEGIN
              INSERT OR IGNORE INTO database_access_users(username,engine,owner,created_at,updated_at)
              VALUES(NEW.db_user,'mariadb',NEW.owner,NEW.created_at,CAST(strftime('%s','now') AS INTEGER));
              INSERT OR IGNORE INTO database_access_grants(db_name,db_user,privileges,owner,created_at,updated_at)
              VALUES(NEW.db_name,NEW.db_user,'{privilege_text}',NEW.owner,NEW.created_at,CAST(strftime('%s','now') AS INTEGER));
            END;

            CREATE TRIGGER IF NOT EXISTS trg_nvp_database_access_delete
            AFTER DELETE ON databases
            WHEN OLD.engine='mariadb'
            BEGIN
              DELETE FROM database_access_grants WHERE db_name=OLD.db_name;
              DELETE FROM database_access_users
               WHERE username=OLD.db_user
                 AND NOT EXISTS(SELECT 1 FROM database_access_grants WHERE db_user=OLD.db_user)
                 AND NOT EXISTS(SELECT 1 FROM databases WHERE db_user=OLD.db_user AND engine='mariadb');
            END;
            """
        )

        rows = conn.execute(
            "SELECT db_name,db_user,owner,created_at FROM databases WHERE engine='mariadb'"
        ).fetchall()
        for row in rows:
            username = str(row["db_user"] or "").strip()
            db_name = str(row["db_name"] or "").strip()
            owner = str(row["owner"] or "admin")[:64]
            created = int(row["created_at"] or now)
            if not username or not db_name:
                continue
            conn.execute(
                """INSERT OR IGNORE INTO database_access_users
                   (username,engine,owner,created_at,updated_at) VALUES(?,?,?,?,?)""",
                (username, "mariadb", owner, created, now),
            )
            conn.execute(
                """INSERT OR IGNORE INTO database_access_grants
                   (db_name,db_user,privileges,owner,created_at,updated_at) VALUES(?,?,?,?,?,?)""",
                (db_name, username, privilege_text, owner, created, now),
            )

        ensure_postgres_access_bridge(conn, now)
