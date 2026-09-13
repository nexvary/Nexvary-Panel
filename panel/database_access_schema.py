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
            """
        )

        # Any database provisioned through the legacy create workflow is adopted immediately.
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

        # Adopt databases that pre-date the access-manager schema.
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
