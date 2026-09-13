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

        # Adopt databases created by the legacy one-database/one-user workflow.
        rows = conn.execute(
            "SELECT db_name,db_user,owner,created_at FROM databases WHERE engine='mariadb'"
        ).fetchall()
        privilege_text = ",".join(FULL_PRIVILEGES)
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
