from __future__ import annotations

from .db_layer import db


def ensure_database_lifecycle_schema() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS database_snapshots (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              engine TEXT NOT NULL,
              db_name TEXT NOT NULL,
              archive TEXT NOT NULL,
              size_bytes INTEGER NOT NULL DEFAULT 0,
              sha256 TEXT NOT NULL DEFAULT '',
              owner TEXT NOT NULL,
              kind TEXT NOT NULL DEFAULT 'manual',
              created_at INTEGER NOT NULL,
              restored_at INTEGER NOT NULL DEFAULT 0,
              UNIQUE(engine,archive)
            );
            CREATE INDEX IF NOT EXISTS idx_database_snapshots_owner
              ON database_snapshots(owner,engine,created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_database_snapshots_database
              ON database_snapshots(engine,db_name,created_at DESC);
            """
        )
