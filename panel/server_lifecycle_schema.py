from __future__ import annotations

from .db_layer import db


def ensure_server_lifecycle_schema() -> None:
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS server_maintenance_previews (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          kind TEXT NOT NULL,
          fingerprint TEXT NOT NULL DEFAULT '',
          snapshot_json TEXT NOT NULL DEFAULT '{}',
          status TEXT NOT NULL DEFAULT 'preview',
          requested_by TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          cancelled_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_server_maintenance_status
          ON server_maintenance_previews(status,created_at DESC);
        """)
