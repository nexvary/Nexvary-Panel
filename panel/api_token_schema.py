from __future__ import annotations

from .db_layer import db


def ensure_api_token_schema() -> None:
    with db() as conn:
        conn.executescript("""
          CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            scopes_json TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_used_at INTEGER,
            revoked_at INTEGER
          );
          CREATE INDEX IF NOT EXISTS idx_api_tokens_active ON api_tokens(revoked_at,created_by);
        """)
