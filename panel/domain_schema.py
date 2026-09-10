from __future__ import annotations

from .db_layer import db


def ensure_domain_schema() -> None:
    with db() as conn:
        conn.executescript("""
          CREATE TABLE IF NOT EXISTS domain_aliases (
            id INTEGER PRIMARY KEY,
            domain TEXT NOT NULL,
            alias TEXT UNIQUE NOT NULL,
            owner TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(domain) REFERENCES sites(domain) ON DELETE CASCADE
          );
          CREATE INDEX IF NOT EXISTS idx_domain_aliases_owner ON domain_aliases(owner,domain);
        """)
