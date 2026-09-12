from __future__ import annotations

from .db_layer import db


def ensure_transfer_schema() -> None:
    with db() as conn:
        conn.executescript("""
          CREATE TABLE IF NOT EXISTS transfer_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL,
            system_user TEXT UNIQUE NOT NULL,
            domain TEXT NOT NULL,
            owner TEXT NOT NULL,
            key_fingerprint TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(owner,label),
            FOREIGN KEY(domain) REFERENCES sites(domain) ON DELETE CASCADE
          );
          CREATE INDEX IF NOT EXISTS idx_transfer_accounts_owner ON transfer_accounts(owner,enabled);
          CREATE INDEX IF NOT EXISTS idx_transfer_accounts_domain ON transfer_accounts(domain,enabled);
        """)
