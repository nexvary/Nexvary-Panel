from __future__ import annotations

from .db_layer import db


def ensure_mail_schema() -> None:
    with db() as conn:
        conn.executescript("""
          CREATE TABLE IF NOT EXISTS mail_domains (
            domain TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
          );
          CREATE TABLE IF NOT EXISTS mailboxes (
            id INTEGER PRIMARY KEY,
            domain TEXT NOT NULL,
            localpart TEXT NOT NULL,
            quota_mb INTEGER NOT NULL DEFAULT 1024,
            enabled INTEGER NOT NULL DEFAULT 1,
            owner TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(domain,localpart)
          );
          CREATE INDEX IF NOT EXISTS idx_mailboxes_owner_domain ON mailboxes(owner,domain,enabled);
          CREATE TABLE IF NOT EXISTS mail_forwarders (
            id INTEGER PRIMARY KEY,
            domain TEXT NOT NULL,
            localpart TEXT NOT NULL,
            destination TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            owner TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(domain,localpart)
          );
          CREATE INDEX IF NOT EXISTS idx_mail_forwarders_owner_domain ON mail_forwarders(owner,domain,enabled);
        """)
