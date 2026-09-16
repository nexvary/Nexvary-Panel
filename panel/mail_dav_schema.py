from __future__ import annotations

from .db_layer import db


def ensure_mail_dav_schema() -> None:
    with db() as conn:
        conn.executescript("""
          CREATE TABLE IF NOT EXISTS mail_dav_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mailbox_id INTEGER NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            owner TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
          );
          CREATE INDEX IF NOT EXISTS idx_mail_dav_owner
            ON mail_dav_accounts(owner,enabled,username);
        """)
