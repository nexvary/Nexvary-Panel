from __future__ import annotations

from .db_layer import db


def ensure_mail_default_schema() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS mail_default_addresses (
              domain TEXT PRIMARY KEY,
              mode TEXT NOT NULL DEFAULT 'reject',
              destination TEXT NOT NULL DEFAULT '',
              owner TEXT NOT NULL,
              updated_at INTEGER NOT NULL,
              CHECK(mode IN ('reject','forward'))
            );
            CREATE INDEX IF NOT EXISTS idx_mail_default_owner
              ON mail_default_addresses(owner,mode);
            """
        )
