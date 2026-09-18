from __future__ import annotations

from .db_layer import db


def ensure_mail_list_schema() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS mail_distribution_lists (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              domain TEXT NOT NULL,
              localpart TEXT NOT NULL,
              owner TEXT NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              UNIQUE(domain,localpart)
            );
            CREATE INDEX IF NOT EXISTS idx_mail_distribution_owner
              ON mail_distribution_lists(owner,domain,localpart);

            CREATE TABLE IF NOT EXISTS mail_distribution_members (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              list_id INTEGER NOT NULL,
              address TEXT NOT NULL,
              position INTEGER NOT NULL DEFAULT 0,
              created_at INTEGER NOT NULL,
              UNIQUE(list_id,address),
              FOREIGN KEY(list_id) REFERENCES mail_distribution_lists(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_mail_distribution_members_list
              ON mail_distribution_members(list_id,position,id);
            """
        )
