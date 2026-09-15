from __future__ import annotations

from .db_layer import db


def ensure_mail_automation_schema() -> None:
    with db() as conn:
        conn.executescript("""
          CREATE TABLE IF NOT EXISTS mail_autoresponders (
            mailbox_id INTEGER PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 0,
            subject TEXT NOT NULL DEFAULT '',
            body TEXT NOT NULL DEFAULT '',
            interval_days INTEGER NOT NULL DEFAULT 1,
            owner TEXT NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
          );

          CREATE TABLE IF NOT EXISTS mail_filters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mailbox_id INTEGER NOT NULL,
            priority INTEGER NOT NULL DEFAULT 100,
            field TEXT NOT NULL,
            match_type TEXT NOT NULL,
            pattern TEXT NOT NULL,
            action TEXT NOT NULL,
            destination TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            owner TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
          );
          CREATE INDEX IF NOT EXISTS idx_mail_filters_mailbox ON mail_filters(mailbox_id,enabled,priority,id);

          CREATE TABLE IF NOT EXISTS mail_spam_policies (
            mailbox_id INTEGER PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 0,
            action TEXT NOT NULL DEFAULT 'junk',
            owner TEXT NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
          );
        """)
