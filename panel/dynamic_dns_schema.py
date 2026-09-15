from __future__ import annotations

from .db_layer import db


def ensure_dynamic_dns_schema() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS dynamic_dns_records (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              domain TEXT NOT NULL,
              hostname TEXT NOT NULL,
              record_type TEXT NOT NULL,
              target_id INTEGER NOT NULL,
              provider_record_id TEXT NOT NULL DEFAULT '',
              token_hash TEXT UNIQUE NOT NULL,
              ttl INTEGER NOT NULL DEFAULT 300,
              last_address TEXT NOT NULL DEFAULT '',
              last_update INTEGER NOT NULL DEFAULT 0,
              enabled INTEGER NOT NULL DEFAULT 1,
              owner TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              UNIQUE(domain,hostname,record_type),
              FOREIGN KEY(domain) REFERENCES sites(domain) ON DELETE CASCADE,
              FOREIGN KEY(target_id) REFERENCES integration_targets(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_dynamic_dns_owner
              ON dynamic_dns_records(owner,domain,enabled);
            CREATE INDEX IF NOT EXISTS idx_dynamic_dns_due
              ON dynamic_dns_records(enabled,last_update);
            """
        )
