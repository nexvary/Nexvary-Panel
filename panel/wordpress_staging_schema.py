from __future__ import annotations

from .db_layer import db


def ensure_wordpress_staging_schema() -> None:
    with db() as conn:
        conn.executescript("""
          CREATE TABLE IF NOT EXISTS wordpress_staging (
            id INTEGER PRIMARY KEY,
            source_domain TEXT UNIQUE NOT NULL,
            target_domain TEXT UNIQUE NOT NULL,
            source_db TEXT NOT NULL,
            target_db TEXT UNIQUE NOT NULL,
            db_user TEXT NOT NULL,
            owner TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ready',
            last_publish_snapshot TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(source_domain) REFERENCES wordpress_instances(domain) ON DELETE CASCADE,
            FOREIGN KEY(target_domain) REFERENCES sites(domain) ON DELETE CASCADE
          );
          CREATE INDEX IF NOT EXISTS idx_wordpress_staging_owner ON wordpress_staging(owner,source_domain,target_domain);
        """)
