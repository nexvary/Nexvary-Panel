from __future__ import annotations

from .db_layer import db


def ensure_wordpress_update_guard_schema() -> None:
    with db() as conn:
        conn.executescript("""
          CREATE TABLE IF NOT EXISTS wordpress_update_guard (
            id INTEGER PRIMARY KEY,
            source_domain TEXT NOT NULL,
            staging_domain TEXT NOT NULL,
            kind TEXT NOT NULL,
            slug TEXT NOT NULL,
            installed_version TEXT NOT NULL DEFAULT '',
            target_version TEXT NOT NULL DEFAULT '',
            staging_snapshot TEXT NOT NULL DEFAULT '',
            production_snapshot TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'preview',
            detail TEXT NOT NULL DEFAULT '',
            owner TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            verified_at INTEGER NOT NULL DEFAULT 0,
            published_at INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(source_domain) REFERENCES wordpress_instances(domain) ON DELETE CASCADE,
            FOREIGN KEY(staging_domain) REFERENCES wordpress_instances(domain) ON DELETE CASCADE
          );
          CREATE INDEX IF NOT EXISTS idx_wp_update_guard_source ON wordpress_update_guard(owner,source_domain,id DESC);
          CREATE INDEX IF NOT EXISTS idx_wp_update_guard_status ON wordpress_update_guard(status,updated_at);
        """)
