from __future__ import annotations

from .db_layer import db


def ensure_site_controls_schema() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS site_web_controls (
              domain TEXT PRIMARY KEY,
              owner TEXT NOT NULL,
              privacy_enabled INTEGER NOT NULL DEFAULT 0 CHECK(privacy_enabled IN (0,1)),
              privacy_path TEXT NOT NULL DEFAULT '/',
              privacy_username TEXT,
              hotlink_enabled INTEGER NOT NULL DEFAULT 0 CHECK(hotlink_enabled IN (0,1)),
              hotlink_extensions TEXT NOT NULL DEFAULT 'jpg,jpeg,png,gif,webp,svg',
              indexing_mode TEXT NOT NULL DEFAULT 'off' CHECK(indexing_mode IN ('off','on')),
              mime_overrides TEXT NOT NULL DEFAULT '{}',
              updated_at INTEGER NOT NULL,
              FOREIGN KEY(domain) REFERENCES sites(domain) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_site_web_controls_owner ON site_web_controls(owner,domain);
            """
        )
