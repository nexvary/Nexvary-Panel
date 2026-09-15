from __future__ import annotations

from .db_layer import db


def ensure_wordpress_publish_schema() -> None:
    with db() as conn:
        conn.executescript("""
          CREATE TABLE IF NOT EXISTS wordpress_publish_history (
            id INTEGER PRIMARY KEY,
            source_domain TEXT NOT NULL,
            target_domain TEXT NOT NULL,
            snapshot_id TEXT UNIQUE NOT NULL,
            scope TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'published',
            version TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            rolled_back_at INTEGER NOT NULL DEFAULT 0
          );
          CREATE INDEX IF NOT EXISTS idx_wordpress_publish_history_source
            ON wordpress_publish_history(source_domain,created_at DESC,id DESC);

          CREATE TRIGGER IF NOT EXISTS trg_wordpress_full_publish_history
          AFTER UPDATE OF last_publish_snapshot ON wordpress_staging
          WHEN NEW.last_publish_snapshot <> '' AND NEW.last_publish_snapshot <> OLD.last_publish_snapshot
          BEGIN
            INSERT OR IGNORE INTO wordpress_publish_history(
              source_domain,target_domain,snapshot_id,scope,status,version,detail,created_at,rolled_back_at
            ) VALUES(
              NEW.source_domain,
              NEW.target_domain,
              NEW.last_publish_snapshot,
              'full',
              'published',
              COALESCE((SELECT version FROM wordpress_instances WHERE domain=NEW.source_domain),''),
              'full-safe-publish',
              NEW.updated_at,
              0
            );
          END;

          CREATE TRIGGER IF NOT EXISTS trg_wordpress_full_publish_rollback_history
          AFTER UPDATE OF status ON wordpress_staging
          WHEN NEW.status='rolled-back' AND OLD.status<>NEW.status AND NEW.last_publish_snapshot<>''
          BEGIN
            UPDATE wordpress_publish_history
              SET status='rolled-back', rolled_back_at=NEW.updated_at
              WHERE snapshot_id=NEW.last_publish_snapshot AND source_domain=NEW.source_domain;
          END;
        """)
