from __future__ import annotations

from .db_layer import db


def ensure_bulk_jobs_schema() -> None:
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS bulk_jobs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          operation TEXT NOT NULL,
          payload_json TEXT NOT NULL DEFAULT '{}',
          status TEXT NOT NULL DEFAULT 'queued',
          owner TEXT NOT NULL,
          total INTEGER NOT NULL DEFAULT 0,
          pending INTEGER NOT NULL DEFAULT 0,
          succeeded INTEGER NOT NULL DEFAULT 0,
          failed INTEGER NOT NULL DEFAULT 0,
          blocked INTEGER NOT NULL DEFAULT 0,
          cancelled INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          completed_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_bulk_jobs_owner_created ON bulk_jobs(owner,id DESC);
        CREATE INDEX IF NOT EXISTS idx_bulk_jobs_status ON bulk_jobs(status,updated_at);

        CREATE TABLE IF NOT EXISTS bulk_job_items (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          job_id INTEGER NOT NULL,
          item_key TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',
          attempts INTEGER NOT NULL DEFAULT 0,
          detail TEXT NOT NULL DEFAULT '',
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          UNIQUE(job_id,item_key),
          FOREIGN KEY(job_id) REFERENCES bulk_jobs(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_bulk_job_items_next ON bulk_job_items(job_id,status,id);
        CREATE INDEX IF NOT EXISTS idx_bulk_job_items_updated ON bulk_job_items(status,updated_at);
        """)
