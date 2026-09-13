from __future__ import annotations

import time

from .db_layer import db
from .extension_registry import EXTENSIONS


def ensure_extension_schema() -> None:
    now = int(time.time())
    with db() as conn:
        conn.executescript("""
          CREATE TABLE IF NOT EXISTS extension_states (
            extension_id TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 1,
            updated_by TEXT NOT NULL DEFAULT 'system',
            updated_at INTEGER NOT NULL
          );
        """)
        for item in EXTENSIONS:
            conn.execute(
                "INSERT OR IGNORE INTO extension_states(extension_id,enabled,updated_by,updated_at) VALUES(?,?,?,?)",
                (item.extension_id, 1 if item.default_enabled else 0, "system", now),
            )
