from __future__ import annotations

from .db_layer import db


def ensure_doctor_schema() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS doctor_remediations (
                id INTEGER PRIMARY KEY,
                check_name TEXT NOT NULL,
                service_name TEXT NOT NULL,
                before_ok INTEGER NOT NULL,
                before_detail TEXT NOT NULL DEFAULT '',
                after_ok INTEGER,
                after_detail TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL CHECK(status IN ('applied','verified','failed')),
                actor TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_doctor_remediations_created
              ON doctor_remediations(created_at DESC);
            """
        )
