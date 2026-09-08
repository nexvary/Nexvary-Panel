from __future__ import annotations

import sqlite3
import time
from flask import request, session
from .config import APP_DIR, DB_PATH


def db() -> sqlite3.Connection:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("""
      CREATE TABLE IF NOT EXISTS sites (id INTEGER PRIMARY KEY, domain TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, target TEXT DEFAULT '', app_port INTEGER, enabled INTEGER NOT NULL DEFAULT 1, owner TEXT NOT NULL DEFAULT 'admin', created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS databases (id INTEGER PRIMARY KEY, db_name TEXT UNIQUE NOT NULL, db_user TEXT NOT NULL, engine TEXT NOT NULL DEFAULT 'mariadb', site_domain TEXT DEFAULT '', owner TEXT NOT NULL DEFAULT 'admin', created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS backups (id INTEGER PRIMARY KEY, domain TEXT NOT NULL, archive TEXT NOT NULL, size_bytes INTEGER NOT NULL DEFAULT 0, owner TEXT NOT NULL DEFAULT 'admin', created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, role TEXT NOT NULL, salt TEXT NOT NULL, password_hash TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT, ip TEXT);
    """)
    return conn


def ensure_schema_columns() -> None:
    with db() as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(sites)")}
        for name, ddl in {
            "app_port": "ALTER TABLE sites ADD COLUMN app_port INTEGER",
            "enabled": "ALTER TABLE sites ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1",
            "owner": "ALTER TABLE sites ADD COLUMN owner TEXT NOT NULL DEFAULT 'admin'",
        }.items():
            if name not in cols:
                conn.execute(ddl)
        db_cols = {r[1] for r in conn.execute("PRAGMA table_info(databases)")}
        if "site_domain" not in db_cols:
            conn.execute("ALTER TABLE databases ADD COLUMN site_domain TEXT DEFAULT ''")


def audit(action: str, detail: str = "") -> None:
    try:
        actor = session.get("user", "system")
        ip = request.headers.get("X-Real-IP", request.remote_addr or "").strip()
    except RuntimeError:
        actor, ip = "system", ""
    with db() as conn:
        conn.execute("INSERT INTO audit(ts,actor,action,detail,ip) VALUES(?,?,?,?,?)", (int(time.time()), actor, action[:80], detail[:700], ip[:80]))
