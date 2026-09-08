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
      CREATE TABLE IF NOT EXISTS deployments (id INTEGER PRIMARY KEY, domain TEXT NOT NULL, repo_url TEXT NOT NULL, branch TEXT NOT NULL DEFAULT 'main', target TEXT NOT NULL DEFAULT 'public', status TEXT NOT NULL DEFAULT 'pending', detail TEXT DEFAULT '', owner TEXT NOT NULL DEFAULT 'admin', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS wordpress_instances (id INTEGER PRIMARY KEY, domain TEXT UNIQUE NOT NULL, db_name TEXT NOT NULL, db_user TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'prepared', version TEXT DEFAULT '', owner TEXT NOT NULL DEFAULT 'admin', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY, level TEXT NOT NULL DEFAULT 'info', title TEXT NOT NULL, detail TEXT DEFAULT '', source TEXT DEFAULT 'system', owner TEXT NOT NULL DEFAULT 'admin', read_at INTEGER, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS user_security (username TEXT PRIMARY KEY, totp_secret TEXT DEFAULT '', totp_enabled INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);
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


def notify(level: str, title: str, detail: str = "", source: str = "system", owner: str | None = None) -> None:
    level = level if level in {"info", "ok", "warning", "critical"} else "info"
    try:
        actor = session.get("user", "admin")
    except RuntimeError:
        actor = "admin"
    owner = (owner or actor or "admin")[:64]
    now = int(time.time())
    with db() as conn:
        # Suppress identical noisy alerts for ten minutes.
        recent = conn.execute("SELECT 1 FROM notifications WHERE owner=? AND source=? AND title=? AND created_at>? LIMIT 1",
                              (owner, source[:40], title[:120], now - 600)).fetchone()
        if recent:
            return
        conn.execute("INSERT INTO notifications(level,title,detail,source,owner,created_at) VALUES(?,?,?,?,?,?)",
                     (level, title[:120], detail[:700], source[:40], owner, now))
