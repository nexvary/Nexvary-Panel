from __future__ import annotations

import time

from .db_layer import db


def ensure_account_schema() -> None:
    now = int(time.time())
    with db() as conn:
        conn.executescript("""
          CREATE TABLE IF NOT EXISTS reseller_profiles (
            username TEXT PRIMARY KEY,
            max_accounts INTEGER NOT NULL DEFAULT 25,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
          );
          CREATE TABLE IF NOT EXISTS hosting_accounts (
            username TEXT PRIMARY KEY,
            reseller_owner TEXT NOT NULL DEFAULT 'admin',
            primary_domain TEXT UNIQUE NOT NULL,
            package_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(package_id) REFERENCES hosting_packages(id) ON DELETE RESTRICT
          );
          CREATE INDEX IF NOT EXISTS idx_hosting_accounts_reseller ON hosting_accounts(reseller_owner,status);
          CREATE TABLE IF NOT EXISTS account_suspension_sites (
            username TEXT NOT NULL,
            domain TEXT NOT NULL,
            was_enabled INTEGER NOT NULL DEFAULT 1,
            captured_at INTEGER NOT NULL,
            PRIMARY KEY(username,domain)
          );
          CREATE INDEX IF NOT EXISTS idx_account_suspension_sites_user ON account_suspension_sites(username,was_enabled);
        """)
        # The built-in admin is not stored in the users table, but it is the root reseller boundary.
        conn.execute(
            "INSERT OR IGNORE INTO reseller_profiles(username,max_accounts,enabled,created_at,updated_at) VALUES('admin',100000,1,?,?)",
            (now, now),
        )
