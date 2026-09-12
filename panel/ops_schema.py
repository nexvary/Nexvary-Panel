from __future__ import annotations

from .db_layer import db


def ensure_ops_schema() -> None:
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS dns_zone_bindings (
          domain TEXT PRIMARY KEY,
          target_id INTEGER NOT NULL,
          owner TEXT NOT NULL,
          updated_at INTEGER NOT NULL,
          FOREIGN KEY(target_id) REFERENCES integration_targets(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_dns_zone_bindings_target ON dns_zone_bindings(target_id);

        CREATE TABLE IF NOT EXISTS dns_changes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          domain TEXT NOT NULL,
          target_id INTEGER NOT NULL,
          operation TEXT NOT NULL,
          record_type TEXT NOT NULL,
          record_name TEXT NOT NULL,
          record_value TEXT NOT NULL,
          ttl INTEGER NOT NULL DEFAULT 300,
          priority INTEGER NOT NULL DEFAULT 0,
          provider_record_id TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'preview',
          snapshot_json TEXT NOT NULL DEFAULT '',
          owner TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          applied_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_dns_changes_owner_domain ON dns_changes(owner,domain,created_at);

        CREATE TABLE IF NOT EXISTS ssl_jobs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          domain TEXT NOT NULL,
          action TEXT NOT NULL,
          contact_email TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'queued',
          detail TEXT NOT NULL DEFAULT '',
          owner TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ssl_jobs_owner_domain ON ssl_jobs(owner,domain,created_at);

        CREATE TABLE IF NOT EXISTS ssl_policies (
          domain TEXT PRIMARY KEY,
          owner TEXT NOT NULL,
          contact_email TEXT NOT NULL DEFAULT '',
          auto_renew INTEGER NOT NULL DEFAULT 0,
          renew_before_days INTEGER NOT NULL DEFAULT 30,
          last_check INTEGER NOT NULL DEFAULT 0,
          last_renewal INTEGER NOT NULL DEFAULT 0,
          last_status TEXT NOT NULL DEFAULT 'unknown',
          last_detail TEXT NOT NULL DEFAULT '',
          updated_at INTEGER NOT NULL,
          FOREIGN KEY(domain) REFERENCES sites(domain) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_ssl_policies_auto ON ssl_policies(auto_renew,last_check);

        CREATE TABLE IF NOT EXISTS php_runtime_assignments (
          domain TEXT PRIMARY KEY,
          version TEXT NOT NULL,
          owner TEXT NOT NULL,
          updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS postgres_resources (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          db_name TEXT UNIQUE NOT NULL,
          db_user TEXT NOT NULL,
          site_domain TEXT NOT NULL DEFAULT '',
          owner TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          UNIQUE(owner,db_user)
        );
        CREATE INDEX IF NOT EXISTS idx_postgres_owner ON postgres_resources(owner,created_at);

        CREATE TABLE IF NOT EXISTS migration_bundles (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          domain TEXT NOT NULL,
          archive TEXT NOT NULL,
          size_bytes INTEGER NOT NULL DEFAULT 0,
          sha256 TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'ready',
          owner TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_migration_owner_domain ON migration_bundles(owner,domain,created_at);

        CREATE TABLE IF NOT EXISTS fleet_nodes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          endpoint TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 1,
          owner TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'unknown',
          last_seen INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          UNIQUE(owner,name)
        );
        CREATE INDEX IF NOT EXISTS idx_fleet_nodes_owner ON fleet_nodes(owner,enabled);
        """)
