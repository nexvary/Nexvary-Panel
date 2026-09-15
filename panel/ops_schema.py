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
          credential_ref TEXT NOT NULL DEFAULT '',
          enabled INTEGER NOT NULL DEFAULT 1,
          owner TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'unknown',
          last_seen INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          UNIQUE(owner,name)
        );
        CREATE INDEX IF NOT EXISTS idx_fleet_nodes_owner ON fleet_nodes(owner,enabled);

        CREATE TABLE IF NOT EXISTS fleet_probes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          node_id INTEGER NOT NULL,
          status TEXT NOT NULL,
          remote_version TEXT NOT NULL DEFAULT '',
          capabilities_json TEXT NOT NULL DEFAULT '{}',
          latency_ms INTEGER NOT NULL DEFAULT 0,
          checked_at INTEGER NOT NULL,
          FOREIGN KEY(node_id) REFERENCES fleet_nodes(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_fleet_probes_node ON fleet_probes(node_id,id DESC);

        CREATE TABLE IF NOT EXISTS fleet_inbound_tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          label TEXT NOT NULL,
          token_hash TEXT NOT NULL UNIQUE,
          enabled INTEGER NOT NULL DEFAULT 1,
          owner TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          last_used INTEGER NOT NULL DEFAULT 0,
          UNIQUE(owner,label)
        );
        CREATE INDEX IF NOT EXISTS idx_fleet_inbound_tokens_enabled ON fleet_inbound_tokens(enabled,owner);

        CREATE TABLE IF NOT EXISTS fleet_jobs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          request_id TEXT NOT NULL UNIQUE,
          node_id INTEGER,
          direction TEXT NOT NULL,
          operation TEXT NOT NULL,
          status TEXT NOT NULL,
          detail_json TEXT NOT NULL DEFAULT '{}',
          owner TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          FOREIGN KEY(node_id) REFERENCES fleet_nodes(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_fleet_jobs_owner_created ON fleet_jobs(owner,created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_fleet_jobs_direction_status ON fleet_jobs(direction,status,updated_at);
        """)
        cols = {str(row[1]) for row in conn.execute("PRAGMA table_info(fleet_nodes)").fetchall()}
        if "credential_ref" not in cols:
            conn.execute("ALTER TABLE fleet_nodes ADD COLUMN credential_ref TEXT NOT NULL DEFAULT ''")
        # database_access is initialized before advanced_ops in the module registry.
        # Once postgres_resources exists, complete the cross-module adoption bridge.
        from .database_access_schema import ensure_postgres_access_bridge
        ensure_postgres_access_bridge(conn)
