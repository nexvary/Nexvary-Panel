from __future__ import annotations

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

import wordpress_staging as staging

CONFIG = """<?php
define('DB_NAME', 'live_db');
define('DB_USER', 'wp_user');
define('DB_PASSWORD', 'VerySecretPassword!2026');
define('DB_HOST', 'localhost');
$table_prefix = 'wp_';
define('DISALLOW_FILE_EDIT', true);
if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');
require_once ABSPATH . 'wp-settings.php';
"""

with tempfile.TemporaryDirectory(prefix="nvp-wp-stage-agent-") as tmp_name:
    root = pathlib.Path(tmp_name)
    config = root / "wp-config.php"
    config.write_text(CONFIG, encoding="utf-8")

    meta = staging._config_meta(root)
    assert meta["db_name"] == "live_db"
    assert meta["db_user"] == "wp_user"
    assert meta["db_password"] == "VerySecretPassword!2026"
    assert meta["db_host"] == "localhost"
    assert meta["table_prefix"] == "wp_"

    staging._rewrite_config(config, db_name="stage_db", environment="staging")
    text = config.read_text(encoding="utf-8")
    assert "define('DB_NAME', 'stage_db');" in text
    assert "define('DB_USER', 'wp_user');" in text
    assert "VerySecretPassword!2026" in text
    assert "define('WP_ENVIRONMENT_TYPE', 'staging');" in text

    staging._rewrite_config(
        config,
        db_name="live_db",
        environment="production",
        db_user="live_user",
        db_password="DifferentSecret!2026",
        db_host="127.0.0.1",
    )
    text = config.read_text(encoding="utf-8")
    assert "define('DB_NAME', 'live_db');" in text
    assert "define('DB_USER', 'live_user');" in text
    assert "DifferentSecret!2026" in text
    assert "define('DB_HOST', '127.0.0.1');" in text
    assert "define('WP_ENVIRONMENT_TYPE', 'production');" in text
    assert text.count("WP_ENVIRONMENT_TYPE") == 1

    content = root / "wp-content"
    content.mkdir()
    (content / "index.php").write_text("<?php", encoding="utf-8")
    files, size = staging._scan_tree(root)
    assert files >= 2 and size > 0

    link = root / "unsafe-link"
    link.symlink_to(content / "index.php")
    try:
        staging._scan_tree(root)
        raise AssertionError("symlink must be rejected")
    except ValueError as exc:
        assert str(exc) == "wordpress-staging-symlink-blocked"

    bad = root / "bad-config"
    bad.mkdir()
    (bad / "wp-config.php").write_text(CONFIG.replace("localhost", "db.example.net"), encoding="utf-8")
    try:
        staging._config_meta(bad)
        raise AssertionError("external DB host must be rejected")
    except ValueError as exc:
        assert str(exc) == "wordpress-staging-requires-local-mariadb"

print("Nexvary Panel WordPress staging agent safety gate: PASS")
