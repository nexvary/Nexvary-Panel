from __future__ import annotations

import json
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

import wordpress_entry as entry

with tempfile.TemporaryDirectory(prefix="nvp-wp-selective-") as tmp_name:
    root = pathlib.Path(tmp_name)
    live = root / "live"
    stage = root / "stage"
    backups = root / "backups"
    for site in (live, stage):
        for name in ("plugins", "themes", "uploads"):
            (site / "wp-content" / name).mkdir(parents=True, exist_ok=True)
    (live / "wp-content/plugins/old.php").write_text("old-plugin", encoding="utf-8")
    (live / "wp-content/themes/old.css").write_text("old-theme", encoding="utf-8")
    (live / "wp-content/uploads/media.txt").write_text("live-media", encoding="utf-8")
    (stage / "wp-content/plugins/new.php").write_text("new-plugin", encoding="utf-8")
    (stage / "wp-content/themes/new.css").write_text("new-theme", encoding="utf-8")
    (stage / "wp-content/uploads/media.txt").write_text("stage-media", encoding="utf-8")

    entry.wp._domain = lambda value: str(value)
    entry.wp._wordpress_root = lambda domain: live if domain == "live.example.test" else stage
    entry.wp.inventory = lambda domain: {"ok": True, "version": "6.8.2"}
    entry.staging._config_meta = lambda path: {"db_name": "live_db", "db_user": "wp_user", "db_password": "x", "db_host": "localhost", "table_prefix": "wp_"}
    def fake_publish_dir(wp, domain, snapshot):
        backups.mkdir(parents=True, exist_ok=True)
        return backups / snapshot
    entry.staging._publish_dir = fake_publish_dir
    entry.staging._dump_db = lambda name, destination: destination.write_bytes(b"-- safe test dump --\n")
    entry.staging._chown_www = lambda path: None

    result = entry.selective_publish("live.example.test", "stage.example.test", "plugins_themes")
    assert result["ok"] is True
    assert result["database_changed"] is False
    assert result["uploads_changed"] is False
    assert (live / "wp-content/plugins/new.php").read_text(encoding="utf-8") == "new-plugin"
    assert not (live / "wp-content/plugins/old.php").exists()
    assert (live / "wp-content/themes/new.css").read_text(encoding="utf-8") == "new-theme"
    assert (live / "wp-content/uploads/media.txt").read_text(encoding="utf-8") == "live-media"
    manifest = json.loads((backups / result["snapshot_id"] / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["scope"] == "plugins_themes"
    assert (backups / result["snapshot_id"] / "database.sql").is_file()

    try:
        entry.selective_publish("live.example.test", "stage.example.test", "database")
        raise AssertionError("unsupported selective scope must be rejected")
    except ValueError as exc:
        assert str(exc) == "unsupported-wordpress-selective-publish-scope"

    restored = []
    entry.wp.inventory = lambda domain: {"ok": False}
    entry.staging._restore_publish = lambda wp, domain, snapshot, manifest: restored.append((domain, snapshot.name, manifest["scope"]))
    try:
        entry.selective_publish("live.example.test", "stage.example.test", "plugins_themes")
        raise AssertionError("failed post-publish validation must roll back")
    except RuntimeError as exc:
        assert str(exc) == "wordpress-selective-publish-validation-failed"
    assert restored and restored[-1][0] == "live.example.test" and restored[-1][2] == "plugins_themes"

print("Nexvary Panel WordPress selective publish agent gate: PASS")
