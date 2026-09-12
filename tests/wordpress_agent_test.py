from __future__ import annotations

import hashlib
import importlib.util
import os
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("nvp_wordpress_agent", ROOT / "agent" / "wordpress_agent.py")
agent = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(agent)

with tempfile.TemporaryDirectory(prefix="nvp-wordpress-agent-") as tmp:
    base = pathlib.Path(tmp) / "sites"
    backups = pathlib.Path(tmp) / "backups"
    public = base / "wp.example.test" / "public"
    (public / "wp-includes").mkdir(parents=True)
    (public / "wp-content" / "plugins" / "hello-tool").mkdir(parents=True)
    (public / "wp-content" / "themes" / "royal-theme").mkdir(parents=True)
    version_text = "<?php\n$wp_version = '6.8.2';\n"
    (public / "wp-includes" / "version.php").write_text(version_text, encoding="utf-8")
    core_text = "<?php // core fixture\n"
    (public / "wp-load.php").write_text(core_text, encoding="utf-8")
    config_text = "<?php // preserve me\n"
    (public / "wp-config.php").write_text(config_text, encoding="utf-8")
    plugin_text = "<?php\n/*\nVersion: 2.4.1\n*/\n"
    (public / "wp-content" / "plugins" / "hello-tool" / "hello-tool.php").write_text(plugin_text, encoding="utf-8")
    (public / "wp-content" / "themes" / "royal-theme" / "style.css").write_text("/*\nVersion: 1.7.0\n*/\n", encoding="utf-8")

    agent.SITE_BASE = base
    agent.BACKUP_BASE = backups
    inventory = agent.inventory("wp.example.test")
    assert inventory["ok"] is True
    assert inventory["version"] == "6.8.2"
    assert inventory["config_present"] is True
    assert inventory["plugin_count"] == 1 and inventory["plugins"][0]["slug"] == "hello-tool"
    assert inventory["theme_count"] == 1 and inventory["themes"][0]["slug"] == "royal-theme"
    assert inventory["maintenance"] is False

    checksums = {
        "wp-includes/version.php": hashlib.md5(version_text.encode(), usedforsecurity=False).hexdigest(),
        "wp-load.php": hashlib.md5(core_text.encode(), usedforsecurity=False).hexdigest(),
        "wp-content/plugins/hello-tool/hello-tool.php": "0" * 32,
    }
    agent._wp_api = lambda path, params: {"checksums": checksums}
    integrity = agent.integrity("wp.example.test")
    assert integrity["integrity_ok"] is True, integrity
    assert integrity["checked"] == 2

    (public / "wp-load.php").write_text("tampered", encoding="utf-8")
    integrity = agent.integrity("wp.example.test")
    assert integrity["integrity_ok"] is False
    assert integrity["mismatched_count"] == 1
    assert "wp-load.php" in integrity["mismatched"]

    # Model a trusted same-version WordPress release without external network in unit tests.
    release = pathlib.Path(tmp) / "release" / "wordpress"
    (release / "wp-includes").mkdir(parents=True)
    (release / "wp-includes" / "version.php").write_text(version_text, encoding="utf-8")
    (release / "wp-load.php").write_text(core_text, encoding="utf-8")
    original_download = agent._download_release
    original_extract = agent._extract_release
    original_chown = agent.os.chown
    agent._download_release = lambda version, destination: pathlib.Path(tmp) / "release.tar.gz"
    agent._extract_release = lambda archive, destination: release
    # Production runs as root; unit tests are intentionally unprivileged.
    agent.os.chown = lambda *args, **kwargs: None
    try:
        repaired = agent.repair_core("wp.example.test")
        assert repaired["ok"] is True and repaired["repaired"] == 1 and repaired["integrity_ok"] is True
        snapshot_id = repaired["snapshot_id"]
        assert agent.SNAPSHOT_RE.fullmatch(snapshot_id)
        assert (backups / "wp.example.test" / snapshot_id / "manifest.json").is_file()
        assert (public / "wp-load.php").read_text(encoding="utf-8") == core_text
        assert (public / "wp-config.php").read_text(encoding="utf-8") == config_text
        assert (public / "wp-content" / "plugins" / "hello-tool" / "hello-tool.php").read_text(encoding="utf-8") == plugin_text

        rolled = agent.rollback_repair("wp.example.test", snapshot_id)
        assert rolled["ok"] is True and rolled["rolled_back"] == 1
        assert (public / "wp-load.php").read_text(encoding="utf-8") == "tampered"
        assert (public / "wp-config.php").read_text(encoding="utf-8") == config_text
    finally:
        agent._download_release = original_download
        agent._extract_release = original_extract
        agent.os.chown = original_chown

    # The production service chowns .maintenance to www-data; model no account in this unprivileged fixture.
    original_getpwnam = agent.pwd.getpwnam
    agent.pwd.getpwnam = lambda name: (_ for _ in ()).throw(KeyError(name))
    try:
        result = agent.maintenance("wp.example.test", True)
        assert result["maintenance"] is True and (public / ".maintenance").is_file()
        assert agent.inventory("wp.example.test")["maintenance"] is True
        result = agent.maintenance("wp.example.test", False)
        assert result["maintenance"] is False and not (public / ".maintenance").exists()
    finally:
        agent.pwd.getpwnam = original_getpwnam

    # Symlinked WordPress roots must never be accepted as managed roots.
    outside = pathlib.Path(tmp) / "outside"
    outside.mkdir()
    (base / "link.example.test").mkdir(parents=True)
    (base / "link.example.test" / "public").symlink_to(outside, target_is_directory=True)
    try:
        agent.inventory("link.example.test")
        raise AssertionError("symlinked site root was accepted")
    except ValueError:
        pass

print("Nexvary Panel WordPress lifecycle agent gate: PASS")
