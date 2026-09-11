from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("nvp_wordpress_agent", ROOT / "agent" / "wordpress_agent.py")
agent = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(agent)

with tempfile.TemporaryDirectory(prefix="nvp-wordpress-agent-") as tmp:
    base = pathlib.Path(tmp) / "sites"
    public = base / "wp.example.test" / "public"
    (public / "wp-includes").mkdir(parents=True)
    (public / "wp-content" / "plugins" / "hello-tool").mkdir(parents=True)
    (public / "wp-content" / "themes" / "royal-theme").mkdir(parents=True)
    version_text = "<?php\n$wp_version = '6.8.2';\n"
    (public / "wp-includes" / "version.php").write_text(version_text, encoding="utf-8")
    core_text = "<?php // core fixture\n"
    (public / "wp-load.php").write_text(core_text, encoding="utf-8")
    (public / "wp-config.php").write_text("<?php // no secrets in test\n", encoding="utf-8")
    (public / "wp-content" / "plugins" / "hello-tool" / "hello-tool.php").write_text("<?php\n/*\nVersion: 2.4.1\n*/\n", encoding="utf-8")
    (public / "wp-content" / "themes" / "royal-theme" / "style.css").write_text("/*\nVersion: 1.7.0\n*/\n", encoding="utf-8")

    agent.SITE_BASE = base
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
        # wp-content entries are deliberately ignored: integrity covers WordPress core only.
        "wp-content/plugins/hello-tool/hello-tool.php": "0" * 32,
    }
    agent._wp_api = lambda path, params: {"checksums": checksums}
    integrity = agent.integrity("wp.example.test")
    assert integrity["integrity_ok"] is True, integrity
    assert integrity["checked"] == 2

    (public / "wp-load.php").write_text("tampered", encoding="utf-8")
    integrity = agent.integrity("wp.example.test")
    assert integrity["integrity_ok"] is False
    assert "wp-load.php" in integrity["mismatched"]

    # The production service runs as root and chowns .maintenance to www-data.
    # This unit test intentionally runs unprivileged, so model an environment without that account.
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
