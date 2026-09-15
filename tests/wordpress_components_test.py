from __future__ import annotations

import importlib.util
import os
import pathlib
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]

def load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module

wp = load("nvp_wp_agent_components_test", ROOT / "agent" / "wordpress_agent.py")
components = load("nvp_wp_components_test", ROOT / "agent" / "wordpress_components.py")

with tempfile.TemporaryDirectory(prefix="nvp-wp-components-") as tmp:
    base = pathlib.Path(tmp) / "sites"
    backups = pathlib.Path(tmp) / "backups"
    public = base / "wp.example.test" / "public"
    plugin = public / "wp-content" / "plugins" / "hello-tool"
    theme = public / "wp-content" / "themes" / "royal-theme"
    (public / "wp-includes").mkdir(parents=True)
    plugin.mkdir(parents=True)
    theme.mkdir(parents=True)
    (public / "wp-includes" / "version.php").write_text("<?php\n$wp_version = '6.8.2';\n", encoding="utf-8")
    (public / "wp-config.php").write_text("<?php // preserve config\n", encoding="utf-8")
    (plugin / "hello-tool.php").write_text("<?php\n/*\nVersion: 1.0.0\n*/\n", encoding="utf-8")
    (plugin / "data.txt").write_text("old-data", encoding="utf-8")
    (theme / "style.css").write_text("/*\nVersion: 3.0.0\n*/\n", encoding="utf-8")

    wp.SITE_BASE = base
    wp.BACKUP_BASE = backups

    def fake_api(path: str, params: dict):
        slug = params.get("request[slug]")
        if slug == "hello-tool":
            return {"version": "2.0.0", "download_link": "https://downloads.wordpress.org/plugin/hello-tool.2.0.0.zip"}
        if slug == "royal-theme":
            return {"version": "3.0.0", "download_link": "https://downloads.wordpress.org/theme/royal-theme.3.0.0.zip"}
        return {"version": "1.0.0", "download_link": "https://evil.example.invalid/package.zip"}

    wp._wp_api = fake_api

    checked = components.check_component(wp, "wp.example.test", "plugin", "hello-tool")
    assert checked["installed_version"] == "1.0.0"
    assert checked["latest_version"] == "2.0.0"
    assert checked["update_available"] is True
    theme_check = components.check_component(wp, "wp.example.test", "theme", "royal-theme")
    assert theme_check["update_available"] is False

    original_download = components._download
    original_chown = components.os.chown
    original_getpwnam = wp.pwd.getpwnam

    def fake_download(_wp, url: str, destination: pathlib.Path) -> pathlib.Path:
        assert url == "https://downloads.wordpress.org/plugin/hello-tool.2.0.0.zip"
        archive = destination / "component.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("hello-tool/hello-tool.php", "<?php\n/*\nVersion: 2.0.0\n*/\n")
            zf.writestr("hello-tool/data.txt", "new-data")
        return archive

    components._download = fake_download
    components.os.chown = lambda *args, **kwargs: None
    wp.pwd.getpwnam = lambda name: (_ for _ in ()).throw(KeyError(name))
    try:
        result = components.update_component(wp, "wp.example.test", "plugin", "hello-tool")
        assert result["ok"] is True and result["updated"] is True
        assert result["installed_version"] == "1.0.0" and result["latest_version"] == "2.0.0"
        snapshot_id = result["snapshot_id"]
        assert wp.SNAPSHOT_RE.fullmatch(snapshot_id)
        assert (backups / "wp.example.test" / snapshot_id / "component-manifest.json").is_file()
        assert "Version: 2.0.0" in (plugin / "hello-tool.php").read_text(encoding="utf-8")
        assert (plugin / "data.txt").read_text(encoding="utf-8") == "new-data"
        assert "preserve config" in (public / "wp-config.php").read_text(encoding="utf-8")
        assert not (public / ".maintenance").exists()

        rolled = components.rollback_component(wp, "wp.example.test", snapshot_id)
        assert rolled["ok"] is True and rolled["restored_version"] == "1.0.0"
        assert "Version: 1.0.0" in (plugin / "hello-tool.php").read_text(encoding="utf-8")
        assert (plugin / "data.txt").read_text(encoding="utf-8") == "old-data"
        assert not (public / ".maintenance").exists()
    finally:
        components._download = original_download
        components.os.chown = original_chown
        wp.pwd.getpwnam = original_getpwnam

    # ZIP traversal must be rejected before extraction.
    traversal = pathlib.Path(tmp) / "traversal.zip"
    with zipfile.ZipFile(traversal, "w") as zf:
        zf.writestr("hello-tool/../../escape.php", "bad")
    try:
        components._extract(traversal, pathlib.Path(tmp) / "extract-traversal", "hello-tool")
        raise AssertionError("ZIP traversal was accepted")
    except RuntimeError as exc:
        assert "unsafe-path" in str(exc)

    # ZIP symlink entries must be rejected.
    symlink_zip = pathlib.Path(tmp) / "symlink.zip"
    with zipfile.ZipFile(symlink_zip, "w") as zf:
        info = zipfile.ZipInfo("hello-tool/link.php")
        info.create_system = 3
        info.external_attr = (0o120777 << 16)
        zf.writestr(info, "../../outside")
    try:
        components._extract(symlink_zip, pathlib.Path(tmp) / "extract-symlink", "hello-tool")
        raise AssertionError("ZIP symlink was accepted")
    except RuntimeError as exc:
        assert "symlink" in str(exc)

    # Arbitrary/untrusted package hosts are never accepted from WordPress API metadata.
    try:
        components.check_component(wp, "wp.example.test", "plugin", "unknown-plugin")
        raise AssertionError("uninstalled/untrusted plugin was accepted")
    except ValueError:
        pass

print("Nexvary Panel WordPress components gate: PASS")
