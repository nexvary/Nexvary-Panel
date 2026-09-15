from __future__ import annotations

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent"
sys.path.insert(0, str(AGENT))

import site_controls

with tempfile.TemporaryDirectory(prefix="nvp-site-controls-agent-") as tmp:
    base = pathlib.Path(tmp)
    site = base / "www"
    managed = base / "managed"
    auth = base / "auth"
    logs = base / "logs"
    site.mkdir(); managed.mkdir(); logs.mkdir()
    conf = base / "example.conf"
    conf.write_text("server { server_name example.com; root /var/www/example.com; }\n")

    site_controls._site_root = lambda domain: site
    site_controls._managed_dir = lambda domain: managed
    site_controls._ensure_managed_include = lambda domain: (conf, None)
    site_controls._run = lambda args: {"ok": True}
    site_controls._password_hash = lambda password: "$6$test$only-a-hash"
    site_controls.AUTH_BASE = auth
    site_controls.LOG_BASE = logs
    site_controls.os.chown = lambda *args: None

    privacy = site_controls.sync_directory_privacy(
        "example.com", enabled=True, path="/private/", username="secureuser", password="StrongPassword!2026"
    )
    assert privacy["ok"] is True, privacy
    assert "auth_basic" in (managed / "directory-privacy.conf").read_text()
    auth_text = (auth / "example.com.htpasswd").read_text()
    assert "secureuser:$6$test$only-a-hash" in auth_text
    assert "StrongPassword!2026" not in auth_text

    hotlink = site_controls.sync_hotlink("example.com", enabled=True, extensions=["jpg", "png"])
    assert hotlink["ok"] is True, hotlink
    hotlink_text = (managed / "hotlink-protection.conf").read_text()
    assert "valid_referers" in hotlink_text and "jpg|png" in hotlink_text

    indexing = site_controls.sync_indexing("example.com", mode="off")
    assert indexing["ok"] is True
    assert "autoindex off" in (managed / "directory-indexing.conf").read_text()

    mime = site_controls.sync_mime_overrides("example.com", mappings={"wasm": "application/wasm", "avif": "image/avif"})
    assert mime["ok"] is True, mime
    mime_text = (managed / "mime-overrides.conf").read_text()
    assert "application/wasm" in mime_text and "image/avif" in mime_text
    blocked = site_controls.sync_mime_overrides("example.com", mappings={"php": "text/plain"})
    assert blocked["ok"] is False

    access = logs / "example.com.access.log"
    access.write_text("\n".join(f"line-{i}" for i in range(20)) + "\n")
    raw = site_controls.raw_access("example.com", lines=5)
    assert raw["ok"] is True
    assert raw["lines"] == [f"line-{i}" for i in range(15, 20)]

    disabled = site_controls.sync_directory_privacy("example.com", enabled=False)
    assert disabled["ok"] is True
    assert not (managed / "directory-privacy.conf").exists()
    assert not (auth / "example.com.htpasswd").exists()

print("NEXVARY Site Control provider transaction gate: PASS")
