from __future__ import annotations

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent"
sys.path.insert(0, str(AGENT))

import resource_usage

with tempfile.TemporaryDirectory(prefix="nvp-resource-agent-") as tmp:
    root = pathlib.Path(tmp) / "site"
    root.mkdir()
    (root / "index.html").write_bytes(b"x" * 1024)
    assets = root / "assets"
    assets.mkdir()
    (assets / "app.js").write_bytes(b"y" * 2048)
    outside = pathlib.Path(tmp) / "outside.bin"
    outside.write_bytes(b"z" * 8192)
    (root / "outside-link").symlink_to(outside)

    resource_usage._site_root = lambda domain: root
    resource_usage.site_metrics = lambda domain: {
        "ok": True,
        "metrics": {"bandwidth_bytes": 4096, "sample_scope": "latest-log-window"},
    }

    result = resource_usage.site_resource_usage("example.test")
    assert result["ok"] is True
    assert result["disk_bytes"] == 3072, result
    assert result["bandwidth_bytes"] == 4096
    assert result["hard_quota_safe"] == {"disk": True, "bandwidth": False}
    assert result["disk_scope"] == "managed-site-root"
    assert result["filesystem_entries"] >= 3

print("NEXVARY Resource Usage filesystem safety gate: PASS")
