from __future__ import annotations

import os
import stat
from pathlib import Path

from webtools import _site_root, site_metrics

MAX_ENTRIES = 500_000


def _tree_bytes(root: Path) -> tuple[int, int]:
    total = 0
    entries = 0
    stack = [root]
    while stack:
        base = stack.pop()
        try:
            with os.scandir(base) as it:
                for entry in it:
                    entries += 1
                    if entries > MAX_ENTRIES:
                        raise ValueError("site-tree-entry-limit-exceeded")
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    mode = st.st_mode
                    if stat.S_ISLNK(mode):
                        continue
                    if stat.S_ISREG(mode):
                        total += int(st.st_size)
                    elif stat.S_ISDIR(mode):
                        stack.append(Path(entry.path))
        except OSError as exc:
            raise ValueError("site-tree-unreadable") from exc
    return total, entries


def site_resource_usage(domain: str) -> dict:
    root = _site_root(domain)
    disk_bytes, entries = _tree_bytes(root)
    metrics = site_metrics(domain)
    if not metrics.get("ok"):
        bandwidth_bytes = None
        bandwidth_scope = "unavailable"
    else:
        payload = metrics.get("metrics") or {}
        bandwidth_bytes = int(payload.get("bandwidth_bytes") or 0)
        bandwidth_scope = str(payload.get("sample_scope") or "latest-log-window")
    return {
        "ok": True,
        "domain": domain,
        "disk_bytes": disk_bytes,
        "filesystem_entries": entries,
        "bandwidth_bytes": bandwidth_bytes,
        "bandwidth_scope": bandwidth_scope,
        "disk_scope": "managed-site-root",
        "hard_quota_safe": {"disk": True, "bandwidth": False},
    }
