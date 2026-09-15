from __future__ import annotations

import json
import os
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

from webtools import _site_root, site_metrics

MAX_ENTRIES = 500_000
USAGE_STATE_DIR = Path(os.environ.get("NVP_USAGE_STATE_DIR", "/var/lib/nexvary-panel/usage"))


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


def _monthly_bandwidth(domain: str) -> dict:
    period = datetime.fromtimestamp(time.time(), tz=timezone.utc).strftime("%Y-%m")
    path = USAGE_STATE_DIR / f"{domain}.json"
    try:
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_size > 32 * 1024:
            raise ValueError("unsafe-bandwidth-state")
        data = json.loads(path.read_text("utf-8"))
        if not isinstance(data, dict) or data.get("domain") != domain or data.get("period") != period:
            raise ValueError("stale-bandwidth-state")
        amount = max(0, int(data.get("bytes") or 0))
        complete = bool(data.get("complete", False))
        return {
            "bytes": amount,
            "period": period,
            "complete": complete,
            "reason": str(data.get("reason") or "unknown")[:80],
            "updated_at": max(0, int(data.get("updated_at") or 0)),
        }
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError, TypeError):
        return {"bytes": None, "period": period, "complete": False, "reason": "monthly-ledger-unavailable", "updated_at": 0}


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
    monthly = _monthly_bandwidth(domain)
    return {
        "ok": True,
        "domain": domain,
        "disk_bytes": disk_bytes,
        "filesystem_entries": entries,
        "bandwidth_bytes": bandwidth_bytes,
        "bandwidth_scope": bandwidth_scope,
        "monthly_bandwidth_bytes": monthly["bytes"],
        "monthly_bandwidth_period": monthly["period"],
        "monthly_bandwidth_complete": monthly["complete"],
        "monthly_bandwidth_reason": monthly["reason"],
        "monthly_bandwidth_updated_at": monthly["updated_at"],
        "disk_scope": "managed-site-root",
        "hard_quota_safe": {"disk": True, "bandwidth": bool(monthly["complete"])},
    }
