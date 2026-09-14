#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

LOG_BASE = Path(os.environ.get("NVP_NGINX_LOG_DIR", "/var/log/nginx"))
STATE_DIR = Path(os.environ.get("NVP_USAGE_STATE_DIR", "/var/lib/nexvary-panel/usage"))
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
LOG_RE = re.compile(rb'^\S+ \S+ \S+ \[(?P<date>[^\]]+)\] "[A-Z]+ \S+ [^"]+" \d{3} (?P<bytes>\d+|-) ')
MONTHS = {b"Jan":1,b"Feb":2,b"Mar":3,b"Apr":4,b"May":5,b"Jun":6,b"Jul":7,b"Aug":8,b"Sep":9,b"Oct":10,b"Nov":11,b"Dec":12}
MAX_LINE = 64 * 1024


def _period(now: float | None = None) -> str:
    stamp = datetime.fromtimestamp(now if now is not None else time.time(), tz=timezone.utc)
    return f"{stamp.year:04d}-{stamp.month:02d}"


def _line_period(raw_date: bytes) -> str | None:
    # NGINX common date begins 14/Sep/2026:05:34:00 +0000.
    if len(raw_date) < 11 or raw_date[2:3] != b"/" or raw_date[6:7] != b"/":
        return None
    try:
        day = int(raw_date[0:2]); month = MONTHS.get(raw_date[3:6]); year = int(raw_date[7:11])
    except ValueError:
        return None
    if month is None or not 1 <= day <= 31:
        return None
    return f"{year:04d}-{month:02d}"


def _safe_log(path: Path) -> os.stat_result | None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return None
    return st


def _scan(path: Path, offset: int, period: str) -> tuple[int, int]:
    st = _safe_log(path)
    if st is None:
        raise ValueError("log-unavailable")
    if offset < 0 or offset > st.st_size:
        raise ValueError("log-offset-invalid")
    total = 0
    with path.open("rb") as handle:
        handle.seek(offset)
        if offset:
            # State offsets are stored only after complete lines. If a file was externally truncated,
            # the size check above rejects it instead of silently double-counting.
            pass
        while True:
            line = handle.readline(MAX_LINE + 1)
            if not line:
                break
            if len(line) > MAX_LINE or not line.endswith(b"\n"):
                continue
            match = LOG_RE.match(line)
            if not match or _line_period(match.group("date")) != period:
                continue
            size = match.group("bytes")
            if size.isdigit():
                total += int(size)
        end = handle.tell()
    return total, end


def _state_path(domain: str) -> Path:
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("invalid-domain")
    return STATE_DIR / f"{domain}.json"


def _load(domain: str) -> dict | None:
    path = _state_path(domain)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_size > 32 * 1024:
        return None
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _save(domain: str, data: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE_DIR, 0o700)
    path = _state_path(domain)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{domain}.", dir=str(STATE_DIR))
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        payload = (json.dumps(data, separators=(",", ":"), sort_keys=True) + "\n").encode()
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload); handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp, path); os.chmod(path, 0o600)
    finally:
        tmp.unlink(missing_ok=True)


def account_domain(domain: str, *, now: float | None = None) -> dict:
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("invalid-domain")
    current = LOG_BASE / f"{domain}.access.log"
    current_stat = _safe_log(current)
    period = _period(now)
    state = _load(domain)
    if current_stat is None:
        result = {
            "domain": domain, "period": period, "bytes": 0, "complete": False,
            "continuous": False, "inode": None, "offset": 0, "updated_at": int(now or time.time()),
            "reason": "current-log-unavailable",
        }
        _save(domain, result); return result

    inode = int(current_stat.st_ino)
    now_i = int(now or time.time())
    if not state:
        added, end = _scan(current, 0, period)
        result = {
            "domain": domain, "period": period, "bytes": added, "complete": False,
            "continuous": True, "inode": inode, "offset": end, "updated_at": now_i,
            "reason": "tracking-started-mid-period",
        }
        _save(domain, result); return result

    old_inode = state.get("inode")
    old_offset = int(state.get("offset") or 0)
    same_period = state.get("period") == period
    total = int(state.get("bytes") or 0) if same_period else 0
    continuous = bool(state.get("continuous", False))
    complete = bool(state.get("complete", False)) if same_period else bool(continuous and old_inode is not None)
    reason = "continuous"

    try:
        if old_inode == inode:
            added, end = _scan(current, old_offset, period)
            total += added
        else:
            rotated = LOG_BASE / f"{domain}.access.log.1"
            rotated_stat = _safe_log(rotated)
            if rotated_stat is not None and old_inode == int(rotated_stat.st_ino):
                added_old, _ = _scan(rotated, old_offset, period)
                added_new, end = _scan(current, 0, period)
                total += added_old + added_new
            else:
                # A rotation/truncation escaped the accounting window. Preserve what was already
                # counted, resume from the current file, but never claim this month is complete.
                added_new, end = _scan(current, 0, period)
                total += added_new
                continuous = False
                complete = False
                reason = "rotation-gap-detected"
    except ValueError:
        continuous = False; complete = False; reason = "scan-gap-detected"
        end = int(current_stat.st_size)

    result = {
        "domain": domain, "period": period, "bytes": max(0, total), "complete": bool(complete),
        "continuous": bool(continuous), "inode": inode, "offset": max(0, int(end)), "updated_at": now_i,
        "reason": reason,
    }
    _save(domain, result); return result


def account_all(*, now: float | None = None) -> list[dict]:
    rows = []
    for path in sorted(LOG_BASE.glob("*.access.log")):
        name = path.name[:-len(".access.log")]
        if DOMAIN_RE.fullmatch(name):
            try:
                rows.append(account_domain(name, now=now))
            except (OSError, ValueError):
                continue
    return rows


def main() -> None:
    account_all()


if __name__ == "__main__":
    main()
