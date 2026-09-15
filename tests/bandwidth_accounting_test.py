from __future__ import annotations

import pathlib
import sys
import tempfile
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

import bandwidth_accounting as bw


def ts(year: int, month: int, day: int = 1) -> float:
    return datetime(year, month, day, tzinfo=timezone.utc).timestamp()


def line(day: int, mon: str, year: int, size: int) -> bytes:
    return f'1.1.1.1 - - [{day:02d}/{mon}/{year}:00:00:00 +0000] "GET / HTTP/1.1" 200 {size} "-" "gate"\n'.encode()


with tempfile.TemporaryDirectory(prefix="nvp-bandwidth-") as tmp:
    base = pathlib.Path(tmp)
    logs = base / "logs"; logs.mkdir()
    state = base / "state"; state.mkdir()
    bw.LOG_BASE = logs
    bw.STATE_DIR = state
    current = logs / "example.test.access.log"

    current.write_bytes(line(14, "Sep", 2026, 100))
    first = bw.account_domain("example.test", now=ts(2026, 9, 14))
    assert first["bytes"] == 100 and first["complete"] is False
    assert first["reason"] == "tracking-started-mid-period"

    with current.open("ab") as fh:
        fh.write(line(15, "Sep", 2026, 50))
    second = bw.account_domain("example.test", now=ts(2026, 9, 15))
    assert second["bytes"] == 150 and second["complete"] is False

    with current.open("ab") as fh:
        fh.write(line(1, "Oct", 2026, 200))
    october = bw.account_domain("example.test", now=ts(2026, 10, 1))
    assert october["bytes"] == 200 and october["complete"] is True, october

    rotated = logs / "example.test.access.log.1"
    current.rename(rotated)
    current.write_bytes(line(2, "Oct", 2026, 300))
    after_rotation = bw.account_domain("example.test", now=ts(2026, 10, 2))
    assert after_rotation["bytes"] == 500 and after_rotation["complete"] is True, after_rotation

    rotated.rename(logs / "example.test.access.log.2")
    current.rename(rotated)
    current.write_bytes(line(3, "Oct", 2026, 400))
    # Hide the previous inode from the accountant to emulate missed multiple rotations.
    rotated.rename(logs / "example.test.access.log.3")
    gap = bw.account_domain("example.test", now=ts(2026, 10, 3))
    assert gap["complete"] is False, gap
    assert gap["continuous"] is False
    assert gap["reason"] == "rotation-gap-detected"

print("NEXVARY monthly bandwidth accounting gate: PASS")
