from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from migration_adapters import _safe_name  # noqa: E402

for unsafe in (
    "../etc/passwd",
    "../../etc/shadow",
    "site/../../../root/.ssh/authorized_keys",
    "site/../outside.txt",
    "/etc/passwd",
    "C:/Windows/System32/config/SAM",
    "C:\\Windows\\System32\\config\\SAM",
    "./../../escape",
    "safe/..",
    "\x00bad",
    "safe/\x00bad",
):
    try:
        _safe_name(unsafe)
    except ValueError as exc:
        assert str(exc) == "unsafe-migration-archive"
    else:
        raise AssertionError(f"unsafe migration member accepted: {unsafe!r}")

assert _safe_name("./site/index.html") == "site/index.html"
assert _safe_name("site/assets/app.css") == "site/assets/app.css"
assert _safe_name("site\\assets\\app.js") == "site/assets/app.js"

print("Nexvary Panel migration path traversal normalization gate: PASS")
