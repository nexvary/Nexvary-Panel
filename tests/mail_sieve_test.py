from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

import mail_sieve

script = mail_sieve._build_script(
    "info@example.test",
    {"enabled": True, "subject": 'Out "today"', "body": "Line one\n.Line two", "interval_days": 2},
    [
        {"field": "subject", "match_type": "contains", "pattern": 'Invoice "2026"', "action": "fileinto", "destination": "Billing", "priority": 10},
        {"field": "from", "match_type": "is", "pattern": "alerts@example.net", "action": "redirect", "destination": "archive@example.net", "priority": 20},
    ],
    {"enabled": True, "action": "junk"},
)
assert 'require [' in script
assert '"fileinto"' in script and '"mailbox"' in script and '"redirect"' in script and '"vacation"' in script
assert 'fileinto :create "Junk";' in script
assert 'fileinto :create "Billing";' in script
assert 'redirect "archive@example.net";' in script
assert 'Invoice \\"2026\\"' in script
assert 'vacation :days 2' in script
assert '\n..Line two\n.' in script
assert "# Managed by Nexvary Panel" in script

try:
    mail_sieve._normalize_filters([
        {"field": "subject", "match_type": "contains", "pattern": "bad\nheader", "action": "discard", "destination": "", "priority": 1}
    ])
    raise AssertionError("newline injection accepted")
except ValueError:
    pass

try:
    mail_sieve._normalize_filters([
        {"field": "from", "match_type": "contains", "pattern": "x", "action": "fileinto", "destination": "../escape", "priority": 1}
    ])
    raise AssertionError("unsafe mailbox folder accepted")
except ValueError:
    pass

try:
    mail_sieve._normalize_filters([{"field": "subject", "match_type": "contains", "pattern": "x", "action": "discard", "priority": 1}] * 41)
    raise AssertionError("unbounded filter list accepted")
except ValueError:
    pass

print("Nexvary Panel Dovecot Sieve generation gate: PASS")
