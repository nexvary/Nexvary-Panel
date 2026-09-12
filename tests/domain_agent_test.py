from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from domain_ops import _rewrite_managed_server_names

raw = b'''server {
 listen 80;
 server_name example.com www.example.com;
}
server {
 listen 443 ssl;
 server_name example.com www.example.com;
 ssl_certificate /x/fullchain.pem;
}
server {
 listen 443 ssl;
 server_name unrelated.example.net;
}
'''
updated, count = _rewrite_managed_server_names(raw, "example.com", ["app.example.com", "parked.example.org"])
expected = b"server_name example.com www.example.com app.example.com parked.example.org;"
assert count == 2, count
assert updated.count(expected) == 2
assert b"server_name unrelated.example.net;" in updated

# A file that does not own the primary domain must never be rewritten.
unchanged, count = _rewrite_managed_server_names(b"server_name other.example.net;", "example.com", ["x.example.com"])
assert count == 0 and unchanged == b"server_name other.example.net;"

print("Nexvary Panel Domain Lifecycle NGINX transformation gate: PASS")
