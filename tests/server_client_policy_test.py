from __future__ import annotations

import pathlib
import sys
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from panel import server_client


class ProbeSocket:
    opened = 0
    timeout = None

    def __init__(self, *args, **kwargs):
        type(self).opened += 1

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, value):
        type(self).timeout = value

    def connect(self, path):
        raise OSError("probe-stop-before-provider")


ProbeSocket.opened = 0
with patch("panel.server_client.socket.socket", ProbeSocket):
    denied = server_client.server_call({"action": "root-shell", "command": "id"}, timeout=9999)
assert denied == {"ok": False, "error": "privileged operation not registered"}
assert ProbeSocket.opened == 0, "unknown privileged action reached Unix socket boundary"

ProbeSocket.opened = 0
ProbeSocket.timeout = None
with patch("panel.server_client.socket.socket", ProbeSocket):
    result = server_client.server_call({"action": "server-overview"}, timeout=9999)
assert result == {"ok": False, "error": "server lifecycle provider unavailable"}
assert ProbeSocket.opened == 1
assert ProbeSocket.timeout == 15, ProbeSocket.timeout

ProbeSocket.opened = 0
ProbeSocket.timeout = None
with patch("panel.server_client.socket.socket", ProbeSocket):
    result = server_client.server_call({"action": "server-updates-apply", "fingerprint": "a" * 64}, timeout=9999)
assert result == {"ok": False, "error": "server lifecycle provider unavailable"}
assert ProbeSocket.opened == 1
assert ProbeSocket.timeout == 1900, ProbeSocket.timeout

oversized = {"action": "server-overview", "padding": "x" * (server_client.MAX_REQUEST + 100)}
ProbeSocket.opened = 0
with patch("panel.server_client.socket.socket", ProbeSocket):
    result = server_client.server_call(oversized)
assert result == {"ok": False, "error": "server request too large"}
assert ProbeSocket.opened == 0, "oversized privileged request reached Unix socket boundary"

print("NEXVARY privileged client fail-closed boundary gate: PASS")
