from __future__ import annotations

import pathlib
import subprocess
import sys
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

import server_agent  # noqa: E402


assert server_agent.dispatch({"action": "anything"}) == {"ok": False, "error": "server-action-not-allowed"}
assert "server-updates-preview" in server_agent.ACTIONS
assert "server-time-enable-ntp" in server_agent.ACTIONS

update_output = """Reading package lists... Done
Inst nginx [1.0] (1.1 Ubuntu:stable [amd64])
Inst openssl [3.0] (3.1 Ubuntu:stable [amd64])
Conf nginx (1.1 Ubuntu:stable [amd64])
"""
with patch.object(server_agent, "_run", return_value=subprocess.CompletedProcess(["apt-get"], 0, update_output, "")):
    result = server_agent._updates_preview()
assert result["ok"] is True
assert result["count"] == 2
assert [item["name"] for item in result["packages"]] == ["nginx", "openssl"]
assert len(result["fingerprint"]) == 64
assert result["apply_supported"] is False

ps_output = """ 10 root nginx 4.2 0.5 120
 20 mysql mariadbd 1.0 3.5 400
"""
with patch.object(server_agent, "_run", return_value=subprocess.CompletedProcess(["ps"], 0, ps_output, "")):
    processes = server_agent._processes()
assert processes["ok"] is True
assert processes["processes"][0]["pid"] == 10
assert processes["processes"][0]["command"] == "nginx"

with patch.object(server_agent, "_run", return_value=subprocess.CompletedProcess(["timedatectl"], 0, "Timezone=UTC\nNTP=yes\nNTPSynchronized=yes\n", "")):
    state = server_agent._time_state()
assert state["timezone"] == "UTC"
assert state["ntp"] is True
assert state["synchronized"] is True

print("Nexvary Panel Server Lifecycle agent gate: PASS")
