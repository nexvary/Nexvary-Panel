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
assert "server-updates-apply" in server_agent.ACTIONS
assert "server-time-enable-ntp" in server_agent.ACTIONS
assert "server-hostname-set" in server_agent.ACTIONS
assert server_agent._set_hostname("not a hostname")["error"] == "invalid-server-hostname"
assert server_agent._set_hostname("singlelabel")["error"] == "invalid-server-hostname"

with patch.object(server_agent.socket, "gethostname", return_value="old.example.com"), patch.object(
    server_agent, "_run", return_value=subprocess.CompletedProcess(["hostnamectl"], 0, "", "")
) as run_mock, patch.object(server_agent, "_overview", return_value={"ok": True, "hostname": "new.example.com"}):
    changed = server_agent._set_hostname("new.example.com")
assert changed["ok"] is True and changed["changed"] is True
assert changed["previous_hostname"] == "old.example.com"
run_mock.assert_called_once_with(["hostnamectl", "set-hostname", "new.example.com"], 30)

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
assert result["apply_supported"] is True

assert server_agent._updates_apply("bad")["error"] == "invalid-system-update-fingerprint"

before = {
    "ok": True,
    "count": 2,
    "packages": [{"name": "nginx", "version": "1.1"}, {"name": "openssl", "version": "3.1"}],
    "fingerprint": "a" * 64,
    "reboot_required": False,
    "generated_at": 1,
    "apply_supported": True,
}
after = {
    "ok": True,
    "count": 0,
    "packages": [],
    "fingerprint": "b" * 64,
    "reboot_required": True,
    "generated_at": 2,
    "apply_supported": True,
}
with patch.object(server_agent, "_updates_preview", side_effect=[before, after]), patch.object(
    server_agent, "_run", return_value=subprocess.CompletedProcess(["apt-get"], 0, "", "")
) as update_run:
    applied = server_agent._updates_apply("a" * 64)
assert applied["ok"] is True and applied["changed"] is True
assert applied["applied_count"] == 2 and applied["remaining_count"] == 0
assert applied["reboot_required"] is True
assert update_run.call_args.args[0][0] == "apt-get"
assert "upgrade" in update_run.call_args.args[0]

with patch.object(server_agent, "_updates_preview", return_value=before), patch.object(server_agent, "_run") as stale_run:
    stale = server_agent._updates_apply("c" * 64)
assert stale["ok"] is False and stale["error"] == "system-update-preview-stale"
stale_run.assert_not_called()

empty = dict(before, count=0, packages=[], fingerprint="d" * 64)
with patch.object(server_agent, "_updates_preview", return_value=empty), patch.object(server_agent, "_run") as empty_run:
    no_change = server_agent._updates_apply("d" * 64)
assert no_change["ok"] is True and no_change["changed"] is False and no_change["applied_count"] == 0
empty_run.assert_not_called()

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
