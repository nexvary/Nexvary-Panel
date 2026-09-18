from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent import server_agent
from panel.privileged_policy import PRIVILEGED_OPERATIONS, operation_policy

required = {"capability", "step_up", "timeout", "risk", "pre_check", "post_check", "rollback", "audit"}
server_actions = set(server_agent.ACTIONS)
registered_server_actions = {name for name in PRIVILEGED_OPERATIONS if name.startswith("server-")}
assert registered_server_actions == server_actions, (registered_server_actions ^ server_actions)

for action, policy in PRIVILEGED_OPERATIONS.items():
    assert required <= set(policy), (action, required - set(policy))
    assert policy["risk"] in {"low", "medium", "high"}, action
    assert isinstance(policy["timeout"], int) and 1 <= policy["timeout"] <= 1900, action
    assert isinstance(policy["step_up"], bool), action
    assert str(policy["capability"]).strip(), action
    assert str(policy["pre_check"]).strip() and str(policy["post_check"]).strip(), action
    assert str(policy["rollback"]).strip() and str(policy["audit"]).strip(), action

for action in {"server-updates-apply", "server-time-enable-ntp", "server-hostname-set", "service-restart"}:
    assert operation_policy(action)["step_up"] is True, action

try:
    operation_policy("root-shell")
except KeyError as exc:
    assert str(exc).strip("'") == "privileged-operation-not-registered"
else:
    raise AssertionError("unknown privileged operation did not fail closed")

print("NEXVARY privileged operation policy registry gate: PASS")
