from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

import database_agent as agent

# Validation blocks privilege escalation and malformed identifiers/passwords.
try:
    agent._privileges(["SELECT", "SUPER"])
    raise AssertionError("SUPER privilege must be rejected")
except ValueError:
    pass
try:
    agent._identifier("bad-user;DROP")
    raise AssertionError("unsafe identifier must be rejected")
except ValueError:
    pass
try:
    agent._password("short")
    raise AssertionError("weak password must be rejected")
except ValueError:
    pass

calls: list[str] = []

def fake_exists(kind: str, name: str) -> bool:
    return True

# Simulate a failure after REVOKE and verify the last panel-known privileges are reapplied.
def fake_run(sql: str, timeout: int = 25):
    calls.append(sql)
    if sql.startswith("GRANT SELECT, UPDATE"):
        return False, "rejected"
    return True, ""

agent._exists = fake_exists
agent._run = fake_run
result = agent.grant_replace({
    "db_name": "app_db",
    "username": "app_user",
    "privileges": ["SELECT", "UPDATE"],
    "previous_privileges": ["SELECT"],
})
assert result["ok"] is False
assert calls[0].startswith("REVOKE ALL PRIVILEGES ON `app_db`.*")
assert any(sql.startswith("GRANT SELECT ON `app_db`.*") for sql in calls), calls

# A successful replacement must use only the allow-listed privilege set.
calls.clear()
def good_run(sql: str, timeout: int = 25):
    calls.append(sql)
    return True, ""
agent._run = good_run
result = agent.grant_replace({
    "db_name": "app_db",
    "username": "app_user",
    "privileges": ["SELECT", "INSERT", "UPDATE"],
    "previous_privileges": ["SELECT"],
})
assert result["ok"] is True
assert result["privileges"] == ["SELECT", "INSERT", "UPDATE"]
assert calls[-1].startswith("GRANT SELECT, INSERT, UPDATE ON `app_db`.*")

assert agent.dispatch({"action": "raw-sql", "sql": "DROP DATABASE x"})["error"] == "database-action-not-allowed"
print("Nexvary Panel MariaDB access agent safety gate: PASS")
