from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

import postgres_agent as agent

readonly = agent._profile_sql("app_db", "report_user", "owner_user", "readonly")
assert readonly.startswith("BEGIN;") and readonly.rstrip().endswith("COMMIT;")
assert 'GRANT CONNECT ON DATABASE "app_db" TO "report_user";' in readonly
assert 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO "report_user";' in readonly
assert 'GRANT USAGE,CREATE ON SCHEMA public' not in readonly

developer = agent._profile_sql("app_db", "dev_user", "owner_user", "developer")
assert 'GRANT USAGE,CREATE ON SCHEMA public TO "dev_user";' in developer
assert "SUPERUSER" not in developer and "CREATEDB" not in developer and "CREATEROLE" not in developer

try:
    agent._profile_sql("app_db", "dev_user", "owner_user", "superuser")
    raise AssertionError("unsafe grant profile accepted")
except ValueError:
    pass

calls: list[tuple[list[str], str | None]] = []
agent._available = lambda: True
agent._exists = lambda kind, value: False

def fake_run(args, timeout=30, stdin=None):
    calls.append((list(args), stdin))
    return subprocess.CompletedProcess(args, 0, "", "")

agent._run = fake_run
created = agent._role_create({"username": "safe_role", "password": "StrongPgPass-2026!"})
assert created["ok"] is True
sql = calls[-1][1] or ""
for required in ("NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", "NOREPLICATION", "NOBYPASSRLS"):
    assert required in sql
assert "StrongPgPass-2026!" in sql

calls.clear()
agent._exists = lambda kind, value: True
agent._database_owner = lambda name: "owner_user"
profile = agent._grant_profile({"db_name": "app_db", "username": "safe_role", "profile": "readwrite"})
assert profile == {"ok": True, "db_name": "app_db", "username": "safe_role", "profile": "readwrite"}
assert len(calls) == 1, calls
args, sql = calls[0]
assert args[-1] == "app_db"
assert sql and sql.startswith("BEGIN;") and sql.rstrip().endswith("COMMIT;")
assert 'GRANT CONNECT,TEMPORARY ON DATABASE "app_db" TO "safe_role";' in sql
assert "SUPERUSER" not in sql and "CREATEDB" not in sql and "CREATEROLE" not in sql

assert agent._dispatch({"action": "raw-sql", "sql": "ALTER ROLE x SUPERUSER"})["error"] == "postgres-action-not-allowed"
print("Nexvary Panel PostgreSQL access agent safety gate: PASS")
