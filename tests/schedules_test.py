import datetime as dt
import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-schedules-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db

    app = create_app()
    app.testing = True
    client = app.test_client()
    csrf = "schedules-csrf"
    with client.session_transaction() as sess:
        sess.update(auth=True, user="admin", role="admin", csrf=csrf, step_up_user="admin", step_up_until=int(time.time()) + 300)

    now = int(time.time())
    with db() as conn:
        conn.execute(
            "INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES('example.com','static','',NULL,1,'admin',?)",
            (now,),
        )
        conn.execute(
            "INSERT INTO deployments(domain,repo_url,branch,target,status,detail,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
            ("example.com", "https://github.com/example/site.git", "main", "public", "ready", "", "admin", now, now),
        )
        conn.execute("UPDATE hosting_packages SET max_cron_jobs=1 WHERE name='NEXVARY Unlimited'")

    headers = {"X-CSRF-Token": csrf}
    payload = {
        "domain": "example.com",
        "task_type": "backup_site",
        "cadence": "hourly",
        "hour_utc": 0,
        "minute_utc": 15,
        "weekday_utc": 0,
        "enabled": True,
    }
    r = client.post("/api/schedules", json=payload, headers=headers)
    assert r.status_code == 201, r.data
    task_id = r.get_json()["id"]

    r = client.get("/api/schedules")
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["max_cron_jobs"] == 1
    assert len(body["tasks"]) == 1
    assert body["tasks"][0]["task_type"] == "backup_site"
    assert set(body["task_types"]) == {"backup_site", "git_deploy"}

    r = client.post("/api/schedules", json={**payload, "task_type": "git_deploy"}, headers=headers)
    assert r.status_code == 409, r.data
    assert "quota" in r.get_json()["error"]

    r = client.put(f"/api/schedules/{task_id}", json={"enabled": False}, headers=headers)
    assert r.status_code == 200, r.data
    with db() as conn:
        row = conn.execute("SELECT enabled FROM scheduled_tasks WHERE id=?", (task_id,)).fetchone()
        assert row and int(row["enabled"]) == 0

    r = client.post(f"/api/schedules/{task_id}/run", json={}, headers=headers)
    assert r.status_code == 200, r.data
    with db() as conn:
        row = conn.execute("SELECT run_requested,last_status FROM scheduled_tasks WHERE id=?", (task_id,)).fetchone()
        assert row and int(row["run_requested"]) == 1 and row["last_status"] == "queued"

    r = client.delete(f"/api/schedules/{task_id}", headers=headers)
    assert r.status_code == 200, r.data

    bad = dict(payload)
    bad["task_type"] = "shell"
    r = client.post("/api/schedules", json=bad, headers=headers)
    assert r.status_code == 400
    bad = dict(payload)
    bad["minute_utc"] = 99
    r = client.post("/api/schedules", json=bad, headers=headers)
    assert r.status_code == 400

    with client.session_transaction() as sess:
        sess["step_up_until"] = 0
    r = client.post("/api/schedules", json=payload, headers=headers)
    assert r.status_code == 428

    with client.session_transaction() as sess:
        sess["step_up_until"] = int(time.time()) + 300
    with db() as conn:
        pkg = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Unlimited'").fetchone()
        conn.execute(
            "INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,0,?)",
            (int(pkg["id"]), "advanced.cron", int(time.time())),
        )
    r = client.get("/api/schedules")
    assert r.status_code == 403

# Test scheduler timing without running privileged operations.
from agent.scheduler_agent import _due

base = dt.datetime(2026, 9, 9, 12, 20, tzinfo=dt.timezone.utc)
ts = int(base.timestamp())
row = {"enabled": 1, "run_requested": 0, "cadence": "hourly", "minute_utc": 15, "hour_utc": 0, "weekday_utc": 0, "last_run": 0}
assert _due(row, ts) is True
row["last_run"] = int(dt.datetime(2026, 9, 9, 12, 16, tzinfo=dt.timezone.utc).timestamp())
assert _due(row, ts) is False
row = {"enabled": 1, "run_requested": 0, "cadence": "daily", "minute_utc": 0, "hour_utc": 12, "weekday_utc": 0, "last_run": 0}
assert _due(row, ts) is True
row = {"enabled": 1, "run_requested": 0, "cadence": "weekly", "minute_utc": 0, "hour_utc": 12, "weekday_utc": base.weekday(), "last_run": 0}
assert _due(row, ts) is True
row["enabled"] = 0
assert _due(row, ts) is False
row["run_requested"] = 1
assert _due(row, ts) is True  # explicit Step-Up-protected Run Now overrides pause

print("Nexvary Panel Scheduled Tasks quota/Step-Up/allowlist/timing tests: PASS")
