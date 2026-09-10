from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-autossl-") as tmp:
    db_path = Path(tmp) / "panel.db"
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(db_path)
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db

    create_app()

    spec = importlib.util.spec_from_file_location("nvp_autossl", ROOT / "agent" / "autossl_scheduler.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    mod.DB_PATH = db_path

    now = int(time.time())
    with db() as conn:
        conn.execute("INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",
                     ("example.com", "static", "", None, "admin", now))
        conn.execute("INSERT INTO ssl_policies(domain,owner,contact_email,auto_renew,renew_before_days,updated_at) VALUES(?,?,?,?,?,?)",
                     ("example.com", "admin", "admin@example.com", 1, 30, now))

    calls = []
    def missing_then_issue(payload, timeout=240):
        calls.append(dict(payload))
        if payload["action"] == "ssl-status":
            return {"ok": True, "installed": False, "domain": "example.com"}
        if payload["action"] == "ssl-issue":
            return {"ok": True, "installed": True, "detail": "issued"}
        raise AssertionError(payload)
    mod._ops = missing_then_issue
    assert mod.run_once() == 0
    assert [x["action"] for x in calls] == ["ssl-status", "ssl-issue"]
    with db() as conn:
        row = conn.execute("SELECT last_status,last_renewal FROM ssl_policies WHERE domain='example.com'").fetchone()
        assert row["last_status"] == "valid" and int(row["last_renewal"]) > 0
        conn.execute("UPDATE ssl_policies SET last_check=0,last_renewal=0")

    future = datetime.now(timezone.utc) + timedelta(days=80)
    detail = "notAfter=" + future.strftime("%b %d %H:%M:%S %Y GMT")
    calls.clear()
    mod._ops = lambda payload, timeout=240: calls.append(dict(payload)) or {"ok": True, "installed": True, "detail": detail}
    mod.run_once()
    assert [x["action"] for x in calls] == ["ssl-status"]

    expiring = datetime.now(timezone.utc) + timedelta(days=5)
    expiring_detail = "notAfter=" + expiring.strftime("%b %d %H:%M:%S %Y GMT")
    calls.clear()
    def expiring_then_renew(payload, timeout=240):
        calls.append(dict(payload))
        if payload["action"] == "ssl-status":
            return {"ok": True, "installed": True, "detail": expiring_detail}
        if payload["action"] == "ssl-renew":
            return {"ok": True, "detail": "renewed"}
        raise AssertionError(payload)
    with db() as conn:
        conn.execute("UPDATE ssl_policies SET last_check=0")
    mod._ops = expiring_then_renew
    mod.run_once()
    assert [x["action"] for x in calls] == ["ssl-status", "ssl-renew"]

print("Nexvary Panel AutoSSL policy scheduler gate: PASS")
