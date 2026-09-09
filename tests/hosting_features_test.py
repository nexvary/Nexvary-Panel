import os
import pathlib
import re
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-hosting-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db
    from panel.hosting_features import FEATURES, feature_catalog, maturity_summary

    assert len(FEATURES) >= 90, len(FEATURES)
    assert len(FEATURES) == len(set(FEATURES))
    assert all(re.fullmatch(r"[a-z0-9_]+\.[a-z0-9_]+", key) for key in FEATURES)
    assert all(item.scope in {"account", "server"} for item in FEATURES.values())
    assert all(item.maturity in {"native", "foundation", "planned"} for item in FEATURES.values())
    assert all(item.risk == "privileged" for item in FEATURES.values() if item.scope == "server" and item.feature_id not in {"whm.system_health", "whm.service_status", "whm.logs", "whm.disk_usage"})
    summary = maturity_summary()
    assert sum(summary.values()) == len(FEATURES)
    assert summary["native"] > 10
    assert summary["foundation"] > 20
    assert summary["planned"] > 20
    assert len(feature_catalog("account")) > 50
    assert len(feature_catalog("server")) > 25

    app = create_app()
    app.testing = True
    client = app.test_client()
    csrf = "hosting-test-csrf-token"
    with client.session_transaction() as sess:
        sess.update(
            auth=True,
            user="admin",
            role="admin",
            csrf=csrf,
            step_up_user="admin",
            step_up_until=int(time.time()) + 300,
        )

    r = client.get("/api/hosting/catalog")
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["ok"] is True
    assert body["package"]["name"] == "NEXVARY Unlimited"
    assert len(body["catalog"]) == len(FEATURES)
    assert any(row["feature_id"] == "email.accounts" for row in body["catalog"])
    assert next(row for row in body["catalog"] if row["feature_id"] == "email.mailing_lists")["operational"] is False

    r = client.get("/api/hosting/packages")
    assert r.status_code == 200
    packages = r.get_json()["packages"]
    assert {p["name"] for p in packages} >= {"NEXVARY Core", "NEXVARY Unlimited"}

    payload = {
        "name": "NEXVARY Business",
        "description": "Business hosting package",
        "disk_mb": 20480,
        "bandwidth_mb": 204800,
        "max_sites": 20,
        "max_databases": 20,
        "max_mailboxes": 50,
        "max_ftp_accounts": 10,
        "max_cron_jobs": 20,
        "max_subdomains": 50,
        "max_backups": 30,
        "enabled": True,
    }
    r = client.post("/api/hosting/packages", json=payload, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 201, r.data
    package_id = r.get_json()["id"]

    r = client.put(
        f"/api/hosting/packages/{package_id}/features/email.accounts",
        json={"enabled": True},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.data
    r = client.put(
        f"/api/hosting/packages/{package_id}/features/whm.reboot",
        json={"enabled": False},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.data
    r = client.put(
        f"/api/hosting/packages/{package_id}/features/not.real",
        json={"enabled": True},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 404

    with db() as conn:
        now = int(time.time())
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,?,?)",
            ("client01", "viewer", "00" * 16, "00" * 32, 1, now),
        )

    r = client.put(
        "/api/hosting/users/client01/package",
        json={"package_id": package_id},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.data
    with db() as conn:
        assigned = conn.execute("SELECT package_id FROM user_hosting_package WHERE username='client01'").fetchone()
        assert assigned and int(assigned["package_id"]) == package_id
        audit_rows = conn.execute("SELECT action,detail FROM audit ORDER BY id").fetchall()
        assert any(row["action"] == "hosting-package-create" for row in audit_rows)
        assert any(row["action"] == "hosting-feature-policy" for row in audit_rows)
        assert any(row["action"] == "hosting-package-assign" for row in audit_rows)

    bad = dict(payload)
    bad["name"] = "Bad Range"
    bad["disk_mb"] = -1
    r = client.post("/api/hosting/packages", json=bad, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 400

    with client.session_transaction() as sess:
        sess["step_up_until"] = 0
    r = client.post("/api/hosting/packages", json=payload, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 428

print("Nexvary Panel Hosting Suite registry/package/quota/security tests: PASS")
