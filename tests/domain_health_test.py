from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-domain-health-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_OPS_SOCK"] = str(pathlib.Path(tmp) / "missing-ops.sock")

    from panel import create_app
    from panel.db_layer import db

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        pid = int(core["id"])
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("domainclient", "operator", "11" * 16, "22" * 32, now),
        )
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("otherclient", "operator", "33" * 16, "44" * 32, now),
        )
        conn.execute(
            "INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)",
            ("domainclient", pid, now),
        )
        conn.execute(
            "INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",
            ("ready.example.test", "php", "", None, "domainclient", now),
        )
        conn.execute(
            "INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",
            ("other.example.test", "php", "", None, "otherclient", now),
        )
        conn.execute(
            "INSERT INTO domain_aliases(domain,alias,owner,created_at,updated_at) VALUES(?,?,?,?,?)",
            ("ready.example.test", "www2.ready.example.test", "domainclient", now, now),
        )
        cur = conn.execute(
            """INSERT INTO integration_targets(name,provider,capability,endpoint,secret_kind,secret_id,enabled,owner,created_at,updated_at)
               VALUES(?,?,?,?,?,?,1,?,?,?)""",
            ("dns-main", "cloudflare", "dns", "https://api.cloudflare.com", "cloudflare_token", "secret-do-not-leak", "admin", now, now),
        )
        target_id = int(cur.lastrowid)
        conn.execute(
            "INSERT INTO dns_zone_bindings(domain,target_id,owner,updated_at) VALUES(?,?,?,?)",
            ("ready.example.test", target_id, "domainclient", now),
        )
        conn.execute(
            """INSERT INTO ssl_policies(domain,owner,contact_email,auto_renew,renew_before_days,last_check,last_renewal,last_status,last_detail,updated_at)
               VALUES(?,?,?,1,21,?,?,?,'',?)""",
            ("ready.example.test", "domainclient", "ops@example.test", now, now, "healthy", now),
        )
        conn.execute(
            "INSERT INTO mail_domains(domain,owner,enabled,created_at,updated_at) VALUES(?,?,1,?,?)",
            ("ready.example.test", "domainclient", now, now),
        )
        conn.execute(
            """INSERT INTO mailboxes(domain,localpart,quota_mb,enabled,owner,created_at,updated_at)
               VALUES(?,?,1024,1,?,?,?)""",
            ("ready.example.test", "admin", "domainclient", now, now),
        )

    with client.session_transaction() as session:
        session.update(auth=True, user="domainclient", role="operator", csrf="domain-health-csrf")

    response = client.get("/api/domain-health?domain=ready.example.test")
    assert response.status_code == 200, response.data
    readiness = response.get_json()["readiness"]
    assert readiness["score"] == 100, readiness
    assert readiness["grade"] == "A"
    assert readiness["domain_lifecycle"]["aliases"] == 1
    assert readiness["dns"]["provider"] == "cloudflare"
    assert readiness["dns"]["dnssec"]["supported_by_bound_provider"] is True
    assert readiness["ssl"]["auto_renew"] is True
    assert readiness["mail"]["mailboxes"] == 1
    raw = response.get_data(as_text=True)
    assert "secret-do-not-leak" not in raw
    assert "api.cloudflare.com" not in raw

    response = client.get("/api/domain-health?domain=other.example.test")
    assert response.status_code == 403, response.data

    response = client.get("/api/domain-health")
    assert response.status_code == 200, response.data
    body = response.get_json()
    assert body["count"] == 1
    assert body["domains"][0]["domain"] == "ready.example.test"

    with db() as conn:
        conn.execute(
            """INSERT INTO dns_changes(domain,target_id,operation,record_type,record_name,record_value,ttl,priority,provider_record_id,status,snapshot_json,owner,created_at,applied_at)
               VALUES(?,?,'create','A',?,'203.0.113.10',300,0,'','preview','',?,?,0)""",
            ("ready.example.test", target_id, "app.ready.example.test", "domainclient", now),
        )

    response = client.get("/api/domain-health?domain=ready.example.test")
    assert response.status_code == 200
    readiness = response.get_json()["readiness"]
    assert readiness["score"] < 100
    assert readiness["dns"]["pending_previews"] == 1
    assert any(x["id"] == "dns-preview-clean" for x in readiness["recommendations"])

    with db() as conn:
        conn.execute(
            """INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at)
               VALUES(?,?,0,?) ON CONFLICT(package_id,feature_id)
               DO UPDATE SET enabled=0,updated_at=excluded.updated_at""",
            (pid, "security.ssl_tls", now),
        )

    response = client.get("/api/domain-health?domain=ready.example.test")
    assert response.status_code == 200
    readiness = response.get_json()["readiness"]
    assert readiness["ssl"]["feature_enabled"] is False
    failed = {item["id"] for item in readiness["recommendations"]}
    assert {"ssl-entitlement", "ssl-automation"}.issubset(failed)

print("Nexvary Panel Domain Readiness gate: PASS")
