from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-domain-guardian-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_OPS_SOCK"] = str(pathlib.Path(tmp) / "missing-ops.sock")

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_domain_guardian as guardian

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "guardian-csrf"

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        pid = int(core["id"])
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)", ("guardianclient", "operator", "10" * 16, "20" * 32, now))
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)", ("otherguardian", "operator", "30" * 16, "40" * 32, now))
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)", ("guardianclient", pid, now))
        for feature_id in ("security.ssl_tls", "email.deliverability", "email.accounts", "domains.domains", "domains.zone_editor"):
            conn.execute("INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,1,?) ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=1,updated_at=excluded.updated_at", (pid, feature_id, now))
        conn.execute("INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)", ("guardian.example.test", "php", "", None, "guardianclient", now))
        conn.execute("INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)", ("other.example.test", "php", "", None, "otherguardian", now))
        conn.execute("INSERT INTO mail_domains(domain,owner,enabled,created_at,updated_at) VALUES(?,?,1,?,?)", ("guardian.example.test", "guardianclient", now, now))
        cur = conn.execute("INSERT INTO integration_targets(name,provider,capability,endpoint,secret_kind,secret_id,enabled,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,1,'admin',?,?)", ("guardian-dns", "cloudflare", "authoritative-dns", "https://api.cloudflare.com/client/v4/zones/guardian", "cloudflare", "fixture-id", now, now))
        target_id = int(cur.lastrowid)
        conn.execute("INSERT INTO dns_zone_bindings(domain,target_id,owner,updated_at) VALUES(?,?,?,?)", ("guardian.example.test", target_id, "guardianclient", now))

    fake_health = {
        "domain": "guardian.example.test", "selector": "default", "score": 0, "grade": "F",
        "checks": {"mx": [], "spf": [], "dmarc": [], "dmarc_policy": "", "dkim": [], "mta_sts": [], "tls_rpt": [], "mail_host": "mail.guardian.example.test", "mail_host_a": []},
        "recommendations": [
            {"id": "mx", "severity": "critical", "message": "missing MX"}, {"id": "spf", "severity": "critical", "message": "missing SPF"},
            {"id": "dmarc", "severity": "warning", "message": "missing DMARC"}, {"id": "dkim", "severity": "warning", "message": "missing DKIM"},
            {"id": "mta-sts", "severity": "info", "message": "missing MTA-STS"}, {"id": "tls-rpt", "severity": "info", "message": "missing TLS-RPT"},
        ],
    }
    guardian.build_deliverability_health = lambda domain, selector: dict(fake_health, domain=domain, selector=selector)

    with client.session_transaction() as sess:
        sess.update(auth=True, user="guardianclient", role="operator", csrf=csrf)

    response = client.get("/api/domain-guardian?domain=guardian.example.test&live=1&selector=default")
    assert response.status_code == 200, response.data
    body = response.get_json()["guardian"]
    plan_ids = {item["id"] for item in body["plan"]}
    assert {"enable-autossl", "prepare-mail-dns", "publish-dkim"}.issubset(plan_ids), body
    assert body["safe_prepare_count"] == 2 and body["deliverability"]["score"] == 0
    assert "fixture-id" not in response.get_data(as_text=True)

    payload = {"domain": "guardian.example.test", "selector": "default", "contact_email": "ops@guardian.example.test", "mail_host": "mail.guardian.example.test", "mail_ipv4": "93.184.216.34"}
    response = client.post("/api/domain-guardian/prepare", json=payload, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 428, response.data

    with client.session_transaction() as sess:
        sess["step_up_user"] = "guardianclient"
        sess["step_up_until"] = now + 300

    response = client.post("/api/domain-guardian/prepare", json=payload, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200, response.data
    result = response.get_json()
    assert {item["id"] for item in result["prepared"]} == {"enable-autossl", "prepare-mail-dns"}, result
    assert all(item["external_change"] is False for item in result["prepared"])
    assert "No external DNS record was applied" in result["safety_note"]

    with db() as conn:
        policy = conn.execute("SELECT auto_renew,contact_email,last_status FROM ssl_policies WHERE domain=?", ("guardian.example.test",)).fetchone()
        assert policy and int(policy["auto_renew"]) == 1 and policy["last_status"] == "pending"
        rows = conn.execute("SELECT record_type,status FROM dns_changes WHERE domain=? ORDER BY id", ("guardian.example.test",)).fetchall()
        assert len(rows) == 5 and all(row["status"] == "preview" for row in rows)

    response = client.post("/api/domain-guardian/prepare", json=payload, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200, response.data
    with db() as conn:
        assert int(conn.execute("SELECT COUNT(*) FROM dns_changes WHERE domain=?", ("guardian.example.test",)).fetchone()[0]) == 5
        assert int(conn.execute("SELECT COUNT(*) FROM ssl_policies WHERE domain=?", ("guardian.example.test",)).fetchone()[0]) == 1

    response = client.post("/api/domain-guardian/prepare", json=dict(payload, mail_ipv4="127.0.0.1"), headers={"X-CSRF-Token": csrf})
    assert response.status_code == 400, response.data
    response = client.get("/api/domain-guardian?domain=other.example.test&live=0")
    assert response.status_code == 403, response.data

print("NEXVARY Domain Guardian trust automation gate: PASS")
