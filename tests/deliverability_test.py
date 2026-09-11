from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-deliverability-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"
    os.environ["NVP_OPS_SOCK"] = str(pathlib.Path(tmp) / "missing-ops.sock")

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_deliverability as deliverability

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "deliverability-csrf"

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        pid = int(core["id"])
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("mailclient", "operator", "77" * 16, "88" * 32, now),
        )
        conn.execute(
            "INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)",
            ("mailclient", pid, now),
        )
        conn.execute(
            "INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",
            ("mail.example.test", "php", "", None, "mailclient", now),
        )
        conn.execute(
            "INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",
            ("adminmail.example.test", "php", "", None, "admin", now),
        )
        conn.execute(
            "INSERT INTO integration_targets(name,provider,capability,endpoint,secret_kind,secret_id,enabled,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,1,'admin',?,?)",
            ("mail-zone", "cloudflare", "authoritative-dns", "https://api.cloudflare.com/client/v4/zones/abcdefgh", "cloudflare", "cf_mail_test", now, now),
        )
        target_id = int(conn.execute("SELECT id FROM integration_targets WHERE name='mail-zone'").fetchone()["id"])
        conn.execute(
            "INSERT INTO dns_zone_bindings(domain,target_id,owner,updated_at) VALUES(?,?,?,?)",
            ("mail.example.test", target_id, "mailclient", now),
        )

    fake_health = {
        "domain": "mail.example.test",
        "selector": "default",
        "score": 0,
        "grade": "F",
        "checks": {
            "mx": [],
            "spf": [],
            "dmarc": [],
            "dmarc_policy": "",
            "dkim": [],
            "mta_sts": [],
            "tls_rpt": [],
            "mail_host": "mail.mail.example.test",
            "mail_host_a": [],
        },
        "recommendations": [{"id": "mx", "severity": "critical", "message": "missing"}],
    }
    deliverability._health = lambda domain, selector: dict(fake_health, domain=domain, selector=selector)

    with client.session_transaction() as session:
        session.update(auth=True, user="mailclient", role="operator", csrf=csrf)

    response = client.get("/api/mail/deliverability/health?domain=mail.example.test&selector=default")
    assert response.status_code == 200, response.data
    body = response.get_json()
    assert body["score"] == 0 and body["grade"] == "F"

    payload = {
        "domain": "mail.example.test",
        "selector": "default",
        "mail_host": "smtp.mail.example.test",
        "mail_ipv4": "8.8.8.8",
    }
    response = client.post(
        "/api/mail/deliverability/prepare-dns",
        json=payload,
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 428, response.data

    with client.session_transaction() as session:
        session["step_up_user"] = "mailclient"
        session["step_up_until"] = now + 300

    response = client.post(
        "/api/mail/deliverability/prepare-dns",
        json=payload,
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200, response.data
    body = response.get_json()
    assert len(body["created"]) == 5, body
    assert body["reused_preview_ids"] == []
    assert "not changed" in body["note"].lower()

    with db() as conn:
        rows = conn.execute(
            "SELECT record_type,record_name,record_value,priority,status FROM dns_changes WHERE domain=? ORDER BY id",
            ("mail.example.test",),
        ).fetchall()
        assert len(rows) == 5
        assert all(row["status"] == "preview" for row in rows)
        kinds = [row["record_type"] for row in rows]
        assert kinds.count("TXT") == 3 and "MX" in kinds and "A" in kinds
        assert any(row["record_type"] == "MX" and int(row["priority"]) == 10 for row in rows)
        assert any(row["record_type"] == "TXT" and str(row["record_value"]).startswith("v=spf1") for row in rows)
        assert any(row["record_type"] == "TXT" and str(row["record_value"]).startswith("v=DMARC1") for row in rows)
        assert any(row["record_type"] == "TXT" and str(row["record_value"]).startswith("v=TLSRPTv1") for row in rows)
        assert not any(row["status"] == "applied" for row in rows)

    # Repeating the repair request must reuse identical preview rows rather than duplicate them.
    response = client.post(
        "/api/mail/deliverability/prepare-dns",
        json=payload,
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200, response.data
    body = response.get_json()
    assert body["created"] == [] and len(body["reused_preview_ids"]) == 5, body
    with db() as conn:
        assert int(conn.execute("SELECT COUNT(*) FROM dns_changes WHERE domain=?", ("mail.example.test",)).fetchone()[0]) == 5

    # Scope is enforced before diagnostics or repair preparation.
    response = client.get("/api/mail/deliverability/health?domain=adminmail.example.test")
    assert response.status_code == 403, response.data

    # Disabling Zone Editor blocks preparation even though deliverability diagnostics remain readable.
    with db() as conn:
        conn.execute(
            "INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,0,?) "
            "ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=0,updated_at=excluded.updated_at",
            (pid, "domains.zone_editor", now),
        )
    response = client.post(
        "/api/mail/deliverability/prepare-dns",
        json=payload,
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 403, response.data

print("Nexvary Panel mail deliverability repair gate: PASS")
