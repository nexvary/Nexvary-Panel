from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))

with tempfile.TemporaryDirectory(prefix="nvp-mail-trace-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_mail_queue as trace_routes
    import mail_agent

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "mail-trace-csrf"

    with db() as conn:
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("trace01", "operator", "00" * 16, "00" * 32, now),
        )
        conn.execute(
            "INSERT INTO sites(domain,kind,target,enabled,owner,created_at) VALUES(?,?,?,1,?,?)",
            ("trace.example.com", "static", "", "trace01", now),
        )
        conn.execute(
            "INSERT INTO sites(domain,kind,target,enabled,owner,created_at) VALUES(?,?,?,1,?,?)",
            ("private.example.net", "static", "", "other01", now),
        )

    calls: list[dict] = []

    def fake_mail_call(payload: dict, timeout: int = 0):
        calls.append({"payload": dict(payload), "timeout": timeout})
        return {
            "ok": True,
            "domain": payload["domain"],
            "source": "mail.log",
            "count": 1,
            "events": [{
                "queue_id": "ABCD123",
                "component": "smtp",
                "timestamp": "2026-09-14T10:00:00+00:00",
                "sender": "sender@example.net",
                "recipient": "info@trace.example.com",
                "status": "sent",
                "dsn": "2.0.0",
                "relay": "mx.example.net[203.0.113.10]:25",
                "detail": "250 message accepted",
            }],
        }

    trace_routes.mail_call = fake_mail_call

    with client.session_transaction() as session:
        session.update(auth=True, user="trace01", role="operator", csrf=csrf)

    response = client.get("/api/mail/trace?domain=trace.example.com&limit=25")
    assert response.status_code == 200, response.data
    body = response.get_json()
    assert body["ok"] is True and body["count"] == 1
    assert body["events"][0]["queue_id"] == "ABCD123"
    assert calls == [{"payload": {"action": "delivery-trace", "domain": "trace.example.com", "limit": 25}, "timeout": 12}]

    outside = client.get("/api/mail/trace?domain=private.example.net")
    assert outside.status_code == 403
    assert len(calls) == 1

    bad_limit = client.get("/api/mail/trace?domain=trace.example.com&limit=oops")
    assert bad_limit.status_code == 400

    with db() as conn:
        package_id = int(conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()[0])
        conn.execute(
            "INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,0,?)",
            (package_id, "email.delivery_trace", now),
        )
    disabled = client.get("/api/mail/trace?domain=trace.example.com")
    assert disabled.status_code == 403
    assert len(calls) == 1

    synthetic = [
        "2026-09-14T09:59:58+00:00 host postfix/qmgr[101]: ABCD123: from=<sender@example.net>, size=1200, nrcpt=1 (queue active)",
        "2026-09-14T10:00:00+00:00 host postfix/smtp[102]: ABCD123: to=<info@trace.example.com>, relay=mx.remote.net[198.51.100.9]:25, dsn=2.0.0, status=sent (250 message accepted)",
        "2026-09-14T10:01:00+00:00 host postfix/qmgr[101]: ZZZ999: from=<hidden@private.example.net>, size=400, nrcpt=1 (queue active)",
        "2026-09-14T10:01:01+00:00 host postfix/smtp[102]: ZZZ999: to=<elsewhere@example.org>, relay=mx.example.org[198.51.100.8]:25, dsn=2.0.0, status=sent (250 hidden event)",
    ]
    original_reader = mail_agent._mail_log_lines
    try:
        mail_agent._mail_log_lines = lambda: ("synthetic", synthetic)
        traced = mail_agent._delivery_trace("trace.example.com", 50)
    finally:
        mail_agent._mail_log_lines = original_reader

    assert traced["ok"] is True and traced["source"] == "synthetic"
    assert traced["count"] == 2
    assert {event["queue_id"] for event in traced["events"]} == {"ABCD123"}
    assert all("raw" not in event for event in traced["events"])
    assert all("private.example.net" not in str(event) for event in traced["events"])
    delivery = next(event for event in traced["events"] if event["recipient"])
    assert delivery["recipient"] == "info@trace.example.com"
    assert delivery["status"] == "sent" and delivery["dsn"] == "2.0.0"

print("Nexvary Panel tenant-scoped Mail Track Delivery gate: PASS")
