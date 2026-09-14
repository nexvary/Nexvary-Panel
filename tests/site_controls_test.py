from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-site-controls-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_site_controls as routes

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "site-controls-csrf"
    calls: list[dict] = []

    def fake_webtools(payload, timeout=0):
        calls.append(dict(payload))
        if payload.get("action") == "site-control-raw-access":
            return {"ok": True, "lines": ["203.0.113.10 - GET / HTTP/1.1 200"], "truncated": False}
        return {"ok": True}

    routes.webtools_call = fake_webtools

    features = [
        "files.directory_privacy",
        "security.hotlink",
        "advanced.indexes",
        "advanced.mime_types",
        "metrics.raw_access",
    ]
    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        package_id = int(core["id"])
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("client01", "operator", "11" * 16, "22" * 32, now),
        )
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)", ("client01", package_id, now))
        conn.execute(
            "INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",
            ("example.com", "static", "", None, "client01", now),
        )
        conn.execute(
            "INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",
            ("other.example.net", "static", "", None, "other", now),
        )
        for feature in features:
            conn.execute(
                "INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,1,?) ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=1,updated_at=excluded.updated_at",
                (package_id, feature, now),
            )

    with client.session_transaction() as sess:
        sess.update(auth=True, user="client01", role="operator", csrf=csrf)

    r = client.get("/api/site-controls?domain=example.com")
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert all(body["capabilities"].values()), body
    assert body["settings"]["indexing_mode"] == "off"

    # Ownership is enforced before any provider call.
    before = len(calls)
    r = client.get("/api/site-controls?domain=other.example.net")
    assert r.status_code in {400, 403}, r.data
    assert len(calls) == before

    # Writes require a fresh Step-Up session.
    r = client.put(
        "/api/site-controls/privacy",
        json={"domain":"example.com","enabled":True,"path":"/private/","username":"secureuser","password":"StrongPassword!2026"},
        headers={"X-CSRF-Token":csrf},
    )
    assert r.status_code == 428, r.data

    with client.session_transaction() as sess:
        sess["step_up_user"] = "client01"
        sess["step_up_until"] = now + 300

    r = client.put(
        "/api/site-controls/privacy",
        json={"domain":"example.com","enabled":True,"path":"/private/","username":"secureuser","password":"StrongPassword!2026"},
        headers={"X-CSRF-Token":csrf},
    )
    assert r.status_code == 200, r.data
    assert calls[-1]["action"] == "site-control-privacy"
    assert calls[-1]["password"] == "StrongPassword!2026"
    response_text = r.get_data(as_text=True)
    assert "StrongPassword!2026" not in response_text

    with db() as conn:
        row = conn.execute("SELECT privacy_enabled,privacy_path,privacy_username FROM site_web_controls WHERE domain='example.com'").fetchone()
        assert int(row["privacy_enabled"]) == 1 and row["privacy_path"] == "/private/" and row["privacy_username"] == "secureuser"
        columns = [item[1] for item in conn.execute("PRAGMA table_info(site_web_controls)").fetchall()]
        assert "password" not in " ".join(columns).lower()
        audits = "\n".join(str(x[0]) for x in conn.execute("SELECT detail FROM audit ORDER BY id").fetchall())
        assert "StrongPassword!2026" not in audits

    r = client.put(
        "/api/site-controls/hotlink",
        json={"domain":"example.com","enabled":True,"extensions":["jpg","png","webp"]},
        headers={"X-CSRF-Token":csrf},
    )
    assert r.status_code == 200 and calls[-1]["action"] == "site-control-hotlink", r.data

    r = client.put(
        "/api/site-controls/indexing",
        json={"domain":"example.com","mode":"on"},
        headers={"X-CSRF-Token":csrf},
    )
    assert r.status_code == 200 and calls[-1]["mode"] == "on", r.data

    r = client.put(
        "/api/site-controls/mime",
        json={"domain":"example.com","mappings":{"wasm":"application/wasm","avif":"image/avif"}},
        headers={"X-CSRF-Token":csrf},
    )
    assert r.status_code == 200 and calls[-1]["action"] == "site-control-mime", r.data

    before = len(calls)
    r = client.put(
        "/api/site-controls/mime",
        json={"domain":"example.com","mappings":{"php":"text/plain"}},
        headers={"X-CSRF-Token":csrf},
    )
    assert r.status_code == 400 and len(calls) == before, r.data

    r = client.get("/api/site-controls/raw-access?domain=example.com&lines=100")
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["lines"] and "203.0.113.10" in body["lines"][0]
    assert "client IP" in body["privacy_notice"]

    # Package Feature Manager is executable: disabling hotlink blocks the provider call.
    with db() as conn:
        conn.execute(
            "UPDATE hosting_package_features SET enabled=0,updated_at=? WHERE package_id=? AND feature_id='security.hotlink'",
            (now, package_id),
        )
    before = len(calls)
    r = client.put(
        "/api/site-controls/hotlink",
        json={"domain":"example.com","enabled":False,"extensions":["jpg"]},
        headers={"X-CSRF-Token":csrf},
    )
    assert r.status_code == 403 and len(calls) == before, r.data

print("NEXVARY Site Control Center policy, Step-Up, ownership and secret-handling gate: PASS")
