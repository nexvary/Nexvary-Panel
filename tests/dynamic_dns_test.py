from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-ddns-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db
    import panel.routes_dynamic_dns as routes_dynamic_dns

    app = create_app()
    app.testing = True
    client = app.test_client()
    now = int(time.time())
    csrf = "ddns-csrf"
    calls: list[dict] = []

    def fake_ops(payload, timeout=0):
        calls.append(dict(payload))
        if payload.get("action") == "dns-apply":
            operation = payload.get("operation")
            return {
                "ok": True,
                "provider_record_id": payload.get("provider_record_id") or "cf-ddns-1",
                "snapshot": {"operation": operation, "created_id": "cf-ddns-1" if operation == "create" else "", "records": []},
            }
        if payload.get("action") == "dns-rollback":
            return {"ok": True, "restored": 1}
        return {"ok": False, "error": "unexpected action"}

    routes_dynamic_dns.ops_call = fake_ops

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        core_id = int(core["id"])
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ("client01", "operator", "11" * 16, "22" * 32, now),
        )
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)", ("client01", core_id, now))
        conn.execute(
            "INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",
            ("example.com", "static", "", None, "client01", now),
        )
        cur = conn.execute(
            """INSERT INTO integration_targets
               (name,provider,capability,endpoint,secret_kind,secret_id,enabled,owner,created_at,updated_at)
               VALUES(?,?,?,?,?,?,1,?,?,?)""",
            ("cf-zone", "cloudflare", "dns", "https://api.cloudflare.com/client/v4/zones/zone12345678", "cloudflare", "cf-secret", "admin", now, now),
        )
        target_id = int(cur.lastrowid)
        conn.execute(
            "INSERT INTO dns_zone_bindings(domain,target_id,owner,updated_at) VALUES(?,?,?,?)",
            ("example.com", target_id, "client01", now),
        )

    with client.session_transaction() as sess:
        sess.update(auth=True, user="client01", role="operator", csrf=csrf, step_up_user="client01", step_up_until=now + 300)

    # Private and non-matching addresses are rejected before the provider boundary.
    before = len(calls)
    r = client.post(
        "/api/dynamic-dns/records",
        json={"domain": "example.com", "hostname": "home", "record_type": "A", "address": "192.168.1.10", "ttl": 300},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 400, r.data
    assert len(calls) == before

    r = client.post(
        "/api/dynamic-dns/records",
        json={"domain": "example.com", "hostname": "home", "record_type": "A", "address": "8.8.8.8", "ttl": 300},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 201, r.data
    created = r.get_json()
    token = created["token"]
    record_id = int(created["id"])
    assert token.startswith("nvp_ddns_") and created["shown_once"] is True
    assert calls[-1]["action"] == "dns-apply" and calls[-1]["operation"] == "create"
    assert calls[-1]["record_name"] == "home.example.com"

    with db() as conn:
        row = conn.execute("SELECT token_hash,provider_record_id,last_address FROM dynamic_dns_records WHERE id=?", (record_id,)).fetchone()
        assert row and row["provider_record_id"] == "cf-ddns-1" and row["last_address"] == "8.8.8.8"
        assert token not in str(row["token_hash"])
        conn.execute("UPDATE dynamic_dns_records SET last_update=? WHERE id=?", (now - 30, record_id))

    # Listing never returns token material.
    r = client.get("/api/dynamic-dns/records?domain=example.com")
    assert r.status_code == 200, r.data
    listed = r.get_json()["records"][0]
    assert "token" not in listed and "token_hash" not in listed

    # Machine updates use only the record-scoped bearer token; no browser CSRF/session is required.
    anonymous = app.test_client()
    r = anonymous.post(
        f"/api/dynamic-dns/update/{record_id}",
        json={"address": "1.1.1.1"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.data
    assert r.get_json()["changed"] is True
    assert calls[-1]["operation"] == "update" and calls[-1]["provider_record_id"] == "cf-ddns-1"

    # Rate limiting happens before another provider write.
    before = len(calls)
    r = anonymous.post(
        f"/api/dynamic-dns/update/{record_id}",
        json={"address": "9.9.9.9"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 429, r.data
    assert len(calls) == before

    # Wrong tokens and private addresses cannot reach the provider.
    with db() as conn:
        conn.execute("UPDATE dynamic_dns_records SET last_update=? WHERE id=?", (now - 30, record_id))
    before = len(calls)
    r = anonymous.post(
        f"/api/dynamic-dns/update/{record_id}",
        json={"address": "9.9.9.9"},
        headers={"Authorization": "Bearer nvp_ddns_" + "x" * 43},
    )
    assert r.status_code == 401, r.data
    r = anonymous.post(
        f"/api/dynamic-dns/update/{record_id}",
        json={"address": "10.0.0.5"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 400, r.data
    assert len(calls) == before

    # Same-address refresh updates metadata without an external DNS call.
    with db() as conn:
        conn.execute("UPDATE dynamic_dns_records SET last_update=? WHERE id=?", (now - 30, record_id))
    before = len(calls)
    r = anonymous.post(
        f"/api/dynamic-dns/update/{record_id}",
        json={"address": "1.1.1.1"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200 and r.get_json()["changed"] is False, r.data
    assert len(calls) == before

    # Token rotation revokes the old machine credential immediately.
    r = client.post(f"/api/dynamic-dns/records/{record_id}/rotate-token", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.data
    new_token = r.get_json()["token"]
    assert new_token != token
    with db() as conn:
        conn.execute("UPDATE dynamic_dns_records SET last_update=? WHERE id=?", (now - 30, record_id))
    r = anonymous.post(
        f"/api/dynamic-dns/update/{record_id}",
        json={"address": "9.9.9.9"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401, r.data

    # Hosting Feature Manager can revoke Dynamic DNS without deleting the record.
    with db() as conn:
        conn.execute(
            "INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,0,?) "
            "ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=0,updated_at=excluded.updated_at",
            (core_id, "domains.dynamic_dns", now),
        )
        conn.execute("UPDATE dynamic_dns_records SET last_update=? WHERE id=?", (now - 30, record_id))
    before = len(calls)
    r = anonymous.post(
        f"/api/dynamic-dns/update/{record_id}",
        json={"address": "9.9.9.9"},
        headers={"Authorization": f"Bearer {new_token}"},
    )
    assert r.status_code == 403, r.data
    assert len(calls) == before

    with db() as conn:
        conn.execute(
            "UPDATE hosting_package_features SET enabled=1,updated_at=? WHERE package_id=? AND feature_id='domains.dynamic_dns'",
            (now, core_id),
        )
    r = client.delete(f"/api/dynamic-dns/records/{record_id}", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.data
    assert calls[-1]["operation"] == "delete"

    # Raw DDNS credentials never enter audit details.
    with db() as conn:
        details = "\n".join(str(row[0] or "") for row in conn.execute("SELECT detail FROM audit").fetchall())
        assert "nvp_ddns_" not in details

print("Nexvary Panel Dynamic DNS scoped-token, policy and provider gate: PASS")
