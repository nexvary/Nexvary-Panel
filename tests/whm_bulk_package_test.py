from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-whm-bulk-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db

    app = create_app(); app.testing = True
    client = app.test_client(); now = int(time.time()); csrf = "bulk-csrf"
    with db() as conn:
        core = conn.execute("SELECT * FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        core_id = int(core["id"])
        cur = conn.execute(
            """INSERT INTO hosting_packages(name,description,disk_mb,bandwidth_mb,max_sites,max_databases,max_mailboxes,max_ftp_accounts,max_cron_jobs,max_subdomains,max_backups,enabled,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("NEXVARY Bulk Tiny","Bulk safety target",1024,10240,1,5,5,5,5,5,5,1,now,now),
        )
        tiny_id = int(cur.lastrowid)
        for username, domain in (("bulkone","one.example.test"),("bulktwo","two.example.test")):
            conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)", (username,"operator","11"*16,"22"*32,now))
            conn.execute("INSERT INTO hosting_accounts(username,reseller_owner,primary_domain,package_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", (username,"admin",domain,core_id,"active",now,now))
            conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)", (username,core_id,now))
        conn.execute("INSERT INTO sites(domain,kind,target,enabled,owner,created_at) VALUES(?,?,?,?,?,?)", ("a.two.example.test","php","",1,"bulktwo",now))
        conn.execute("INSERT INTO sites(domain,kind,target,enabled,owner,created_at) VALUES(?,?,?,?,?,?)", ("b.two.example.test","php","",1,"bulktwo",now))

    with client.session_transaction() as s:
        s.update(auth=True,user="admin",role="admin",csrf=csrf)

    payload={"usernames":["bulkone","bulktwo"],"package_id":tiny_id}
    preview=client.post("/api/whm/bulk/package-preview",json=payload,headers={"X-CSRF-Token":csrf})
    assert preview.status_code==200,preview.data
    body=preview.get_json()["preview"]
    assert body["safe_to_apply"] is False
    assert any(x["username"]=="bulktwo" and x["limits"]["max_sites"]["over"] for x in body["blocked"])

    no_step=client.post("/api/whm/bulk/package-assign",json=payload,headers={"X-CSRF-Token":csrf})
    assert no_step.status_code==428
    with client.session_transaction() as s:
        s["step_up_user"]="admin";s["step_up_until"]=now+600
    blocked=client.post("/api/whm/bulk/package-assign",json=payload,headers={"X-CSRF-Token":csrf})
    assert blocked.status_code==409,blocked.data
    with db() as conn:
        assert {int(r[0]) for r in conn.execute("SELECT package_id FROM user_hosting_package WHERE username IN ('bulkone','bulktwo')").fetchall()}=={core_id}
        conn.execute("DELETE FROM sites WHERE domain='b.two.example.test'")

    applied=client.post("/api/whm/bulk/package-assign",json=payload,headers={"X-CSRF-Token":csrf})
    assert applied.status_code==200,applied.data
    assert applied.get_json()["applied"]==2
    with db() as conn:
        assert {int(r[0]) for r in conn.execute("SELECT package_id FROM user_hosting_package WHERE username IN ('bulkone','bulktwo')").fetchall()}=={tiny_id}
        assert {int(r[0]) for r in conn.execute("SELECT package_id FROM hosting_accounts WHERE username IN ('bulkone','bulktwo')").fetchall()}=={tiny_id}
        audit=conn.execute("SELECT detail FROM audit WHERE action='whm-bulk-package-assign' ORDER BY id DESC LIMIT 1").fetchone()
        assert audit and "count=2" in str(audit[0])

    dup=client.post("/api/whm/bulk/package-preview",json={"usernames":["bulkone","bulkone"],"package_id":tiny_id},headers={"X-CSRF-Token":csrf})
    assert dup.status_code==400

    with client.session_transaction() as s:
        s.update(auth=True,user="bulkone",role="operator",csrf=csrf,step_up_user="bulkone",step_up_until=now+600)
    denied=client.post("/api/whm/bulk/package-preview",json={"usernames":["bulkone"],"package_id":tiny_id},headers={"X-CSRF-Token":csrf})
    assert denied.status_code==403

print("Nexvary Panel WHM bulk package atomicity gate: PASS")
