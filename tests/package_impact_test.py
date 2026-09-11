from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

with tempfile.TemporaryDirectory(prefix='nvp-package-impact-') as tmp:
    os.environ['NVP_DATA_DIR']=tmp
    os.environ['NVP_DB_PATH']=str(pathlib.Path(tmp)/'panel.db')
    os.environ['NVP_COOKIE_SECURE']='0'

    from panel import create_app
    from panel.db_layer import db

    app=create_app();app.testing=True;client=app.test_client();now=int(time.time());csrf='impact-csrf'
    with db() as conn:
        conn.execute(
            "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
            ('client1','operator','77'*16,'77'*32,now),
        )
        core_id=int(conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()[0])
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)",('client1',core_id,now))
        conn.execute("INSERT INTO sites(domain,kind,target,enabled,owner,created_at) VALUES(?,?,?,?,?,?)",('one.example.test','php','',1,'client1',now))
        conn.execute("INSERT INTO sites(domain,kind,target,enabled,owner,created_at) VALUES(?,?,?,?,?,?)",('two.example.test','php','',1,'client1',now))
        cur=conn.execute(
            """INSERT INTO hosting_packages(name,description,disk_mb,bandwidth_mb,max_sites,max_databases,max_mailboxes,max_ftp_accounts,max_cron_jobs,max_subdomains,max_backups,enabled,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ('NEXVARY Tiny','Impact simulation target',1024,10240,1,1,1,1,1,1,1,1,now,now),
        )
        tiny_id=int(cur.lastrowid)
        conn.execute(
            "INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,0,?)",
            (tiny_id,'software.wordpress',now),
        )

    with client.session_transaction() as s:
        s.update(auth=True,user='admin',role='admin',csrf=csrf,step_up_user='admin',step_up_until=now+300)

    preview=client.post(
        '/api/hosting/package-impact',
        json={'username':'client1','package_id':tiny_id},
        headers={'X-CSRF-Token':csrf},
    )
    assert preview.status_code==200,preview.data
    impact=preview.get_json()['impact']
    assert impact['current_package']['name']=='NEXVARY Core'
    assert impact['target_package']['name']=='NEXVARY Tiny'
    assert impact['safe_to_assign'] is False
    assert impact['limits']['max_sites']=={'used':2,'target':1,'over':True,'measured':True}
    assert any(v['limit']=='max_sites' and v['excess']==1 for v in impact['violations'])
    assert 'software.wordpress' in impact['removed_features']
    assert set(impact['unmeasured'])=={'disk_mb','bandwidth_mb'}

    blocked=client.put(
        '/api/hosting/users/client1/package',
        json={'package_id':tiny_id},
        headers={'X-CSRF-Token':csrf},
    )
    assert blocked.status_code==409,blocked.data
    assert blocked.get_json()['impact']['safe_to_assign'] is False
    with db() as conn:
        assigned=int(conn.execute("SELECT package_id FROM user_hosting_package WHERE username='client1'").fetchone()[0])
        assert assigned==core_id
        conn.execute("DELETE FROM sites WHERE domain='two.example.test'")

    safe=client.post(
        '/api/hosting/package-impact',
        json={'username':'client1','package_id':tiny_id},
        headers={'X-CSRF-Token':csrf},
    )
    assert safe.status_code==200,safe.data
    assert safe.get_json()['impact']['safe_to_assign'] is True
    assigned=client.put(
        '/api/hosting/users/client1/package',
        json={'package_id':tiny_id},
        headers={'X-CSRF-Token':csrf},
    )
    assert assigned.status_code==200,assigned.data
    with db() as conn:
        current=int(conn.execute("SELECT package_id FROM user_hosting_package WHERE username='client1'").fetchone()[0])
        assert current==tiny_id
        audit=conn.execute("SELECT detail FROM audit WHERE action='hosting-package-assign' ORDER BY id DESC LIMIT 1").fetchone()
        assert audit and 'removed_features=' in str(audit['detail'])

print('NEXVARY package impact / safe downgrade gate: PASS')
