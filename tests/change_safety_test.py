from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import time

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

with tempfile.TemporaryDirectory(prefix='nvp-change-safety-') as tmp:
    os.environ['NVP_DATA_DIR']=tmp
    os.environ['NVP_DB_PATH']=str(pathlib.Path(tmp)/'panel.db')
    os.environ['NVP_COOKIE_SECURE']='0'

    from panel import create_app
    from panel.db_layer import db

    app=create_app();app.testing=True;client=app.test_client();now=int(time.time());csrf='safety-csrf'
    with db() as conn:
        for username,role in [('alice','operator'),('bob','operator')]:
            conn.execute(
                "INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",
                (username,role,'66'*16,'66'*32,now),
            )
        conn.execute(
            "INSERT INTO dns_changes(domain,target_id,operation,record_type,record_name,record_value,ttl,priority,provider_record_id,status,snapshot_json,owner,created_at,applied_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ('alice.test',1,'create','A','www.alice.test','203.0.113.10',300,0,'','preview','','alice',now-50,0),
        )
        conn.execute(
            "INSERT INTO dns_changes(domain,target_id,operation,record_type,record_name,record_value,ttl,priority,provider_record_id,status,snapshot_json,owner,created_at,applied_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ('alice.test',1,'update','A','www.alice.test','203.0.113.11',300,0,'rec1','applied',json.dumps({'records':[{'id':'old'}]}),'alice',now-40,now-35),
        )
        conn.execute(
            "INSERT INTO dns_changes(domain,target_id,operation,record_type,record_name,record_value,ttl,priority,provider_record_id,status,snapshot_json,owner,created_at,applied_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ('bob.test',2,'delete','TXT','bob.test','old',300,0,'rec2','applied','','bob',now-30,now-25),
        )
        conn.execute(
            "INSERT INTO ssl_jobs(domain,action,contact_email,status,detail,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
            ('alice.test','renew','admin@alice.test','success','certificate renewed','alice',now-20,now-19),
        )
        conn.execute(
            "INSERT INTO migration_bundles(domain,archive,size_bytes,sha256,status,owner,created_at) VALUES(?,?,?,?,?,?,?)",
            ('alice.test','/var/backups/nexvary-panel/migrations/alice.tar.gz',100,'a'*64,'ready','alice',now-15),
        )
        conn.execute(
            "INSERT INTO doctor_remediations(check_name,service_name,before_ok,before_detail,after_ok,after_detail,status,actor,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            ('Service: nginx','nginx',0,'inactive',1,'active','verified','alice',now-10,now-9),
        )

    with client.session_transaction() as s:s.update(auth=True,user='admin',role='admin',csrf=csrf)
    r=client.get('/api/change-safety');assert r.status_code==200,r.data
    body=r.get_json();assert body['ok'] is True
    assert body['posture']['recent']==6
    assert body['posture']['attention']==1
    assert body['posture']['pending_previews']==1
    assert body['posture']['protected_changes']==3
    assert any(x['kind']=='dns' and x['safety']=='reversible' for x in body['events'])
    assert any(x['kind']=='migration' and x['safety']=='snapshot-ready' for x in body['events'])
    assert body['policy']['preview_before_mutation'] is True and body['policy']['rollback_preferred'] is True

    with client.session_transaction() as s:s.update(auth=True,user='alice',role='operator',csrf=csrf)
    r=client.get('/api/change-safety');assert r.status_code==200,r.data
    scoped=r.get_json();assert scoped['ok'] is True
    assert scoped['posture']['attention']==0
    assert scoped['posture']['pending_previews']==1
    assert all(x['owner']=='alice' for x in scoped['events'])
    assert not any(x.get('domain')=='bob.test' for x in scoped['events'])

print('NEXVARY Change Safety scope/reversibility gate: PASS')
