import base64
import os
import pathlib
import sys
import tempfile
import time

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

# Minimal syntactically valid Ed25519 public-key payload for web-boundary tests.
blob=b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'+(b'A'*32)
PUB='ssh-ed25519 '+base64.b64encode(blob).decode()

with tempfile.TemporaryDirectory(prefix='nvp-transfer-policy-') as tmp:
    os.environ['NVP_DATA_DIR']=tmp
    os.environ['NVP_DB_PATH']=str(pathlib.Path(tmp)/'panel.db')
    os.environ['NVP_COOKIE_SECURE']='0'
    os.environ['NVP_TRANSFER_SOCK']=str(pathlib.Path(tmp)/'missing-transfer.sock')
    from panel import create_app
    from panel.db_layer import db
    app=create_app(); app.testing=True; client=app.test_client()
    csrf='transfer-policy-csrf'; now=int(time.time())
    with db() as conn:
        core=conn.execute("SELECT id,max_ftp_accounts FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        assert core and int(core['max_ftp_accounts'])>0
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",('transferclient','operator','33'*16,'33'*32,now))
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)",('transferclient',int(core['id']),now))
        conn.execute("INSERT INTO sites(domain,kind,target,enabled,owner,created_at) VALUES(?,?,?,?,?,?)",('transfer.example.com','static','',1,'transferclient',now))
    with client.session_transaction() as s:
        s.update(auth=True,user='transferclient',role='operator',csrf=csrf)
    r=client.get('/api/transfers'); assert r.status_code==200,r.data
    body=r.get_json(); assert body['provider']['online'] is False
    assert any(x['domain']=='transfer.example.com' and x['enabled'] for x in body['sites'])
    r=client.post('/api/transfers',json={'label':'deploy-key','domain':'transfer.example.com','public_key':PUB},headers={'X-CSRF-Token':csrf})
    assert r.status_code==428,r.data
    with client.session_transaction() as s:
        s['step_up_user']='transferclient'; s['step_up_until']=now+300
    r=client.post('/api/transfers',json={'label':'bad','domain':'outside.example.com','public_key':PUB},headers={'X-CSRF-Token':csrf})
    assert r.status_code==403,r.data
    with db() as conn:
        conn.execute("INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,0,?) ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=0,updated_at=excluded.updated_at",(int(core['id']),'files.ftp_accounts',now))
    r=client.get('/api/transfers'); body=r.get_json(); assert any(x['domain']=='transfer.example.com' and not x['enabled'] for x in body['sites'])
    r=client.post('/api/transfers',json={'label':'deploy-key','domain':'transfer.example.com','public_key':PUB},headers={'X-CSRF-Token':csrf})
    assert r.status_code==403,r.data
print('Nexvary Panel SFTP Transfer scope, quota, package-policy and Step-Up tests: PASS')
