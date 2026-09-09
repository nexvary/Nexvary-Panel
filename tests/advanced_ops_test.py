import os
import pathlib
import sys
import tempfile
import time

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

with tempfile.TemporaryDirectory(prefix='nvp-advanced-ops-') as tmp:
    os.environ['NVP_DATA_DIR']=tmp
    os.environ['NVP_DB_PATH']=str(pathlib.Path(tmp)/'panel.db')
    os.environ['NVP_COOKIE_SECURE']='0'
    os.environ['NVP_OPS_SOCK']=str(pathlib.Path(tmp)/'missing-ops.sock')
    from panel import create_app
    from panel.db_layer import db
    import panel.routes_advanced_ops as routes

    calls=[]
    def fake_ops(payload,timeout=25):
        calls.append(dict(payload))
        action=payload.get('action')
        if action=='status': return {'ok':True,'engine':'test','capabilities':{'dns':True,'ssl':True,'php':True,'postgres':True,'migrations':True,'service_control':True}}
        if action=='php-list': return {'ok':True,'versions':['8.3','8.4']}
        if action=='service-status': return {'ok':True,'services':[{'name':'nginx','active':True}]}
        if action=='dns-apply': return {'ok':True,'provider_record_id':'rec123','snapshot':{'records':[],'created_id':'rec123'}}
        if action=='dns-rollback': return {'ok':True,'restored':0}
        if action=='ssl-status': return {'ok':True,'installed':False,'domain':payload['domain']}
        if action in {'ssl-issue','ssl-renew'}: return {'ok':True,'installed':True,'domain':payload['domain'],'detail':'test certificate'}
        if action=='php-set': return {'ok':True,'domain':payload['domain'],'version':payload['version']}
        if action=='postgres-create': return {'ok':True,'db_name':payload['db_name'],'db_user':payload['db_user']}
        if action=='postgres-delete': return {'ok':True,'deleted':True}
        if action=='migration-export': return {'ok':True,'archive':'/var/backups/nexvary-panel/migrations/example-test.tar.gz','size_bytes':321,'sha256':'a'*64}
        if action=='migration-restore': return {'ok':True,'rollback':'/var/backups/nexvary-panel/migrations/rollback.tar.gz'}
        if action=='service-action': return {'ok':True,'name':payload['name'],'action':payload['operation']}
        if action=='mail-queue': return {'ok':True,'count':0,'messages':[]}
        if action=='mail-flush': return {'ok':True}
        return {'ok':False,'error':'unexpected test action'}
    routes.ops_call=fake_ops

    app=create_app();app.testing=True;client=app.test_client();now=int(time.time());csrf='advanced-csrf'
    with db() as conn:
        core=conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone();pid=int(core['id'])
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES(?,?,?,?,1,?)",('opsclient','operator','44'*16,'44'*32,now))
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES(?,?,?)",('opsclient',pid,now))
        conn.execute("INSERT INTO sites(domain,kind,target,app_port,enabled,owner,created_at) VALUES(?,?,?,?,1,?,?)",('example.test','php','',None,'opsclient',now))
        conn.execute("INSERT INTO integration_targets(name,provider,capability,endpoint,secret_kind,secret_id,enabled,owner,created_at,updated_at) VALUES(?,?,?,?,?,?,1,'admin',?,?)",('cf-zone','cloudflare','authoritative-dns','https://api.cloudflare.com/client/v4/zones/abcdefgh','cloudflare','cf_test',now,now))
        target_id=int(conn.execute("SELECT id FROM integration_targets WHERE name='cf-zone'").fetchone()['id'])
        conn.execute("INSERT INTO dns_zone_bindings(domain,target_id,owner,updated_at) VALUES(?,?,?,?)",('example.test',target_id,'opsclient',now))
    with client.session_transaction() as s:s.update(auth=True,user='opsclient',role='operator',csrf=csrf)

    r=client.get('/api/advanced/status');assert r.status_code==200,r.data
    body=r.get_json();assert body['provider']['online'] is True and body['php_versions']==['8.3','8.4']

    # DNS is always preview-first and scope-bound.
    r=client.post('/api/advanced/dns/preview',json={'domain':'example.test','operation':'create','record_type':'A','record_name':'www.example.test','record_value':'203.0.113.10','ttl':300},headers={'X-CSRF-Token':csrf})
    assert r.status_code==200,r.data;change_id=r.get_json()['change']['id']
    assert not any(c.get('action')=='dns-apply' for c in calls)
    r=client.post(f'/api/advanced/dns/{change_id}/apply',headers={'X-CSRF-Token':csrf});assert r.status_code==428,r.data
    with client.session_transaction() as s:s['step_up_user']='opsclient';s['step_up_until']=now+300
    r=client.post(f'/api/advanced/dns/{change_id}/apply',headers={'X-CSRF-Token':csrf});assert r.status_code==200,r.data
    with db() as conn:
        saved=conn.execute("SELECT status,snapshot_json,provider_record_id FROM dns_changes WHERE id=?",(change_id,)).fetchone();assert saved['status']=='applied' and saved['snapshot_json'] and saved['provider_record_id']=='rec123'
    r=client.post(f'/api/advanced/dns/{change_id}/rollback',headers={'X-CSRF-Token':csrf});assert r.status_code==200,r.data
    r=client.post('/api/advanced/dns/preview',json={'domain':'example.test','operation':'create','record_type':'A','record_name':'outside.test','record_value':'203.0.113.10'},headers={'X-CSRF-Token':csrf});assert r.status_code==400,r.data

    # SSL and PHP are scoped and policy-backed.
    r=client.post('/api/advanced/ssl/issue',json={'domain':'example.test','email':'admin@example.test'},headers={'X-CSRF-Token':csrf});assert r.status_code==200,r.data
    r=client.post('/api/advanced/php',json={'domain':'example.test','version':'8.3'},headers={'X-CSRF-Token':csrf});assert r.status_code==200,r.data
    with db() as conn:assert conn.execute("SELECT version FROM php_runtime_assignments WHERE domain='example.test'").fetchone()['version']=='8.3'

    # PostgreSQL is opt-in through Feature Manager; secret must never enter SQLite metadata.
    r=client.post('/api/advanced/postgres',json={'site_domain':'example.test','db_name':'pgdemo','db_user':'pguser','password':'VeryStrongPass_2026'},headers={'X-CSRF-Token':csrf});assert r.status_code==403,r.data
    with db() as conn:conn.execute("INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,1,?) ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=1,updated_at=excluded.updated_at",(pid,'databases.postgresql',now))
    r=client.post('/api/advanced/postgres',json={'site_domain':'example.test','db_name':'pgdemo','db_user':'pguser','password':'VeryStrongPass_2026'},headers={'X-CSRF-Token':csrf});assert r.status_code==201,r.data
    with db() as conn:
        pg=conn.execute("SELECT * FROM postgres_resources WHERE db_name='pgdemo'").fetchone();assert pg and 'password' not in pg.keys()
        dump=' '.join(str(x) for row in conn.execute("SELECT action,details FROM audit ORDER BY id").fetchall() for x in row)
        assert 'VeryStrongPass_2026' not in dump

    # Migration bundle records only safe metadata; restore stays owned.
    r=client.post('/api/advanced/migrations/export',json={'domain':'example.test','db_name':''},headers={'X-CSRF-Token':csrf});assert r.status_code==201,r.data;bundle_id=r.get_json()['id']
    r=client.post(f'/api/advanced/migrations/{bundle_id}/restore',json={'db_name':''},headers={'X-CSRF-Token':csrf});assert r.status_code==200,r.data

    # Server controls remain admin-only.
    r=client.post('/api/advanced/services',json={'name':'nginx','operation':'restart'},headers={'X-CSRF-Token':csrf});assert r.status_code==403,r.data
    r=client.post('/api/advanced/fleet',json={'name':'bad-local','endpoint':'https://127.0.0.1'},headers={'X-CSRF-Token':csrf});assert r.status_code==403,r.data

    with client.session_transaction() as s:s.update(user='admin',role='admin',step_up_user='admin',step_up_until=now+300)
    r=client.post('/api/advanced/fleet',json={'name':'bad-local','endpoint':'https://127.0.0.1'},headers={'X-CSRF-Token':csrf});assert r.status_code==400,r.data
    r=client.post('/api/advanced/services',json={'name':'nginx','operation':'restart'},headers={'X-CSRF-Token':csrf});assert r.status_code==200,r.data

print('Nexvary Panel Advanced Hosting Ops policy gate: PASS')
