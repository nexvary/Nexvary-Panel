from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-entitlements-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db
    from panel.hosting_policy import entitlement_state, package_limit, quota_state
    import panel.routes_sites as routes_sites

    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    with db() as conn:
        core = conn.execute("SELECT id FROM hosting_packages WHERE name='NEXVARY Core'").fetchone()
        assert core
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES('quotauser','operator','00','00',1,?)", (int(time.time()),))
        conn.execute("INSERT INTO user_hosting_package(username,package_id,assigned_at) VALUES('quotauser',?,?)", (int(core['id']), int(time.time())))

    with app.test_request_context('/'):
        assert package_limit('max_sites', username='quotauser', role='operator') == 10
        state = quota_state('max_sites', 9, username='quotauser', role='operator')
        assert state['allowed'] is True and state['remaining'] == 1
        state = quota_state('max_sites', 10, username='quotauser', role='operator')
        assert state['allowed'] is False and state['remaining'] == 0
        assert entitlement_state('domains.domains', limit_name='max_sites', used=0, username='quotauser', role='operator')['allowed'] is True
        try:
            package_limit('made_up_column', username='quotauser', role='operator')
            raise AssertionError('unknown package limit accepted')
        except ValueError:
            pass

    def agent_must_not_run(*_args, **_kwargs):
        raise AssertionError('root agent was reached before hosting policy rejection')

    routes_sites.agent_call = agent_must_not_run
    with client.session_transaction() as sess:
        sess['auth'] = True
        sess['user'] = 'quotauser'
        sess['role'] = 'operator'
        sess['csrf'] = 'gate-token'

    with db() as conn:
        conn.execute("INSERT INTO hosting_package_features(package_id,feature_id,enabled,updated_at) VALUES(?,?,0,?) ON CONFLICT(package_id,feature_id) DO UPDATE SET enabled=0,updated_at=excluded.updated_at", (int(core['id']), 'domains.domains', int(time.time())))
    response = client.post('/sites', data={'csrf_token':'gate-token','domain':'blocked.example','kind':'static'})
    assert response.status_code == 302
    with db() as conn:
        assert conn.execute("SELECT 1 FROM sites WHERE domain='blocked.example'").fetchone() is None
        conn.execute("UPDATE hosting_package_features SET enabled=1 WHERE package_id=? AND feature_id='domains.domains'", (int(core['id']),))
        conn.execute("UPDATE hosting_packages SET max_sites=1 WHERE id=?", (int(core['id']),))
        conn.execute("INSERT INTO sites(domain,kind,target,enabled,owner,created_at) VALUES('existing.example','static','',1,'quotauser',?)", (int(time.time()),))
    response = client.post('/sites', data={'csrf_token':'gate-token','domain':'overquota.example','kind':'static'})
    assert response.status_code == 302
    with db() as conn:
        assert conn.execute("SELECT 1 FROM sites WHERE domain='overquota.example'").fetchone() is None

print('Nexvary Panel operational entitlement and quota gate: PASS')
