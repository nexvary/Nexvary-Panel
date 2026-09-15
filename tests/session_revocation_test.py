from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-session-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "0"

    from panel import create_app
    from panel.db_layer import db

    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    with db() as conn:
        conn.execute("INSERT INTO users(username,role,salt,password_hash,enabled,created_at) VALUES('sessionuser','operator','00','00',1,?)", (int(time.time()),))
        conn.execute("INSERT INTO sites(domain,kind,target,enabled,owner,created_at) VALUES('session.example','static','',1,'sessionuser',?)", (int(time.time()),))

    with client.session_transaction() as sess:
        sess['auth'] = True
        sess['user'] = 'sessionuser'
        sess['role'] = 'operator'
        sess['csrf'] = 'session-csrf'

    assert client.get('/api/files?domain=session.example&path=').status_code != 401

    with db() as conn:
        conn.execute("UPDATE users SET enabled=0 WHERE username='sessionuser'")
    response = client.get('/api/files?domain=session.example&path=')
    assert response.status_code == 401
    assert response.get_json()['error'] == 'session revoked or account disabled'
    with client.session_transaction() as sess:
        assert not sess.get('auth')

    with db() as conn:
        conn.execute("UPDATE users SET enabled=1,role='viewer' WHERE username='sessionuser'")
    with client.session_transaction() as sess:
        sess['auth'] = True
        sess['user'] = 'sessionuser'
        sess['role'] = 'operator'
    response = client.get('/api/files?domain=session.example&path=')
    assert response.status_code == 401

print('Nexvary Panel session revocation gate: PASS')
