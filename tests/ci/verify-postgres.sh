#!/usr/bin/env bash
set -euo pipefail
for svc in postgresql nexvary-panel-postgres nexvary-panel-ops; do
  for i in {1..15}; do sudo systemctl is-active --quiet "$svc" && break; sleep 1; done
  sudo systemctl is-active --quiet "$svc" || exit 1
done
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel/ops.sock)" = "660 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel-postgres)" = "750 postgres nexvary-panel"
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel-postgres/postgres.sock)" = "660 postgres nexvary-panel"
test "$(sudo stat -c '%a %U %G' /var/lib/nexvary-panel-postgres)" = "700 postgres nexvary-panel"
sudo -u nexvary-panel test -x /run/nexvary-panel-postgres

grep -q 'StateDirectory=nexvary-panel-postgres' /etc/systemd/system/nexvary-panel-postgres.service

sudo -u nexvary-panel python3 - <<'PY'
import json,socket

def call(path,payload):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(45); s.connect(path)
    s.sendall((json.dumps(payload)+'\n').encode()); data=b''
    while not data.endswith(b'\n'): data+=s.recv(4096)
    body=json.loads(data); s.close(); return body

status=call('/run/nexvary-panel/ops.sock',{'action':'status'})
assert status.get('ok') is True, status
assert status.get('capabilities',{}).get('postgres') is True, status
pg=call('/run/nexvary-panel-postgres/postgres.sock',{'action':'status'})
assert pg.get('ok') is True and pg.get('available') is True, pg
assert set(pg.get('grant_profiles',[]))=={'readonly','readwrite','developer'}, pg

created=call('/run/nexvary-panel-postgres/postgres.sock',{
  'action':'create','db_name':'nvp_access_gate','db_user':'nvp_owner','password':'OwnerStrongPass-2026!'
})
assert created.get('ok') is True, created
role=call('/run/nexvary-panel-postgres/postgres.sock',{
  'action':'role-create','username':'nvp_reader','password':'ReaderStrongPass-2026!'
})
assert role.get('ok') is True, role
PY

sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d nvp_access_gate <<'SQL'
SET ROLE nvp_owner;
CREATE TABLE public.nvp_existing(id integer);
INSERT INTO public.nvp_existing VALUES (1);
RESET ROLE;
SQL

sudo -u nexvary-panel python3 - <<'PY'
import json,socket

def call(payload):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(45); s.connect('/run/nexvary-panel-postgres/postgres.sock')
    s.sendall((json.dumps(payload)+'\n').encode()); data=b''
    while not data.endswith(b'\n'): data+=s.recv(4096)
    body=json.loads(data); s.close(); return body
body=call({'action':'grant-profile','db_name':'nvp_access_gate','username':'nvp_reader','profile':'readonly'})
assert body.get('ok') is True, body
PY

[[ "$(sudo -u postgres psql -X -Atc "SELECT has_database_privilege('nvp_reader','nvp_access_gate','CONNECT')")" == "t" ]]
[[ "$(sudo -u postgres psql -X -At -d nvp_access_gate -c "SELECT has_table_privilege('nvp_reader','public.nvp_existing','SELECT')")" == "t" ]]
[[ "$(sudo -u postgres psql -X -At -d nvp_access_gate -c "SELECT has_table_privilege('nvp_reader','public.nvp_existing','INSERT')")" == "f" ]]
[[ "$(sudo -u postgres psql -X -Atc "SELECT rolsuper||','||rolcreatedb||','||rolcreaterole||','||rolreplication||','||rolbypassrls FROM pg_roles WHERE rolname='nvp_reader'")" == "false,false,false,false,false" ]]

sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d nvp_access_gate <<'SQL'
SET ROLE nvp_owner;
CREATE TABLE public.nvp_future(id integer);
RESET ROLE;
SQL
[[ "$(sudo -u postgres psql -X -At -d nvp_access_gate -c "SELECT has_table_privilege('nvp_reader','public.nvp_future','SELECT')")" == "t" ]]

# Real PostgreSQL lifecycle: custom-format snapshot, mutation, restore and grant/default privilege survival.
read -r PG_ARCHIVE <<<"$(sudo -u nexvary-panel python3 - <<'PY'
import json,socket
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(360);s.connect('/run/nexvary-panel-postgres/postgres.sock')
s.sendall(b'{"action":"snapshot-create","db_name":"nvp_access_gate"}\n');data=b''
while not data.endswith(b'\n'):data+=s.recv(8192)
body=json.loads(data);s.close();assert body.get('ok') is True,body
assert '/' not in body['archive'] and body['archive'].endswith('.dump'),body
assert len(body.get('sha256',''))==64 and int(body.get('size_bytes',0))>0,body
print(body['archive'])
PY
)"
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d nvp_access_gate -c "UPDATE public.nvp_existing SET id=2;"
read -r PG_ROLLBACK <<<"$(sudo -u nexvary-panel env PG_ARCHIVE="$PG_ARCHIVE" python3 - <<'PY'
import json,os,socket
payload={'action':'snapshot-restore','db_name':'nvp_access_gate','archive':os.environ['PG_ARCHIVE']}
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(420);s.connect('/run/nexvary-panel-postgres/postgres.sock')
s.sendall((json.dumps(payload)+'\n').encode());data=b''
while not data.endswith(b'\n'):data+=s.recv(8192)
body=json.loads(data);s.close();assert body.get('ok') is True,body
assert body.get('rollback_archive') and '/' not in body['rollback_archive'],body
print(body['rollback_archive'])
PY
)"
[[ "$(sudo -u postgres psql -X -At -d nvp_access_gate -c 'SELECT id FROM public.nvp_existing LIMIT 1')" == "1" ]]
[[ "$(sudo -u postgres psql -X -At -d nvp_access_gate -c "SELECT has_table_privilege('nvp_reader','public.nvp_existing','SELECT')")" == "t" ]]

sudo -u nexvary-panel env A="$PG_ARCHIVE" B="$PG_ROLLBACK" python3 - <<'PY'
import json,os,socket
for archive in (os.environ['A'],os.environ['B']):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(30);s.connect('/run/nexvary-panel-postgres/postgres.sock')
    s.sendall((json.dumps({'action':'snapshot-delete','archive':archive})+'\n').encode());data=b''
    while not data.endswith(b'\n'):data+=s.recv(8192)
    body=json.loads(data);s.close();assert body.get('ok') is True,body
PY

sudo -u nexvary-panel python3 - <<'PY'
import json,socket

def call(payload):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(45); s.connect('/run/nexvary-panel-postgres/postgres.sock')
    s.sendall((json.dumps(payload)+'\n').encode()); data=b''
    while not data.endswith(b'\n'): data+=s.recv(4096)
    body=json.loads(data); s.close(); return body
revoked=call({'action':'grant-profile','db_name':'nvp_access_gate','username':'nvp_reader','profile':'none'})
assert revoked.get('ok') is True, revoked
PY
[[ "$(sudo -u postgres psql -X -Atc "SELECT has_database_privilege('nvp_reader','nvp_access_gate','CONNECT')")" == "f" ]]
[[ "$(sudo -u postgres psql -X -At -d nvp_access_gate -c "SELECT has_table_privilege('nvp_reader','public.nvp_existing','SELECT')")" == "f" ]]

sudo -u nexvary-panel python3 - <<'PY'
import json,socket

def call(payload):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(45); s.connect('/run/nexvary-panel-postgres/postgres.sock')
    s.sendall((json.dumps(payload)+'\n').encode()); data=b''
    while not data.endswith(b'\n'): data+=s.recv(4096)
    body=json.loads(data); s.close(); return body
removed=call({'action':'role-drop','username':'nvp_reader'})
assert removed.get('ok') is True, removed
clean=call({'action':'delete','db_name':'nvp_access_gate','db_user':'nvp_owner'})
assert clean.get('ok') is True, clean
PY
