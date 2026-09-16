#!/usr/bin/env bash
set -euo pipefail
check_service(){
  local svc="$1"
  for i in {1..15}; do sudo systemctl is-active --quiet "$svc" && return 0; sleep 1; done
  sudo systemctl status "$svc" --no-pager || true
  sudo journalctl -u "$svc" -n 120 --no-pager || true
  return 1
}
for svc in postfix dovecot nexvary-panel-mail nexvary-panel-dav nexvary-panel-dav-agent; do check_service "$svc"; done
command -v sievec >/dev/null
command -v htpasswd >/dev/null
test -f /opt/nexvary-panel-agent/mail_sieve.py
test -f /opt/nexvary-panel-agent/dav_agent.py
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel/mail.sock)" = "660 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel/dav.sock)" = "660 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /etc/nexvary-panel/mail/users)" = "640 root dovecot"
test "$(sudo stat -c '%a %U %G' /etc/nexvary-panel/mail/domains)" = "640 root postfix"
test "$(sudo stat -c '%a %U %G' /etc/nexvary-panel-radicale/users)" = "640 root radicale"
test "$(sudo stat -c '%a %U %G' /etc/nexvary-panel-radicale/config)" = "640 root radicale"
sudo grep -q '^type = htpasswd$' /etc/nexvary-panel-radicale/config
sudo grep -q '^htpasswd_encryption = bcrypt$' /etc/nexvary-panel-radicale/config
sudo grep -q '^type = owner_only$' /etc/nexvary-panel-radicale/config
sudo grep -q 'NEXVARY_DAV_BEGIN' /etc/nginx/sites-available/nexvary-panel.conf
sudo nginx -t
sudo postfix check
sudo dovecot -n >/dev/null
sudo postconf virtual_mailbox_domains | grep -q '/etc/nexvary-panel/mail/domains'
sudo postconf virtual_transport | grep -q 'dovecot-lmtp'
sudo grep -q '/etc/nexvary-panel/mail/users' /etc/dovecot/conf.d/99-nexvary-panel.conf
sudo grep -q '^protocols = imap lmtp$' /etc/dovecot/conf.d/99-nexvary-panel.conf
sudo grep -Eq 'mail_plugins = .*sieve' /etc/dovecot/conf.d/99-nexvary-panel.conf
echo 'preserve.example OK' | sudo tee -a /etc/nexvary-panel/mail/domains >/dev/null
sudo postmap /etc/nexvary-panel/mail/domains
sudo bash installer/configure-mail.sh
sudo grep -q '^preserve.example OK$' /etc/nexvary-panel/mail/domains
sudo -u nexvary-panel python3 - <<'PY'
import json,socket

def call(payload, expect_ok=True):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(15); s.connect('/run/nexvary-panel/mail.sock')
    s.sendall((json.dumps(payload,separators=(',',':'))+'\n').encode())
    data=b''
    while not data.endswith(b'\n'):
        data+=s.recv(4096)
    s.close()
    body=json.loads(data)
    if expect_ok:
        assert body.get('ok') is True, body
    return body

body=call({'action':'status'})
assert body.get('engine')=='postfix-dovecot', body
call({'action':'mailbox-upsert','address':'ci@example.test','password':'CiMailAutomation!2026'})
sieve=call({
  'action':'sieve-sync',
  'address':'ci@example.test',
  'autoresponder':{'enabled':True,'subject':'CI Away','body':'Automated CI response.','interval_days':1},
  'filters':[{'priority':10,'field':'subject','match_type':'contains','pattern':'invoice','action':'fileinto','destination':'Billing','enabled':1}],
  'spam':{'enabled':True,'action':'junk'},
  'global_filters':[{'priority':5,'field':'header','header_name':'X-Campaign-ID','match_type':'contains','pattern':'vip','action':'fileinto','destination':'Global','enabled':1}],
  'global_domains':['example.test','second.example'],
})
assert sieve.get('global_filters')==1, sieve
loop=call({
  'action':'sieve-sync',
  'address':'ci@example.test',
  'autoresponder':{'enabled':False,'subject':'','body':'','interval_days':1},
  'filters':[],
  'spam':{'enabled':False,'action':'junk'},
  'global_filters':[{'priority':1,'field':'subject','header_name':'','match_type':'contains','pattern':'loop','action':'redirect','destination':'archive@second.example','enabled':1}],
  'global_domains':['example.test','second.example'],
}, expect_ok=False)
assert loop.get('error')=='global-filter-redirect-loop', loop
trace=call({'action':'delivery-trace','domain':'example.test','limit':25})
assert trace.get('domain')=='example.test', trace
assert trace.get('source') in {'mail.log','journalctl'}, trace
assert isinstance(trace.get('events'),list), trace
assert len(trace['events'])<=25, trace
assert all('raw' not in event for event in trace['events']), trace
remote=call({'action':'routing-sync','domain':'remote-ci.example','mode':'remote'})
assert remote.get('mode')=='remote', remote
local=call({'action':'routing-sync','domain':'remote-ci.example','mode':'local'})
assert local.get('mode')=='local', local
conflict=call({'action':'routing-sync','domain':'example.test','mode':'remote'}, expect_ok=False)
assert conflict.get('ok') is False and conflict.get('error')=='routing-conflict-local-resources', conflict
created=call({'action':'mailing-list-sync','address':'team@list-ci.example','members':['one@external.example','two@external.example'],'expected_members':[]})
assert created.get('member_count')==2, created
updated=call({'action':'mailing-list-sync','address':'team@list-ci.example','members':['one@external.example','three@external.example'],'expected_members':['one@external.example','two@external.example']})
assert updated.get('member_count')==2, updated
call({'action':'mailing-list-sync','address':'delete@list-ci.example','members':['one@external.example'],'expected_members':[]})
removed=call({'action':'mailing-list-sync','address':'delete@list-ci.example','members':[],'expected_members':['one@external.example']})
assert removed.get('member_count')==0, removed
stale=call({'action':'mailing-list-sync','address':'team@list-ci.example','members':['x@external.example'],'expected_members':['wrong@external.example']}, expect_ok=False)
assert stale.get('error')=='mailing-list-provider-conflict', stale
PY
SIEVE=/var/mail/vhosts/example.test/ci/.dovecot.sieve
SVBIN=/var/mail/vhosts/example.test/ci/.dovecot.svbin
sudo test -f "$SIEVE"
sudo test -f "$SVBIN"
test "$(sudo stat -c '%a %U %G' "$SIEVE")" = "600 vmail vmail"
test "$(sudo stat -c '%a %U %G' "$SVBIN")" = "600 vmail vmail"
sudo grep -q 'Managed by Nexvary Panel' "$SIEVE"
sudo grep -q 'Account-wide global filters' "$SIEVE"
sudo grep -q 'X-Campaign-ID' "$SIEVE"
sudo grep -q 'fileinto :create "Global"' "$SIEVE"
sudo grep -q 'vacation :days 1' "$SIEVE"
sudo grep -q 'fileinto :create "Billing"' "$SIEVE"
sudo grep -q 'fileinto :create "Junk"' "$SIEVE"
sudo grep -q '^remote-ci.example OK$' /etc/nexvary-panel/mail/domains
sudo grep -Fq 'team@list-ci.example one@external.example,three@external.example' /etc/nexvary-panel/mail/virtual
if sudo grep -Fq 'delete@list-ci.example' /etc/nexvary-panel/mail/virtual; then
  echo 'Deleted mailing list remains in Postfix virtual map' >&2
  exit 1
fi
sudo postfix check
sudo dovecot -n >/dev/null

DAV_USER='calendar@example.test'
DAV_PASS='CiDavCredential!2026'
DAV_ROTATED='CiDavRotated!2026'
sudo -u nexvary-panel env DAV_USER="$DAV_USER" DAV_PASS="$DAV_PASS" python3 - <<'PY'
import json,os,socket

def call(payload, expect_ok=True):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(20); s.connect('/run/nexvary-panel/dav.sock')
    s.sendall((json.dumps(payload,separators=(',',':'))+'\n').encode())
    data=b''
    while not data.endswith(b'\n'):
        data+=s.recv(4096)
    s.close()
    body=json.loads(data)
    if expect_ok:
        assert body.get('ok') is True, body
    return body

status=call({'action':'status'})
assert status.get('online') is True and status.get('engine')=='radicale-caldav-carddav', status
created=call({'action':'credential-sync','username':os.environ['DAV_USER'],'password':os.environ['DAV_PASS'],'expected_present':False})
assert created.get('username')==os.environ['DAV_USER'], created
stale=call({'action':'credential-sync','username':os.environ['DAV_USER'],'password':os.environ['DAV_PASS'],'expected_present':False}, expect_ok=False)
assert stale.get('error')=='dav-provider-conflict', stale
PY
curl -kfsS -X PROPFIND -H 'Depth: 0' -u "$DAV_USER:$DAV_PASS" "https://127.0.0.1:8443/dav/$DAV_USER/" >/dev/null
sudo grep -q '^calendar@example\.test:\$2' /etc/nexvary-panel-radicale/users
if sudo grep -Fq "$DAV_PASS" /etc/nexvary-panel-radicale/users; then
  echo 'DAV cleartext password leaked into htpasswd file' >&2
  exit 1
fi
sudo -u nexvary-panel env DAV_USER="$DAV_USER" DAV_ROTATED="$DAV_ROTATED" python3 - <<'PY'
import json,os,socket
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(20); s.connect('/run/nexvary-panel/dav.sock')
payload={'action':'credential-sync','username':os.environ['DAV_USER'],'password':os.environ['DAV_ROTATED'],'expected_present':True}
s.sendall((json.dumps(payload,separators=(',',':'))+'\n').encode()); data=b''
while not data.endswith(b'\n'): data+=s.recv(4096)
s.close(); body=json.loads(data); assert body.get('ok') is True, body
PY
if curl -kfsS -X PROPFIND -H 'Depth: 0' -u "$DAV_USER:$DAV_PASS" "https://127.0.0.1:8443/dav/$DAV_USER/" >/dev/null 2>&1; then
  echo 'Old DAV credential still authenticates after rotation' >&2
  exit 1
fi
curl -kfsS -X PROPFIND -H 'Depth: 0' -u "$DAV_USER:$DAV_ROTATED" "https://127.0.0.1:8443/dav/$DAV_USER/" >/dev/null
sudo -u nexvary-panel env DAV_USER="$DAV_USER" python3 - <<'PY'
import json,os,socket
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(20); s.connect('/run/nexvary-panel/dav.sock')
s.sendall((json.dumps({'action':'credential-delete','username':os.environ['DAV_USER']},separators=(',',':'))+'\n').encode()); data=b''
while not data.endswith(b'\n'): data+=s.recv(4096)
s.close(); body=json.loads(data); assert body.get('ok') is True, body
PY
if curl -kfsS -X PROPFIND -H 'Depth: 0' -u "$DAV_USER:$DAV_ROTATED" "https://127.0.0.1:8443/dav/$DAV_USER/" >/dev/null 2>&1; then
  echo 'Revoked DAV credential still authenticates' >&2
  exit 1
fi
if sudo grep -q '^calendar@example\.test:' /etc/nexvary-panel-radicale/users; then
  echo 'Revoked DAV account remains in htpasswd file' >&2
  exit 1
fi
