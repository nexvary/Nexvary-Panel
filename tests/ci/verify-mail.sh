#!/usr/bin/env bash
set -euo pipefail
check_service(){
  local svc="$1"
  for i in {1..15}; do sudo systemctl is-active --quiet "$svc" && return 0; sleep 1; done
  sudo systemctl status "$svc" --no-pager || true
  sudo journalctl -u "$svc" -n 120 --no-pager || true
  return 1
}
for svc in postfix dovecot nexvary-panel-mail; do check_service "$svc"; done
command -v sievec >/dev/null
test -f /opt/nexvary-panel-agent/mail_sieve.py
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel/mail.sock)" = "660 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /etc/nexvary-panel/mail/users)" = "640 root dovecot"
test "$(sudo stat -c '%a %U %G' /etc/nexvary-panel/mail/domains)" = "640 root postfix"
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

# Routing is provider-backed and fail-closed. An empty domain can move remote/local,
# while a domain with local mailboxes cannot be switched remote.
remote=call({'action':'routing-sync','domain':'remote-ci.example','mode':'remote'})
assert remote.get('mode')=='remote', remote
local=call({'action':'routing-sync','domain':'remote-ci.example','mode':'local'})
assert local.get('mode')=='local', local
conflict=call({'action':'routing-sync','domain':'example.test','mode':'remote'}, expect_ok=False)
assert conflict.get('ok') is False and conflict.get('error')=='routing-conflict-local-resources', conflict

# Distribution-list provider uses optimistic expected-members and survives reload validation.
created=call({
  'action':'mailing-list-sync','address':'team@list-ci.example',
  'members':['one@external.example','two@external.example'],'expected_members':[]
})
assert created.get('member_count')==2, created
updated=call({
  'action':'mailing-list-sync','address':'team@list-ci.example',
  'members':['one@external.example','three@external.example'],
  'expected_members':['one@external.example','two@external.example']
})
assert updated.get('member_count')==2, updated
call({
  'action':'mailing-list-sync','address':'delete@list-ci.example',
  'members':['one@external.example'],'expected_members':[]
})
removed=call({
  'action':'mailing-list-sync','address':'delete@list-ci.example',
  'members':[],'expected_members':['one@external.example']
})
assert removed.get('member_count')==0, removed
stale=call({
  'action':'mailing-list-sync','address':'team@list-ci.example',
  'members':['x@external.example'],'expected_members':['wrong@external.example']
}, expect_ok=False)
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
