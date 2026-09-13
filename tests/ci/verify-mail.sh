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

def call(payload):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(15); s.connect('/run/nexvary-panel/mail.sock')
    s.sendall((json.dumps(payload,separators=(',',':'))+'\n').encode())
    data=b''
    while not data.endswith(b'\n'):
        data+=s.recv(4096)
    s.close()
    body=json.loads(data)
    assert body.get('ok') is True, body
    return body

body=call({'action':'status'})
assert body.get('engine')=='postfix-dovecot', body
call({'action':'mailbox-upsert','address':'ci@example.test','password':'CiMailAutomation!2026'})
call({
  'action':'sieve-sync',
  'address':'ci@example.test',
  'autoresponder':{'enabled':True,'subject':'CI Away','body':'Automated CI response.','interval_days':1},
  'filters':[{'priority':10,'field':'subject','match_type':'contains','pattern':'invoice','action':'fileinto','destination':'Billing','enabled':1}],
  'spam':{'enabled':True,'action':'junk'},
})
PY
SIEVE=/var/mail/vhosts/example.test/ci/.dovecot.sieve
SVBIN=/var/mail/vhosts/example.test/ci/.dovecot.svbin
sudo test -f "$SIEVE"
sudo test -f "$SVBIN"
test "$(sudo stat -c '%a %U %G' "$SIEVE")" = "600 vmail vmail"
test "$(sudo stat -c '%a %U %G' "$SVBIN")" = "600 vmail vmail"
sudo grep -q 'Managed by Nexvary Panel' "$SIEVE"
sudo grep -q 'vacation :days 1' "$SIEVE"
sudo grep -q 'fileinto :create "Billing"' "$SIEVE"
sudo grep -q 'fileinto :create "Junk"' "$SIEVE"
sudo postfix check
sudo dovecot -n >/dev/null
