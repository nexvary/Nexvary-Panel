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
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel/mail.sock)" = "660 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /etc/nexvary-panel/mail/users)" = "640 root dovecot"
test "$(sudo stat -c '%a %U %G' /etc/nexvary-panel/mail/domains)" = "640 root postfix"
sudo postfix check
sudo dovecot -n >/dev/null
sudo postconf virtual_mailbox_domains | grep -q '/etc/nexvary-panel/mail/domains'
sudo grep -q '/etc/nexvary-panel/mail/users' /etc/dovecot/conf.d/99-nexvary-panel.conf
echo 'preserve.example OK' | sudo tee -a /etc/nexvary-panel/mail/domains >/dev/null
sudo postmap /etc/nexvary-panel/mail/domains
sudo bash installer/configure-mail.sh
sudo grep -q '^preserve.example OK$' /etc/nexvary-panel/mail/domains
sudo -u nexvary-panel python3 - <<'PY'
import json,socket
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(5); s.connect('/run/nexvary-panel/mail.sock')
s.sendall(b'{"action":"status"}\n'); data=b''
while not data.endswith(b'\n'): data+=s.recv(4096)
body=json.loads(data); assert body.get('ok') is True, body; assert body.get('engine')=='postfix-dovecot', body
PY
