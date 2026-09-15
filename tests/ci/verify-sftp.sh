#!/usr/bin/env bash
set -euo pipefail
for i in {1..15}; do sudo systemctl is-active --quiet nexvary-panel-transfer && break; sleep 1; done
sudo systemctl is-active --quiet ssh
sudo systemctl is-active --quiet nexvary-panel-transfer || { sudo systemctl status nexvary-panel-transfer --no-pager; sudo journalctl -u nexvary-panel-transfer -n 120 --no-pager; exit 1; }
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel/transfer.sock)" = "660 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /etc/ssh/nexvary-authorized-keys)" = "750 root nexvary-sftp"
test "$(sudo stat -c '%a %U %G' /srv/nexvary-sftp)" = "755 root root"
sudo sshd -t
sudo grep -q '^Match Group nexvary-sftp$' /etc/ssh/sshd_config.d/90-nexvary-sftp.conf
sudo grep -q 'ForceCommand internal-sftp -d /site' /etc/ssh/sshd_config.d/90-nexvary-sftp.conf
sudo grep -q 'AuthorizedKeysFile /etc/ssh/nexvary-authorized-keys/%u' /etc/ssh/sshd_config.d/90-nexvary-sftp.conf
sudo grep -q 'AuthenticationMethods publickey' /etc/ssh/sshd_config.d/90-nexvary-sftp.conf
sudo grep -q 'PasswordAuthentication no' /etc/ssh/sshd_config.d/90-nexvary-sftp.conf
sudo -u nexvary-panel python3 - <<'PY'
import json,socket
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(5); s.connect('/run/nexvary-panel/transfer.sock')
s.sendall(b'{"action":"status"}\n'); data=b''
while not data.endswith(b'\n'): data+=s.recv(4096)
body=json.loads(data); assert body.get('ok') is True, body; assert body.get('shell') is False, body
PY
sudo install -d -m 0750 -o www-data -g www-data /var/www/sftp-gate.example
echo gate | sudo tee /var/www/sftp-gate.example/index.txt >/dev/null
sudo chown www-data:www-data /var/www/sftp-gate.example/index.txt
ssh-keygen -q -t ed25519 -N '' -f /tmp/nvp_sftp_key
PUB="$(cat /tmp/nvp_sftp_key.pub)"
sudo -u nexvary-panel python3 - "$PUB" <<'PY'
import json,socket,sys
payload={'action':'account-create','system_user':'nvpt_0123456789','domain':'sftp-gate.example','public_key':sys.argv[1]}
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(20); s.connect('/run/nexvary-panel/transfer.sock')
s.sendall((json.dumps(payload)+'\n').encode()); data=b''
while not data.endswith(b'\n'): data+=s.recv(4096)
body=json.loads(data); assert body.get('ok') is True, body; assert body.get('shell') is False, body
PY
getent passwd nvpt_0123456789
id -nG nvpt_0123456789 | grep -qw nexvary-sftp
sudo passwd -S nvpt_0123456789 | grep -q ' P '
sudo mountpoint -q /srv/nexvary-sftp/nvpt_0123456789/site
test "$(sudo stat -c '%a %U %G' /etc/ssh/nexvary-authorized-keys/nvpt_0123456789)" = "640 root nexvary-sftp"
echo uploaded-through-sftp > /tmp/nvp-upload.txt
printf 'pwd\nls\nput /tmp/nvp-upload.txt upload.txt\n' > /tmp/nvp-sftp.batch
if ! sftp -q -b /tmp/nvp-sftp.batch -i /tmp/nvp_sftp_key -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 nvpt_0123456789@127.0.0.1; then
  sudo sshd -T -C user=nvpt_0123456789,host=localhost,addr=127.0.0.1 | grep -E '^(chrootdirectory|forcecommand|authorizedkeysfile|authenticationmethods|passwordauthentication|pubkeyauthentication) ' || true
  sudo journalctl -u ssh -n 120 --no-pager || true
  exit 1
fi
sudo grep -q uploaded-through-sftp /var/www/sftp-gate.example/upload.txt
printf 'ls /etc\n' > /tmp/nvp-sftp-escape.batch
if sftp -q -b /tmp/nvp-sftp-escape.batch -i /tmp/nvp_sftp_key -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 nvpt_0123456789@127.0.0.1; then
  echo 'SFTP chroot escape test unexpectedly succeeded' >&2
  exit 1
fi
sudo -u nexvary-panel python3 - <<'PY'
import json,socket
payload={'action':'account-delete','system_user':'nvpt_0123456789','domain':'sftp-gate.example'}
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(20); s.connect('/run/nexvary-panel/transfer.sock')
s.sendall((json.dumps(payload)+'\n').encode()); data=b''
while not data.endswith(b'\n'): data+=s.recv(4096)
body=json.loads(data); assert body.get('ok') is True, body
PY
! getent passwd nvpt_0123456789
! sudo mountpoint -q /srv/nexvary-sftp/nvpt_0123456789/site
test ! -e /etc/ssh/nexvary-authorized-keys/nvpt_0123456789
