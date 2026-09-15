#!/usr/bin/env bash
set -euo pipefail

for file in \
  /opt/nexvary-panel/panel/routes_site_controls.py \
  /opt/nexvary-panel/panel/site_controls_schema.py \
  /opt/nexvary-panel/templates/sections/site_controls.html \
  /opt/nexvary-panel/static/site-controls.css \
  /opt/nexvary-panel/static/site-controls.js \
  /opt/nexvary-panel-agent/site_controls.py; do
  test -f "$file"
done

test "$(sudo stat -c '%a %U %G' /opt/nexvary-panel-agent/site_controls.py)" = "640 root root"
grep -q '/etc/nginx/nexvary-auth' /etc/systemd/system/nexvary-panel-webtools.service
sudo systemctl is-active --quiet nexvary-panel-webtools
sudo nginx -t

sudo -u nexvary-panel python3 - <<'PY'
import json,socket
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.settimeout(5)
s.connect('/run/nexvary-panel/webtools.sock')
s.sendall(b'{"action":"site-control-raw-access","domain":"not-managed.invalid","lines":5}\n')
data=b''
while not data.endswith(b'\n'):
    data+=s.recv(4096)
body=json.loads(data)
assert body.get('ok') is False, body
PY

echo 'NEXVARY Site Control installer gate: PASS'
