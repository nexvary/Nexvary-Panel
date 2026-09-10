#!/usr/bin/env bash
set -euo pipefail
for svc in postgresql nexvary-panel-postgres nexvary-panel-ops; do
  for i in {1..15}; do sudo systemctl is-active --quiet "$svc" && break; sleep 1; done
  sudo systemctl is-active --quiet "$svc" || exit 1
done
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel/ops.sock)" = "660 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel-postgres/postgres.sock)" = "660 postgres nexvary-panel"
sudo -u nexvary-panel python3 - <<'PY'
import json,socket
def call(payload):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(30); s.connect('/run/nexvary-panel/ops.sock')
    s.sendall((json.dumps(payload)+'\n').encode()); data=b''
    while not data.endswith(b'\n'): data+=s.recv(4096)
    return json.loads(data)
status=call({'action':'status'})
assert status.get('ok') is True, status
assert status.get('capabilities',{}).get('postgres') is True, status
PY
