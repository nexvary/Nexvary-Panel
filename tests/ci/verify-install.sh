#!/usr/bin/env bash
set -euo pipefail
check_service(){
  local svc="$1"
  for i in {1..12}; do sudo systemctl is-active --quiet "$svc" && return 0; sleep 1; done
  echo "Service failed to become active: $svc" >&2
  sudo systemctl status "$svc" --no-pager || true
  sudo journalctl -u "$svc" -n 100 --no-pager || true
  return 1
}
for svc in nginx mariadb nexvary-panel-agent nexvary-panel-vault nexvary-panel-provider nexvary-panel-database nexvary-panel-webtools nexvary-panel-scheduler nexvary-panel-ops nexvary-panel-server nexvary-panel-wordpress nexvary-panel; do check_service "$svc"; done
for file in panel/__init__.py panel/module_registry.py panel/routes_accounts.py panel/account_schema.py panel/routes_database_access.py panel/database_access_schema.py panel/database_client.py panel/routes_database_lifecycle.py panel/database_lifecycle_schema.py panel/routes_resource_usage.py panel/routes_mail.py panel/mail_schema.py panel/routes_mail_automation.py panel/mail_automation_schema.py panel/routes_transfers.py panel/transfer_schema.py panel/routes_domains.py panel/domain_schema.py panel/routes_advanced_ops.py panel/routes_server_lifecycle.py panel/server_lifecycle_schema.py panel/server_client.py panel/routes_autossl.py panel/routes_deliverability.py panel/routes_domain_health.py panel/routes_wordpress_lifecycle.py panel/routes_wordpress_updates.py panel/routes_wordpress_staging.py panel/wordpress_staging_schema.py panel/wordpress_client.py panel/ops_schema.py panel/ops_client.py static/app.css static/approved-theme.css static/hosting-suite.css static/accounts.css static/accounts.js static/database-access.css static/database-access.js static/mail.css static/mail.js static/mail-automation.js static/transfers.css static/transfers.js static/advanced-ops.css static/advanced-ops.js static/domain-readiness.js static/webtools.css static/webtools.js static/scheduled-tasks.css static/wordpress-lifecycle.js static/wordpress-staging.js panel/hosting_features.py; do
  test -f "/opt/nexvary-panel/$file"
done
for file in secret_vault.py vault_agent.py provider_agent.py database_agent.py webtools.py resource_usage.py bandwidth_accounting.py domain_ops.py webtools_agent.py scheduler_agent.py autossl_scheduler.py mail_agent.py mail_backend.py mail_sieve.py transfer_agent.py hosting_ops_agent.py hosting_ops_entry.py server_agent.py postgres_agent.py wordpress_agent.py wordpress_components.py wordpress_staging.py wordpress_entry.py; do
  test -f "/opt/nexvary-panel-agent/$file"
done
test "$(sudo stat -c '%a %U %G' /opt/nexvary-panel-agent/database_agent.py)" = "750 root root"
test "$(sudo stat -c '%a %U %G' /opt/nexvary-panel-agent/resource_usage.py)" = "640 root root"
test "$(sudo stat -c '%a %U %G' /opt/nexvary-panel-agent/bandwidth_accounting.py)" = "750 root root"
test "$(sudo stat -c '%a %U %G' /var/lib/nexvary-panel/usage)" = "700 root root"
test "$(sudo stat -c '%a %U %G' /opt/nexvary-panel-agent/scheduler_agent.py)" = "750 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /opt/nexvary-panel-agent/autossl_scheduler.py)" = "750 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /opt/nexvary-panel-agent/mail_sieve.py)" = "640 root root"
test "$(sudo stat -c '%a %U %G' /opt/nexvary-panel-agent/server_agent.py)" = "750 root root"
test "$(sudo stat -c '%a %U %G' /opt/nexvary-panel-agent/postgres_agent.py)" = "750 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /opt/nexvary-panel-agent/wordpress_agent.py)" = "750 root root"
test "$(sudo stat -c '%a %U %G' /opt/nexvary-panel-agent/wordpress_components.py)" = "640 root root"
test "$(sudo stat -c '%a %U %G' /opt/nexvary-panel-agent/wordpress_staging.py)" = "640 root root"
test "$(sudo stat -c '%a %U %G' /opt/nexvary-panel-agent/wordpress_entry.py)" = "750 root root"
test -f /etc/systemd/system/nexvary-panel-database.service
test -f /etc/systemd/system/nexvary-panel-autossl.service
test -f /etc/systemd/system/nexvary-panel-autossl.timer
test -f /etc/systemd/system/nexvary-panel-bandwidth.service
test -f /etc/systemd/system/nexvary-panel-bandwidth.timer
test -f /etc/systemd/system/nexvary-panel-server.service
test -f /etc/systemd/system/nexvary-panel-wordpress.service
grep -q '/opt/nexvary-panel-agent/database_agent.py' /etc/systemd/system/nexvary-panel-database.service
grep -q 'StateDirectory=nexvary-panel-database' /etc/systemd/system/nexvary-panel-database.service
grep -q '/opt/nexvary-panel-agent/bandwidth_accounting.py' /etc/systemd/system/nexvary-panel-bandwidth.service
grep -q '/opt/nexvary-panel-agent/server_agent.py' /etc/systemd/system/nexvary-panel-server.service
grep -q '/opt/nexvary-panel-agent/wordpress_entry.py' /etc/systemd/system/nexvary-panel-wordpress.service
sudo systemctl is-enabled --quiet nexvary-panel-autossl.timer
sudo systemctl is-active --quiet nexvary-panel-autossl.timer
sudo systemctl is-enabled --quiet nexvary-panel-bandwidth.timer
sudo systemctl is-active --quiet nexvary-panel-bandwidth.timer
test "$(sudo stat -c '%a %U %G' /etc/nexvary-panel/credentials)" = "700 root root"
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel/vault.sock)" = "660 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel/provider.sock)" = "660 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel/database.sock)" = "660 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel/ops.sock)" = "660 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel/server.sock)" = "660 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel/wordpress.sock)" = "660 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /var/lib/nexvary-panel-database)" = "700 root root"
sudo -u nexvary-panel python3 - <<'PY'
import json,socket
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(5);s.connect('/run/nexvary-panel/database.sock')
s.sendall(b'{"action":"status"}\n');data=b''
while not data.endswith(b'\n'): data+=s.recv(4096)
body=json.loads(data);assert body.get('ok') is True,body;assert body.get('engine')=='mariadb',body
PY

sudo -u nexvary-panel python3 - <<'PY'
import json,socket
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(10);s.connect('/run/nexvary-panel/server.sock')
s.sendall(b'{"action":"server-overview"}\n');data=b''
while not data.endswith(b'\n'): data+=s.recv(4096)
body=json.loads(data);s.close();assert body.get('ok') is True,body
assert body.get('hostname'),body
assert 'reboot_required' in body,body
PY

# Real MariaDB lifecycle: snapshot -> mutate -> restore -> verify -> clean.
sudo mariadb -e "DROP DATABASE IF EXISTS nvp_snapshot_gate; CREATE DATABASE nvp_snapshot_gate; CREATE TABLE nvp_snapshot_gate.gate_state(v VARCHAR(32)); INSERT INTO nvp_snapshot_gate.gate_state VALUES('before');"
read -r MARIA_ARCHIVE <<<"$(sudo -u nexvary-panel python3 - <<'PY'
import json,socket
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(180);s.connect('/run/nexvary-panel/database.sock')
s.sendall(b'{"action":"snapshot-create","db_name":"nvp_snapshot_gate"}\n');data=b''
while not data.endswith(b'\n'): data+=s.recv(8192)
body=json.loads(data);s.close();assert body.get('ok') is True,body
assert '/' not in body['archive'] and body['archive'].endswith('.sql'),body
assert len(body.get('sha256',''))==64 and int(body.get('size_bytes',0))>0,body
print(body['archive'])
PY
)"
sudo mariadb -e "UPDATE nvp_snapshot_gate.gate_state SET v='after';"
read -r MARIA_ROLLBACK <<<"$(sudo -u nexvary-panel env MARIA_ARCHIVE="$MARIA_ARCHIVE" python3 - <<'PY'
import json,os,socket
payload={'action':'snapshot-restore','db_name':'nvp_snapshot_gate','archive':os.environ['MARIA_ARCHIVE']}
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(360);s.connect('/run/nexvary-panel/database.sock')
s.sendall((json.dumps(payload)+'\n').encode());data=b''
while not data.endswith(b'\n'): data+=s.recv(8192)
body=json.loads(data);s.close();assert body.get('ok') is True,body
assert body.get('rollback_archive') and '/' not in body['rollback_archive'],body
print(body['rollback_archive'])
PY
)"
[[ "$(sudo mariadb --batch --skip-column-names nvp_snapshot_gate -e 'SELECT v FROM gate_state LIMIT 1')" == "before" ]]
sudo -u nexvary-panel env A="$MARIA_ARCHIVE" B="$MARIA_ROLLBACK" python3 - <<'PY'
import json,os,socket
for archive in (os.environ['A'],os.environ['B']):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(30);s.connect('/run/nexvary-panel/database.sock')
    s.sendall((json.dumps({'action':'snapshot-delete','archive':archive})+'\n').encode());data=b''
    while not data.endswith(b'\n'): data+=s.recv(8192)
    body=json.loads(data);s.close();assert body.get('ok') is True,body
PY
sudo mariadb -e "DROP DATABASE nvp_snapshot_gate;"

curl -kfsS https://127.0.0.1:8443/login | grep -q 'Nexvary Panel'
sudo nginx -t
