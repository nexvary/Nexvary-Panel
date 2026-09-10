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
for svc in nginx mariadb nexvary-panel-agent nexvary-panel-vault nexvary-panel-provider nexvary-panel-webtools nexvary-panel-scheduler nexvary-panel-ops nexvary-panel; do check_service "$svc"; done
for file in panel/__init__.py panel/module_registry.py panel/routes_accounts.py panel/account_schema.py panel/routes_mail.py panel/mail_schema.py panel/routes_transfers.py panel/transfer_schema.py panel/routes_domains.py panel/domain_schema.py panel/routes_advanced_ops.py panel/ops_schema.py panel/ops_client.py static/app.css static/approved-theme.css static/hosting-suite.css static/accounts.css static/accounts.js static/mail.css static/mail.js static/transfers.css static/transfers.js static/advanced-ops.css static/advanced-ops.js static/webtools.css static/webtools.js static/scheduled-tasks.css panel/hosting_features.py; do
  test -f "/opt/nexvary-panel/$file"
done
for file in secret_vault.py vault_agent.py provider_agent.py webtools.py domain_ops.py webtools_agent.py scheduler_agent.py autossl_scheduler.py mail_agent.py mail_backend.py transfer_agent.py hosting_ops_agent.py hosting_ops_entry.py postgres_agent.py; do
  test -f "/opt/nexvary-panel-agent/$file"
done
test "$(sudo stat -c '%a %U %G' /opt/nexvary-panel-agent/scheduler_agent.py)" = "750 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /opt/nexvary-panel-agent/autossl_scheduler.py)" = "750 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /opt/nexvary-panel-agent/postgres_agent.py)" = "750 root nexvary-panel"
test -f /etc/systemd/system/nexvary-panel-autossl.service
test -f /etc/systemd/system/nexvary-panel-autossl.timer
sudo systemctl is-enabled --quiet nexvary-panel-autossl.timer
sudo systemctl is-active --quiet nexvary-panel-autossl.timer
test "$(sudo stat -c '%a %U %G' /etc/nexvary-panel/credentials)" = "700 root root"
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel/vault.sock)" = "660 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel/provider.sock)" = "660 root nexvary-panel"
test "$(sudo stat -c '%a %U %G' /run/nexvary-panel/ops.sock)" = "660 root nexvary-panel"
curl -kfsS https://127.0.0.1:8443/login | grep -q 'Nexvary Panel'
sudo nginx -t
