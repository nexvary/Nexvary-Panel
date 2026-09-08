#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-999} -eq 0 ]] || { echo 'Run as root: sudo bash installer/upgrade.sh'; exit 1; }
[[ -d /opt/nexvary-panel && -f /etc/nexvary-panel/admin.env ]] || { echo 'Existing Nexvary Panel installation not found.'; exit 2; }
. /etc/os-release
[[ "${ID:-}" =~ ^(ubuntu|debian)$ ]] || { echo 'Supported: Ubuntu / Debian'; exit 2; }
WITH_DOCKER=0
[[ "${1:-}" == "--with-docker" ]] && WITH_DOCKER=1
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y nginx python3 python3-venv python3-pip openssl certbot python3-certbot-nginx fail2ban ufw php-fpm mariadb-server nodejs ca-certificates curl rsync
if (( WITH_DOCKER )); then apt-get install -y docker.io; fi
cp -a app.py panel requirements.txt templates static /opt/nexvary-panel/
chown -R nexvary-panel:nexvary-panel /opt/nexvary-panel
/opt/nexvary-panel/venv/bin/pip install -r /opt/nexvary-panel/requirements.txt
install -m 0755 agent/nvpctl /usr/local/sbin/nvpctl
install -m 0750 -o root -g root agent/root_agent.py /opt/nexvary-panel-agent/root_agent.py
install -m 0644 systemd/nexvary-panel.service /etc/systemd/system/nexvary-panel.service
install -m 0644 systemd/nexvary-panel-agent.service /etc/systemd/system/nexvary-panel-agent.service
install -d -m 0700 -o root -g root /var/backups/nexvary-panel
systemctl daemon-reload
systemctl enable --now mariadb fail2ban nginx
if (( WITH_DOCKER )); then systemctl enable --now docker; fi
systemctl restart nexvary-panel-agent nexvary-panel
nginx -t
printf '\nUpgrade complete. Existing admin credentials and SQLite data were preserved.\n'
