#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-999} -eq 0 ]] || { echo 'Run as root: sudo bash installer/upgrade.sh'; exit 1; }
[[ -d /opt/nexvary-panel && -f /etc/nexvary-panel/admin.env ]] || { echo 'Existing Nexvary Panel installation not found.'; exit 2; }
. /etc/os-release
[[ "${ID:-}" =~ ^(ubuntu|debian)$ ]] || { echo 'Supported: Ubuntu / Debian'; exit 2; }
WITH_DOCKER=0
WITH_BACKUP_PROVIDERS=0
for arg in "$@"; do
  case "$arg" in
    --with-docker) WITH_DOCKER=1 ;;
    --with-backup-providers) WITH_BACKUP_PROVIDERS=1 ;;
    *) echo "Unknown upgrade option: $arg"; exit 2 ;;
  esac
done
PANEL_VERSION="$(tr -d '[:space:]' < VERSION 2>/dev/null || printf 'unknown')"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y nginx python3 python3-venv python3-pip openssl certbot python3-certbot-nginx fail2ban ufw php-fpm mariadb-server nodejs ca-certificates curl rsync git
if (( WITH_DOCKER )); then apt-get install -y docker.io; fi
if (( WITH_BACKUP_PROVIDERS )); then apt-get install -y restic rclone; fi
cp -a app.py panel requirements.txt templates static VERSION /opt/nexvary-panel/
chown -R nexvary-panel:nexvary-panel /opt/nexvary-panel
/opt/nexvary-panel/venv/bin/pip install -r /opt/nexvary-panel/requirements.txt
install -d -m 0750 -o root -g nexvary-panel /opt/nexvary-panel-agent /run/nexvary-panel
install -d -m 0750 -o root -g root /etc/nginx/nexvary
install -d -m 0700 -o root -g root /etc/nexvary-panel/credentials /var/backups/nexvary-panel
install -m 0755 agent/nvpctl /usr/local/sbin/nvpctl
install -m 0750 -o root -g root agent/root_agent.py /opt/nexvary-panel-agent/root_agent.py
install -m 0640 -o root -g root agent/secret_vault.py /opt/nexvary-panel-agent/secret_vault.py
install -m 0750 -o root -g root agent/vault_agent.py /opt/nexvary-panel-agent/vault_agent.py
install -m 0750 -o root -g root agent/provider_agent.py /opt/nexvary-panel-agent/provider_agent.py
install -m 0640 -o root -g root agent/webtools.py /opt/nexvary-panel-agent/webtools.py
install -m 0750 -o root -g root agent/webtools_agent.py /opt/nexvary-panel-agent/webtools_agent.py
install -m 0750 -o root -g nexvary-panel agent/scheduler_agent.py /opt/nexvary-panel-agent/scheduler_agent.py
install -m 0644 systemd/nexvary-panel.service /etc/systemd/system/nexvary-panel.service
install -m 0644 systemd/nexvary-panel-agent.service /etc/systemd/system/nexvary-panel-agent.service
install -m 0644 systemd/nexvary-panel-vault.service /etc/systemd/system/nexvary-panel-vault.service
install -m 0644 systemd/nexvary-panel-provider.service /etc/systemd/system/nexvary-panel-provider.service
install -m 0644 systemd/nexvary-panel-webtools.service /etc/systemd/system/nexvary-panel-webtools.service
install -m 0644 systemd/nexvary-panel-scheduler.service /etc/systemd/system/nexvary-panel-scheduler.service
systemctl daemon-reload
systemctl enable --now mariadb fail2ban nginx nexvary-panel-vault nexvary-panel-provider nexvary-panel-webtools nexvary-panel-scheduler
if (( WITH_DOCKER )); then systemctl enable --now docker; fi
systemctl restart nexvary-panel-agent nexvary-panel-vault nexvary-panel-provider nexvary-panel-webtools nexvary-panel-scheduler nexvary-panel
nginx -t
printf '\nNexvary Panel %s upgrade complete. Existing admin credentials, Secret Vault, Integration Targets and SQLite data were preserved.\n' "$PANEL_VERSION"
if (( ! WITH_BACKUP_PROVIDERS )); then printf 'restic/rclone package state was preserved. Use --with-backup-providers to install/enable the curated backup engines.\n'; fi
