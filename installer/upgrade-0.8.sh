#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-999} -eq 0 ]] || { echo 'Run as root: sudo bash installer/upgrade-0.8.sh'; exit 1; }

install -d -m 0750 -o root -g root /opt/nexvary-panel-agent
install -m 0640 -o root -g root agent/fleet_transport.py /opt/nexvary-panel-agent/fleet_transport.py
install -m 0640 -o root -g root agent/migration_adapters.py /opt/nexvary-panel-agent/migration_adapters.py
install -m 0750 -o root -g root agent/hosting_ops_08_entry.py /opt/nexvary-panel-agent/hosting_ops_08_entry.py

bash installer/upgrade.sh "$@"

install -d -m 0700 -o nexvary-panel -g nexvary-panel /var/lib/nexvary-panel/migration-inbox
install -m 0755 -o root -g root installer/nvp-migration-stage /usr/local/sbin/nvp-migration-stage
systemctl restart nexvary-panel-provider nexvary-panel-ops nexvary-panel
systemctl is-active --quiet nexvary-panel-provider
systemctl is-active --quiet nexvary-panel-ops
systemctl is-active --quiet nexvary-panel
printf '\nNexvary Panel Platform 0.8 upgrade activation complete.\n'
