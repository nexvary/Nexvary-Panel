#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-999} -eq 0 ]] || { echo 'Run as root: sudo bash installer/install-0.8.sh'; exit 1; }

# Pre-stage 0.8 privileged modules before the base installer starts systemd units.
# The base installer never deletes /opt/nexvary-panel-agent, so these root-owned files
# are present when provider/ops services start for the first time.
install -d -m 0750 -o root -g root /opt/nexvary-panel-agent
install -m 0640 -o root -g root agent/fleet_transport.py /opt/nexvary-panel-agent/fleet_transport.py
install -m 0640 -o root -g root agent/migration_adapters.py /opt/nexvary-panel-agent/migration_adapters.py
install -m 0750 -o root -g root agent/hosting_ops_08_entry.py /opt/nexvary-panel-agent/hosting_ops_08_entry.py

bash installer/install.sh "$@"

# The ops agent may have created the inbox as root during first start. Hand only this
# directory to the unprivileged panel process; privileged agents remain root-owned.
install -d -m 0700 -o nexvary-panel -g nexvary-panel /var/lib/nexvary-panel/migration-inbox
install -m 0755 -o root -g root installer/nvp-migration-stage /usr/local/sbin/nvp-migration-stage
systemctl restart nexvary-panel-provider nexvary-panel-ops nexvary-panel
systemctl is-active --quiet nexvary-panel-provider
systemctl is-active --quiet nexvary-panel-ops
systemctl is-active --quiet nexvary-panel
printf '\nNexvary Panel Platform 0.8 activation complete.\nLarge migration archives can be staged with: sudo nvp-migration-stage /path/to/backup.tar.gz\n'
