#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-999} -eq 0 ]] || { echo 'Run as root: sudo bash installer/install-0.9.sh'; exit 1; }

WITH_MAIL=0
for arg in "$@"; do
  [[ "$arg" == "--with-mail" ]] && WITH_MAIL=1
done

# Pre-stage 0.9 privileged modules before the base installer starts systemd units.
# The base installer never deletes /opt/nexvary-panel-agent, so these root-owned files
# are present when provider/ops services start for the first time.
install -d -m 0750 -o root -g root /opt/nexvary-panel-agent
install -m 0640 -o root -g root agent/fleet_transport.py /opt/nexvary-panel-agent/fleet_transport.py
install -m 0640 -o root -g root agent/migration_adapters.py /opt/nexvary-panel-agent/migration_adapters.py
install -m 0750 -o root -g root agent/hosting_ops_08_entry.py /opt/nexvary-panel-agent/hosting_ops_08_entry.py

# hosting_ops_08_entry starts under ProtectSystem=strict. Create its inbox before the
# first service start; ownership is handed to the panel user after the base installer
# creates that account. This avoids a fail/restart loop before ops.sock can be bound.
install -d -m 0700 -o root -g root /var/lib/nexvary-panel/migration-inbox

bash installer/install.sh "$@"

install -d -m 0700 -o nexvary-panel -g nexvary-panel /var/lib/nexvary-panel/migration-inbox
install -m 0755 -o root -g root installer/nvp-migration-stage /usr/local/sbin/nvp-migration-stage
systemctl restart nexvary-panel-provider nexvary-panel-ops nexvary-panel

if (( WITH_MAIL )); then
  bash installer/configure-dav.sh
fi

for _ in {1..30}; do
  [[ -S /run/nexvary-panel/provider.sock && -S /run/nexvary-panel/ops.sock ]] && break
  sleep 1
done
[[ -S /run/nexvary-panel/provider.sock ]] || { echo 'Platform 0.9 provider socket did not become ready.' >&2; exit 3; }
[[ -S /run/nexvary-panel/ops.sock ]] || { echo 'Platform 0.9 ops socket did not become ready.' >&2; exit 3; }
if (( WITH_MAIL )); then
  [[ -S /run/nexvary-panel/dav.sock ]] || { echo 'Platform 0.9 DAV provider socket did not become ready.' >&2; exit 3; }
fi

for _ in {1..30}; do
  curl -kfsS https://127.0.0.1:8443/login >/dev/null 2>&1 && break
  sleep 1
done
curl -kfsS https://127.0.0.1:8443/login >/dev/null

systemctl is-active --quiet nexvary-panel-provider
systemctl is-active --quiet nexvary-panel-ops
systemctl is-active --quiet nexvary-panel
if (( WITH_MAIL )); then
  systemctl is-active --quiet nexvary-panel-dav
  systemctl is-active --quiet nexvary-panel-dav-agent
fi
printf '\nNexvary Panel Platform 0.9 activation complete.\nLarge migration archives can be staged with: sudo nvp-migration-stage /path/to/backup.tar.gz\n'
if (( WITH_MAIL )); then printf 'CalDAV/CardDAV is active through the scoped /dav/ endpoint.\n'; fi
