#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-999} -eq 0 ]] || { echo 'configure-dav.sh must run as root'; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y radicale apache2-utils python3-bcrypt

getent group radicale >/dev/null || groupadd --system radicale
id radicale >/dev/null 2>&1 || useradd --system --gid radicale --home-dir /var/lib/nexvary-panel/dav --shell /usr/sbin/nologin radicale
getent group nexvary-panel >/dev/null || { echo 'nexvary-panel group is required'; exit 2; }

systemctl disable --now radicale.service >/dev/null 2>&1 || true

install -d -m 0750 -o root -g radicale /etc/nexvary-panel/radicale
install -d -m 0750 -o radicale -g radicale /var/lib/nexvary-panel/dav /var/lib/nexvary-panel/dav/collections
if [[ ! -e /etc/nexvary-panel/radicale/users ]]; then
  install -m 0640 -o root -g radicale /dev/null /etc/nexvary-panel/radicale/users
else
  [[ ! -L /etc/nexvary-panel/radicale/users && -f /etc/nexvary-panel/radicale/users ]] || { echo 'Unsafe DAV users file boundary'; exit 3; }
  chown root:radicale /etc/nexvary-panel/radicale/users
  chmod 0640 /etc/nexvary-panel/radicale/users
fi

cat > /etc/nexvary-panel/radicale/config <<'EOF'
[server]
hosts = 127.0.0.1:5232
max_connections = 20
timeout = 30

[auth]
type = htpasswd
htpasswd_filename = /etc/nexvary-panel/radicale/users
htpasswd_encryption = bcrypt
delay = 1

[rights]
type = owner_only

[storage]
filesystem_folder = /var/lib/nexvary-panel/dav/collections

[web]
type = internal

[logging]
level = warning
EOF
chown root:radicale /etc/nexvary-panel/radicale/config
chmod 0640 /etc/nexvary-panel/radicale/config

install -d -m 0750 -o root -g root /opt/nexvary-panel-agent
install -m 0750 -o root -g root agent/dav_agent.py /opt/nexvary-panel-agent/dav_agent.py
install -m 0644 systemd/nexvary-panel-dav.service /etc/systemd/system/nexvary-panel-dav.service
install -m 0644 systemd/nexvary-panel-dav-agent.service /etc/systemd/system/nexvary-panel-dav-agent.service

NGINX_SITE=/etc/nginx/sites-available/nexvary-panel.conf
[[ -f "$NGINX_SITE" ]] || { echo 'Nexvary Panel nginx site is required before DAV setup'; exit 4; }
python3 - "$NGINX_SITE" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1])
text=path.read_text(encoding='utf-8')
marker='  # NEXVARY_DAV_BEGIN\n'
if marker not in text:
    block='''  # NEXVARY_DAV_BEGIN
  location = /.well-known/caldav { return 308 /dav/; }
  location = /.well-known/carddav { return 308 /dav/; }
  location /dav/ {
    proxy_pass http://127.0.0.1:5232/;
    proxy_set_header X-Script-Name /dav;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Port $server_port;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Host $http_host;
    proxy_set_header Authorization $http_authorization;
  }
  # NEXVARY_DAV_END
'''
    pos=text.rfind('}')
    if pos < 0:
        raise SystemExit('nginx-server-block-not-found')
    text=text[:pos]+block+text[pos:]
    path.write_text(text,encoding='utf-8')
PY

nginx -t
systemctl daemon-reload
systemctl enable --now nexvary-panel-dav nexvary-panel-dav-agent
systemctl reload nginx

for _ in {1..30}; do
  systemctl is-active --quiet nexvary-panel-dav && [[ -S /run/nexvary-panel/dav.sock ]] && break
  sleep 1
done
systemctl is-active --quiet nexvary-panel-dav
systemctl is-active --quiet nexvary-panel-dav-agent
[[ -S /run/nexvary-panel/dav.sock ]] || { echo 'DAV provider socket did not become ready'; exit 5; }
curl -fsS -o /dev/null http://127.0.0.1:5232/ || true
printf 'Nexvary Panel CalDAV/CardDAV provider configured at /dav/.\n'
