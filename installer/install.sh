#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-999} -eq 0 ]] || { echo 'Run as root: sudo bash installer/install.sh'; exit 1; }
. /etc/os-release
[[ "${ID:-}" =~ ^(ubuntu|debian)$ ]] || { echo 'Supported: Ubuntu / Debian'; exit 2; }
WITH_DOCKER=0
[[ "${1:-}" == "--with-docker" ]] && WITH_DOCKER=1
PANEL_VERSION="$(tr -d '[:space:]' < VERSION 2>/dev/null || printf 'unknown')"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y nginx python3 python3-venv python3-pip openssl certbot python3-certbot-nginx fail2ban ufw php-fpm mariadb-server nodejs ca-certificates curl rsync git
if (( WITH_DOCKER )); then apt-get install -y docker.io; fi

getent group nexvary-panel >/dev/null || groupadd --system nexvary-panel
id nexvary-panel >/dev/null 2>&1 || useradd --system --gid nexvary-panel --home /opt/nexvary-panel --shell /usr/sbin/nologin nexvary-panel
install -d -m 0750 -o nexvary-panel -g nexvary-panel /opt/nexvary-panel /var/lib/nexvary-panel
install -d -m 0750 -o root -g nexvary-panel /opt/nexvary-panel-agent
install -d -m 0750 -o root -g root /etc/nexvary-panel
install -d -m 0700 -o root -g root /var/backups/nexvary-panel
install -d -m 0750 -o root -g nexvary-panel /run/nexvary-panel
cp -a app.py panel requirements.txt templates static VERSION /opt/nexvary-panel/
python3 -m venv /opt/nexvary-panel/venv
/opt/nexvary-panel/venv/bin/pip install --upgrade pip
/opt/nexvary-panel/venv/bin/pip install -r /opt/nexvary-panel/requirements.txt
chown -R nexvary-panel:nexvary-panel /opt/nexvary-panel /var/lib/nexvary-panel
install -m 0755 agent/nvpctl /usr/local/sbin/nvpctl
install -m 0750 -o root -g root agent/root_agent.py /opt/nexvary-panel-agent/root_agent.py
rm -f /etc/sudoers.d/nexvary-panel

if [[ ! -f /etc/nexvary-panel/admin.env ]]; then
  PASS="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-20)"
  SALT="$(openssl rand -hex 16)"
  HASH="$(python3 - "$PASS" "$SALT" <<'PY'
import sys,hashlib
p,s=sys.argv[1:]
print(hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(s),310000).hex())
PY
)"
  SECRET="$(openssl rand -hex 32)"
  cat > /etc/nexvary-panel/admin.env <<EOF
NVP_ADMIN_SALT=$SALT
NVP_ADMIN_HASH=$HASH
NVP_SECRET=$SECRET
EOF
  chmod 0600 /etc/nexvary-panel/admin.env
else
  PASS='(existing password preserved)'
fi

install -m 0644 systemd/nexvary-panel.service /etc/systemd/system/nexvary-panel.service
install -m 0644 systemd/nexvary-panel-agent.service /etc/systemd/system/nexvary-panel-agent.service
CERT_DIR=/etc/nexvary-panel/tls
install -d -m 0700 "$CERT_DIR"
if [[ ! -f "$CERT_DIR/panel.crt" ]]; then
  openssl req -x509 -newkey rsa:3072 -nodes -days 825 -subj "/CN=Nexvary Panel" -keyout "$CERT_DIR/panel.key" -out "$CERT_DIR/panel.crt" >/dev/null 2>&1
  chmod 0600 "$CERT_DIR/panel.key"
fi

cat > /etc/nginx/sites-available/nexvary-panel.conf <<EOF
server {
 listen 8443 ssl; listen [::]:8443 ssl;
 server_name _;
 ssl_certificate $CERT_DIR/panel.crt;
 ssl_certificate_key $CERT_DIR/panel.key;
 ssl_protocols TLSv1.2 TLSv1.3;
 add_header X-Frame-Options DENY always;
 add_header X-Content-Type-Options nosniff always;
 add_header Referrer-Policy no-referrer always;
 add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
 add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'" always;
 client_max_body_size 16m;
 location / {
  proxy_pass http://127.0.0.1:9180;
  proxy_http_version 1.1;
  proxy_set_header Host \$host;
  proxy_set_header X-Real-IP \$remote_addr;
  proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto https;
 }
}
EOF
ln -sfn /etc/nginx/sites-available/nexvary-panel.conf /etc/nginx/sites-enabled/nexvary-panel.conf
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl daemon-reload
systemctl enable --now nginx mariadb fail2ban nexvary-panel-agent nexvary-panel
if (( WITH_DOCKER )); then systemctl enable --now docker; fi
ufw allow OpenSSH >/dev/null || true
ufw allow 80/tcp >/dev/null || true
ufw allow 443/tcp >/dev/null || true
ufw allow 8443/tcp >/dev/null || true

printf '\nNexvary Panel %s installed.\nOpen: https://SERVER_IP:8443\nUser: admin\nPassword: %s\n\nInitial TLS is self-signed. Assign a panel hostname before replacing it with a trusted certificate.\n' "$PANEL_VERSION" "$PASS"
if (( ! WITH_DOCKER )); then printf 'Docker was not installed. Re-run installer with --with-docker if you want Docker Center.\n'; fi
