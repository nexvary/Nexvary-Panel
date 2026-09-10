#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-999} -eq 0 ]] || { echo 'Run as root: sudo bash installer/install.sh'; exit 1; }
. /etc/os-release
[[ "${ID:-}" =~ ^(ubuntu|debian)$ ]] || { echo 'Supported: Ubuntu / Debian'; exit 2; }
WITH_DOCKER=0
WITH_BACKUP_PROVIDERS=0
WITH_MAIL=0
WITH_SFTP=0
WITH_POSTGRES=0
for arg in "$@"; do
  case "$arg" in
    --with-docker) WITH_DOCKER=1 ;;
    --with-backup-providers) WITH_BACKUP_PROVIDERS=1 ;;
    --with-mail) WITH_MAIL=1 ;;
    --with-sftp) WITH_SFTP=1 ;;
    --with-postgres) WITH_POSTGRES=1 ;;
    *) echo "Unknown installer option: $arg"; exit 2 ;;
  esac
done
PANEL_VERSION="$(tr -d '[:space:]' < VERSION 2>/dev/null || printf 'unknown')"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y nginx python3 python3-venv python3-pip openssl certbot python3-certbot-nginx fail2ban ufw php-fpm mariadb-server nodejs ca-certificates curl rsync git
if (( WITH_DOCKER )); then apt-get install -y docker.io; fi
if (( WITH_BACKUP_PROVIDERS )); then apt-get install -y restic rclone; fi
if (( WITH_MAIL )); then
  MAILNAME="$(hostname -f 2>/dev/null || hostname)"
  echo "postfix postfix/mailname string ${MAILNAME}" | debconf-set-selections
  echo 'postfix postfix/main_mailer_type select Internet Site' | debconf-set-selections
  apt-get install -y postfix dovecot-core dovecot-imapd
fi
if (( WITH_SFTP )); then apt-get install -y openssh-server acl; fi
if (( WITH_POSTGRES )); then apt-get install -y postgresql postgresql-client; fi

getent group nexvary-panel >/dev/null || groupadd --system nexvary-panel
id nexvary-panel >/dev/null 2>&1 || useradd --system --gid nexvary-panel --home /opt/nexvary-panel --shell /usr/sbin/nologin nexvary-panel
install -d -m 0750 -o nexvary-panel -g nexvary-panel /opt/nexvary-panel /var/lib/nexvary-panel
install -d -m 0750 -o root -g nexvary-panel /opt/nexvary-panel-agent
install -d -m 0750 -o root -g root /etc/nexvary-panel /etc/nginx/nexvary
install -d -m 0700 -o root -g root /etc/nexvary-panel/credentials /var/backups/nexvary-panel /var/backups/nexvary-panel/migrations
install -d -m 0750 -o root -g nexvary-panel /run/nexvary-panel
cp -a app.py panel requirements.txt templates static VERSION /opt/nexvary-panel/
python3 -m venv /opt/nexvary-panel/venv
/opt/nexvary-panel/venv/bin/pip install --upgrade pip
/opt/nexvary-panel/venv/bin/pip install -r /opt/nexvary-panel/requirements.txt
chown -R nexvary-panel:nexvary-panel /opt/nexvary-panel /var/lib/nexvary-panel
install -m 0755 agent/nvpctl /usr/local/sbin/nvpctl
install -m 0750 -o root -g root agent/root_agent.py /opt/nexvary-panel-agent/root_agent.py
install -m 0640 -o root -g root agent/secret_vault.py /opt/nexvary-panel-agent/secret_vault.py
install -m 0750 -o root -g root agent/vault_agent.py /opt/nexvary-panel-agent/vault_agent.py
install -m 0750 -o root -g root agent/provider_agent.py /opt/nexvary-panel-agent/provider_agent.py
install -m 0640 -o root -g root agent/webtools.py /opt/nexvary-panel-agent/webtools.py
install -m 0640 -o root -g root agent/domain_ops.py /opt/nexvary-panel-agent/domain_ops.py
install -m 0750 -o root -g root agent/webtools_agent.py /opt/nexvary-panel-agent/webtools_agent.py
install -m 0750 -o root -g nexvary-panel agent/scheduler_agent.py /opt/nexvary-panel-agent/scheduler_agent.py
install -m 0640 -o root -g root agent/mail_backend.py /opt/nexvary-panel-agent/mail_backend.py
install -m 0750 -o root -g root agent/mail_agent.py /opt/nexvary-panel-agent/mail_agent.py
install -m 0750 -o root -g root agent/transfer_agent.py /opt/nexvary-panel-agent/transfer_agent.py
install -m 0750 -o root -g root agent/hosting_ops_agent.py /opt/nexvary-panel-agent/hosting_ops_agent.py
install -m 0750 -o root -g root agent/hosting_ops_entry.py /opt/nexvary-panel-agent/hosting_ops_entry.py
install -m 0750 -o root -g nexvary-panel agent/postgres_agent.py /opt/nexvary-panel-agent/postgres_agent.py
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
install -m 0644 systemd/nexvary-panel-vault.service /etc/systemd/system/nexvary-panel-vault.service
install -m 0644 systemd/nexvary-panel-provider.service /etc/systemd/system/nexvary-panel-provider.service
install -m 0644 systemd/nexvary-panel-webtools.service /etc/systemd/system/nexvary-panel-webtools.service
install -m 0644 systemd/nexvary-panel-scheduler.service /etc/systemd/system/nexvary-panel-scheduler.service
install -m 0644 systemd/nexvary-panel-mail.service /etc/systemd/system/nexvary-panel-mail.service
install -m 0644 systemd/nexvary-panel-transfer.service /etc/systemd/system/nexvary-panel-transfer.service
install -m 0644 systemd/nexvary-panel-ops.service /etc/systemd/system/nexvary-panel-ops.service
install -m 0644 systemd/nexvary-panel-postgres.service /etc/systemd/system/nexvary-panel-postgres.service
CERT_DIR=/etc/nexvary-panel/tls
install -d -m 0700 "$CERT_DIR"
if [[ ! -f "$CERT_DIR/panel.crt" ]]; then
  openssl req -x509 -newkey rsa:3072 -nodes -days 825 -subj "/CN=Nexvary Panel" -keyout "$CERT_DIR/panel.key" -out "$CERT_DIR/panel.crt" >/dev/null 2>&1
  chmod 0600 "$CERT_DIR/panel.key"
fi

if (( WITH_MAIL )); then bash installer/configure-mail.sh; fi
if (( WITH_SFTP )); then bash installer/configure-sftp.sh; fi

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
systemctl enable --now nginx mariadb fail2ban nexvary-panel-agent nexvary-panel-vault nexvary-panel-provider nexvary-panel-webtools nexvary-panel-scheduler nexvary-panel-ops nexvary-panel
if (( WITH_DOCKER )); then systemctl enable --now docker; fi
if (( WITH_MAIL )); then systemctl enable --now nexvary-panel-mail; fi
if (( WITH_SFTP )); then systemctl enable --now nexvary-panel-transfer; fi
if (( WITH_POSTGRES )); then systemctl enable --now postgresql nexvary-panel-postgres; fi
ufw allow OpenSSH >/dev/null || true
ufw allow 80/tcp >/dev/null || true
ufw allow 443/tcp >/dev/null || true
ufw allow 8443/tcp >/dev/null || true
if (( WITH_MAIL )); then
  ufw allow 25/tcp >/dev/null || true
  ufw allow 587/tcp >/dev/null || true
  ufw allow 993/tcp >/dev/null || true
fi

printf '\nNexvary Panel %s installed.\nOpen: https://SERVER_IP:8443\nUser: admin\nPassword: %s\n\nInitial TLS is self-signed. Assign a panel hostname before replacing it with a trusted certificate.\n' "$PANEL_VERSION" "$PASS"
if (( ! WITH_DOCKER )); then printf 'Docker was not installed. Re-run installer with --with-docker if you want Docker Center.\n'; fi
if (( ! WITH_BACKUP_PROVIDERS )); then printf 'restic/rclone were not installed. Re-run installer with --with-backup-providers to enable Fusion remote backup engines.\n'; fi
if (( ! WITH_MAIL )); then printf 'Postfix/Dovecot were not configured. Re-run installer with --with-mail to enable the local Email Stack.\n'; fi
if (( ! WITH_SFTP )); then printf 'Key-only SFTP Transfer Center was not configured. Re-run installer with --with-sftp to enable it.\n'; fi
if (( ! WITH_POSTGRES )); then printf 'PostgreSQL was not installed. Re-run installer with --with-postgres to enable PostgreSQL resources.\n'; fi
