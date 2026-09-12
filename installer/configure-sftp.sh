#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-999} -eq 0 ]] || { echo 'configure-sftp.sh must run as root'; exit 1; }
command -v sshd >/dev/null || { echo 'openssh-server is required'; exit 2; }
command -v setfacl >/dev/null || { echo 'acl package is required'; exit 2; }

getent group nexvary-sftp >/dev/null || groupadd --system nexvary-sftp
NEW_KEYS=/etc/ssh/nexvary-authorized-keys
OLD_KEYS=/etc/nexvary-panel/sftp-keys
install -d -m 0750 -o root -g nexvary-sftp "$NEW_KEYS"
install -d -m 0700 -o root -g root /etc/nexvary-panel/sftp-mounts
install -d -m 0755 -o root -g root /srv/nexvary-sftp
install -d -m 0755 -o root -g root /run/sshd

# Upgrade-safe migration: these are public keys, not secrets. Keep the
# protected /etc/nexvary-panel parent non-traversable to SFTP accounts.
if [[ -d "$OLD_KEYS" && ! -L "$OLD_KEYS" ]]; then
  shopt -s nullglob
  for src in "$OLD_KEYS"/nvpt_*; do
    [[ -f "$src" && ! -L "$src" ]] || continue
    base="$(basename "$src")"
    [[ "$base" =~ ^nvpt_[a-f0-9]{10}$ ]] || continue
    install -m 0640 -o root -g nexvary-sftp "$src" "$NEW_KEYS/$base"
  done
  shopt -u nullglob
fi

cat > /etc/ssh/sshd_config.d/90-nexvary-sftp.conf <<'EOF'
Match Group nexvary-sftp
    ChrootDirectory /srv/nexvary-sftp/%u
    ForceCommand internal-sftp -d /site
    AuthorizedKeysFile /etc/ssh/nexvary-authorized-keys/%u
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PubkeyAuthentication yes
    PermitTTY no
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
    GatewayPorts no
EOF
chmod 0644 /etc/ssh/sshd_config.d/90-nexvary-sftp.conf
sshd -t
systemctl enable --now ssh
systemctl reload ssh
