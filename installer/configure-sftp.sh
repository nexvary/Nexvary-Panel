#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-999} -eq 0 ]] || { echo 'configure-sftp.sh must run as root'; exit 1; }
command -v sshd >/dev/null || { echo 'openssh-server is required'; exit 2; }
command -v setfacl >/dev/null || { echo 'acl package is required'; exit 2; }

getent group nexvary-sftp >/dev/null || groupadd --system nexvary-sftp
# Public keys are not secrets. OpenSSH may read AuthorizedKeysFile under the
# target account's credentials, so the central directory must be traversable
# by the SFTP group while remaining root-owned and non-writable.
install -d -m 0750 -o root -g nexvary-sftp /etc/nexvary-panel/sftp-keys
install -d -m 0700 -o root -g root /etc/nexvary-panel/sftp-mounts
install -d -m 0755 -o root -g root /srv/nexvary-sftp
install -d -m 0755 -o root -g root /run/sshd

cat > /etc/ssh/sshd_config.d/90-nexvary-sftp.conf <<'EOF'
Match Group nexvary-sftp
    ChrootDirectory /srv/nexvary-sftp/%u
    ForceCommand internal-sftp -d /site
    AuthorizedKeysFile /etc/nexvary-panel/sftp-keys/%u
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
