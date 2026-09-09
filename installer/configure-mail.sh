#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-999} -eq 0 ]] || { echo 'configure-mail.sh must run as root'; exit 1; }
[[ -f /etc/nexvary-panel/tls/panel.crt && -f /etc/nexvary-panel/tls/panel.key ]] || { echo 'Panel TLS material is required before mail setup'; exit 2; }

getent group vmail >/dev/null || groupadd --system vmail
id vmail >/dev/null 2>&1 || useradd --system --gid vmail --home-dir /var/mail/vhosts --shell /usr/sbin/nologin vmail
VMAIL_UID="$(id -u vmail)"
VMAIL_GID="$(id -g vmail)"

install -d -m 0750 -o root -g root /etc/nexvary-panel/mail
install -d -m 0750 -o vmail -g vmail /var/mail/vhosts
install -d -m 0700 -o vmail -g vmail /var/mail/vhosts/.deleted
install -m 0640 -o root -g dovecot /dev/null /etc/nexvary-panel/mail/users
for map in domains vmailbox virtual; do
  install -m 0640 -o root -g postfix /dev/null "/etc/nexvary-panel/mail/$map"
  postmap "/etc/nexvary-panel/mail/$map"
  chown root:postfix "/etc/nexvary-panel/mail/$map.db"
  chmod 0640 "/etc/nexvary-panel/mail/$map.db"
done

postconf -e 'mydestination = localhost'
postconf -e 'virtual_mailbox_domains = hash:/etc/nexvary-panel/mail/domains'
postconf -e 'virtual_mailbox_base = /var/mail/vhosts'
postconf -e 'virtual_mailbox_maps = hash:/etc/nexvary-panel/mail/vmailbox'
postconf -e "virtual_uid_maps = static:${VMAIL_UID}"
postconf -e "virtual_gid_maps = static:${VMAIL_GID}"
postconf -e 'virtual_alias_maps = hash:/etc/nexvary-panel/mail/virtual'
postconf -e 'smtpd_tls_cert_file = /etc/nexvary-panel/tls/panel.crt'
postconf -e 'smtpd_tls_key_file = /etc/nexvary-panel/tls/panel.key'
postconf -e 'smtpd_tls_security_level = may'
postconf -e 'smtpd_tls_auth_only = yes'
postconf -e 'smtpd_sasl_type = dovecot'
postconf -e 'smtpd_sasl_path = private/auth'
postconf -e 'smtpd_sasl_auth_enable = yes'
postconf -e 'smtpd_recipient_restrictions = permit_mynetworks,permit_sasl_authenticated,reject_unauth_destination'
postconf -e 'disable_vrfy_command = yes'
postconf -e 'smtpd_helo_required = yes'

if ! grep -Eq '^submission[[:space:]]+inet' /etc/postfix/master.cf; then
cat >> /etc/postfix/master.cf <<'EOF'
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
EOF
fi

cat > /etc/dovecot/conf.d/99-nexvary-panel.conf <<EOF
protocols = imap
mail_location = maildir:/var/mail/vhosts/%d/%n/Maildir
first_valid_uid = ${VMAIL_UID}
last_valid_uid = ${VMAIL_UID}
auth_mechanisms = plain login
disable_plaintext_auth = yes
ssl = required
ssl_cert = </etc/nexvary-panel/tls/panel.crt
ssl_key = </etc/nexvary-panel/tls/panel.key

passdb {
  driver = passwd-file
  args = username_format=%u /etc/nexvary-panel/mail/users
}
userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
EOF
chmod 0644 /etc/dovecot/conf.d/99-nexvary-panel.conf

postfix check
dovecot -n >/dev/null
systemctl enable --now postfix dovecot
systemctl restart postfix dovecot
