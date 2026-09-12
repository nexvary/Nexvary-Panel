# Nexvary Panel

Nexvary Panel is a security-first Linux hosting and application control plane with a Royal Electric interface and strict privilege separation.

Current development track: **0.7.0**

## Core architecture

- Unprivileged Flask control plane composed through a validated Module Registry.
- Privileged operations split across narrow Unix-socket providers with explicit action allow-lists.
- No arbitrary root terminal or arbitrary command runner from the web interface.
- CSRF protection, PBKDF2 passwords, secure sessions, TOTP 2FA and Step-Up for sensitive mutations.
- Admin / Reseller / Operator / Viewer RBAC with ownership and hosting-package policy enforcement.
- Secret Vault, audit trail, operational notifications and reversible configuration changes.
- Ubuntu 24.04 clean-install gates plus real Chromium desktop/mobile release gates with screenshots.

## Platform 0.7 hosting capabilities

- Hosting packages, Feature Manager, per-account quotas and scoped reseller accounts.
- Static, PHP-FPM, Node.js, Python and reverse-proxy sites with NGINX validation before reload.
- Domain Lifecycle for aliases/subdomains plus Redirects, custom error pages and bounded access metrics.
- DNS inventory plus Cloudflare/PowerDNS zone binding, Preview → Apply → Rollback writes and DNSSEC lifecycle.
- SSL issuance/renewal through Certbot plus AutoSSL policy and scheduled renewal checks.
- Domain Readiness score combining hosting policy, DNS binding, pending DNS previews, SSL lifecycle and optional mail readiness.
- MariaDB and PostgreSQL provisioning with database passwords excluded from panel SQLite.
- Site-aware local backup/restore, remote backup providers, migration bundles and Scheduled Tasks.
- Scoped File Manager, Git Deploy and key-only chrooted SFTP Transfer Center.
- Postfix/Dovecot Email Center with mailboxes, forwarders, mail queue controls and deliverability checks for MX/SPF/DKIM/DMARC/MTA-STS/TLS-RPT.
- WordPress lifecycle: official core checksums, reversible Core Repair, Maintenance Mode, plugin/theme inventory and official WordPress.org component Check/Update/Rollback with snapshots.
- WordPress Staging/Safe Publish: clone or refresh into another managed PHP site with a separate quota-counted MariaDB database, Preview before publish, live files+database snapshot before replacement and tracked rollback of the latest publish. Current URL rewrite scope is intentionally limited to WordPress `home`/`siteurl` and does not claim serialized-content replacement yet.
- PHP runtime management, Docker inventory/lifecycle controls, service controls and Fleet foundation.
- NEXVARY Doctor, Trust Center, CrowdSec/Fail2Ban posture and Site Health inspection.

## Provider boundaries

Nexvary Panel integrates mature infrastructure through curated providers rather than exposing a generic privileged shell. Current provider/service boundaries include NGINX, Certbot, MariaDB, PostgreSQL, Postfix/Dovecot, OpenSSH/SFTP, WordPress.org, Docker, restic/rclone, Cloudflare/PowerDNS and the Nexvary Vault/Provider/Webtools/Ops agents.

Provider requests use fixed actions and validated arguments. Secrets remain in the Secret Vault or provider-owned credential files and are not returned in normal UI/API payloads. Configuration mutations validate before reload where applicable and preserve rollback paths for destructive or externally visible changes.

See `docs/FUSION_COMPONENTS.md` for the component/integration boundary manifest.

## Install

On a fresh supported Ubuntu/Debian host:

```bash
sudo bash installer/install.sh
```

Optional curated providers can be installed explicitly:

```bash
sudo bash installer/install.sh --with-docker --with-backup-providers --with-mail --with-sftp --with-postgres
```

Upgrade an existing Nexvary Panel installation while preserving panel state:

```bash
sudo bash installer/upgrade.sh
```

The same optional provider flags can be supplied during upgrade when those providers should be installed/configured.

## Release policy

Development changes remain outside `main` until the release gates pass. Platform 0.7 currently gates Python compilation and backend/security tests, a clean Ubuntu 24.04 base installation, Postfix/Dovecot installation, real key-only SFTP, PostgreSQL provider operation and real Chromium UI/overflow checks with screenshots.

A passing gate validates the tested head and environment; it is not a claim of universal production readiness across every distribution, provider or workload.

## Security boundaries

- Treat the panel as internet-facing administrative infrastructure.
- Keep browser-facing processes unprivileged.
- Do not weaken Unix-socket provider boundaries to simplify a feature.
- Do not store database passwords, cloud tokens, mailbox passwords or provider secrets in page HTML, ordinary API responses or audit details.
- Provider adapters must not concatenate user input into shell commands.
- Sensitive mutations require Step-Up where appropriate.
- Validate configuration changes before reload and preserve rollback paths.
- WordPress component updates accept installed slugs only and fetch packages only from official WordPress.org infrastructure.
- WordPress Safe Publish snapshots live files and the live database before replacement; staging uses a separate managed MariaDB database counted against account quota.

## Visual identity

The approved interface direction is deep navy + electric violet with luminous gold framing, electric green for healthy/live states and electric crimson for warnings/danger states. Arabic RTL and desktop/mobile layout are protected by Chromium release gates.
