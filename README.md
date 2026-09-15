# Nexvary Panel

Nexvary Panel is a security-first Linux hosting and application control plane with a Royal Electric interface and strict privilege separation.

Current development track: **0.8.0 — Competitive Parity Closure**

## Core architecture

- Unprivileged Flask control plane composed through a validated Module Registry.
- Privileged operations split across narrow Unix-socket providers with explicit action allow-lists.
- No arbitrary root terminal or arbitrary command runner from the web interface.
- CSRF protection, PBKDF2 passwords, secure sessions, TOTP 2FA and Step-Up for sensitive mutations.
- Admin / Reseller / Operator / Viewer RBAC with ownership and hosting-package policy enforcement.
- Secret Vault, audit trail, operational notifications and reversible configuration changes.
- Ubuntu 24.04 clean-install gates plus real Chromium desktop/mobile release gates with screenshots.

## Platform 0.8 hosting capabilities

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
- PHP runtime management, Docker inventory/lifecycle controls, service controls and server lifecycle operations.
- Reviewed system-update execution: Preview → fingerprint → immediate revalidation → privileged apply; stale plans fail closed.
- Fleet Orchestration with health/capability probing, one-time pairing tokens, Secret Vault credential references, authenticated allow-listed remote apply, request timestamps, idempotency/replay protection and inbound/outbound job history.
- Migration Center 2.0 compatibility inspection and normalization for cPanel, DirectAdmin and Plesk website/MariaDB archive layouts, reusing the existing NEXVARY restore/rollback path.
- Large migration archives can be staged locally under the privileged migration policy while browser uploads remain bounded by the reverse-proxy request policy.
- Curated Extension Hub contracts and kill switches for provider-backed surfaces, including Fleet and Migration Center; arbitrary extension code execution is not permitted.
- NEXVARY Doctor, Trust Center, CrowdSec/Fail2Ban posture and Site Health inspection.

## Provider boundaries

Nexvary Panel integrates mature infrastructure through curated providers rather than exposing a generic privileged shell. Current provider/service boundaries include NGINX, Certbot, MariaDB, PostgreSQL, Postfix/Dovecot, OpenSSH/SFTP, WordPress.org, Docker, restic/rclone, Cloudflare/PowerDNS and the Nexvary Vault/Provider/Webtools/Ops/Server agents.

Provider requests use fixed actions and validated arguments. Secrets remain in the Secret Vault or provider-owned credential files and are not returned in normal UI/API payloads. Configuration mutations validate before reload where applicable and preserve rollback paths for destructive or externally visible changes.

See `docs/FUSION_COMPONENTS.md` for the component/integration boundary manifest and `docs/PLATFORM_0.8_PARITY.md` for the targeted 0.8 parity closure contract.

## Install

On a fresh supported Ubuntu/Debian host for Platform 0.8:

```bash
sudo bash installer/install-0.8.sh
```

Optional curated providers can be installed explicitly:

```bash
sudo bash installer/install-0.8.sh --with-docker --with-backup-providers --with-mail --with-sftp --with-postgres
```

Upgrade an existing Nexvary Panel installation while preserving panel state:

```bash
sudo bash installer/upgrade-0.8.sh
```

The same optional provider flags can be supplied during upgrade when those providers should be installed/configured. Large external-panel backup archives should be copied to the host and staged with the installed `nvp-migration-stage` helper instead of increasing the browser upload limit.

## Release policy

Platform 0.8 is gated on the same candidate commit by Python compilation and backend/security/parity tests, a clean Ubuntu 24.04 base installation, Postfix/Dovecot installation, real key-only SFTP, PostgreSQL provider operation and real Chromium UI/overflow checks with screenshot artifacts.

A passing gate validates the tested head and environment; it is not a claim of universal production readiness across every distribution, provider, external-panel archive or workload.

## Security boundaries

- Treat the panel as internet-facing administrative infrastructure.
- Keep browser-facing processes unprivileged.
- Do not weaken Unix-socket provider boundaries to simplify a feature.
- Do not store database passwords, cloud tokens, mailbox passwords or provider secrets in page HTML, ordinary API responses or audit details.
- Provider adapters must not concatenate user input into shell commands.
- Sensitive mutations require Step-Up where appropriate.
- Validate configuration changes before reload and preserve rollback paths.
- Fleet operations are fixed allow-listed actions; no arbitrary remote shell is exposed.
- Remote system updates require the exact reviewed fingerprint and reject stale plans.
- Migration archives reject traversal, links/devices and unsafe archive entries before normalization.
- WordPress component updates accept installed slugs only and fetch packages only from official WordPress.org infrastructure.
- WordPress Safe Publish snapshots live files and the live database before replacement; staging uses a separate managed MariaDB database counted against account quota.

## Competitive scope note

Platform 0.8 closes the targeted gaps identified at the end of the 0.7 track: reviewed system-update apply, authenticated allow-listed Fleet apply, multi-panel migration adapters, and curated extension contracts for the new surfaces. The closure is enforced by `tests/platform_08_parity_test.py` and documented in `docs/PLATFORM_0.8_PARITY.md`.

This remains a clean-room capability effort and is not a claim that Nexvary Panel duplicates every feature, integration, historical compatibility edge case or third-party marketplace workflow of long-established hosting products. Serialized WordPress content replacement, every possible mail/server administration workflow and arbitrary third-party extension execution remain outside this targeted 0.8 closure unless separately implemented and gated.

## Visual identity

The approved interface direction is deep navy + electric violet with luminous gold framing, electric green for healthy/live states and electric crimson for warnings/danger states. Arabic RTL and desktop/mobile layout are protected by Chromium release gates.
