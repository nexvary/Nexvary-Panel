# Nexvary Panel

**Nexvary Panel** is a security-first server and hosting control panel for Ubuntu and Debian. The project is an original implementation inspired by proven workflows from major hosting panels, without copying proprietary source code, branding, icons, or UI assets.

## Current release candidate: 0.2.1

Implemented today:

- Arabic RTL responsive dashboard.
- Live CPU, RAM and disk telemetry.
- Static, PHP-FPM, Node.js starter, Python starter and Reverse Proxy sites.
- NGINX configuration validation before reload.
- Site enable/disable and per-site NGINX logs.
- Let's Encrypt issuance through Certbot.
- MariaDB database and user creation, with database passwords not stored in panel SQLite.
- Site-aware local backups with MariaDB dump when a database is linked.
- NEXVARY Doctor diagnostics.
- Docker inventory plus start/stop/restart for existing containers.
- Admin / Operator / Viewer RBAC and ownership checks.
- Audit log, login throttling, PBKDF2 password hashing, CSRF and secure cookies.
- Unprivileged web service separated from a root Agent over a Unix socket.

## Architecture

```text
Browser
  -> NGINX :8443 (TLS + security headers)
  -> Gunicorn / Flask as unprivileged nexvary-panel user
  -> Unix socket
  -> root Agent
  -> strict nvpctl allowlist
```

The browser-facing process does not receive sudo access and cannot submit arbitrary shell commands to the root Agent.

## Install on a fresh server

Supported target for the current gate: Ubuntu 24.04. The installer also accepts Ubuntu/Debian families.

```bash
git clone https://github.com/nexvary/Nexvary-Panel.git
cd Nexvary-Panel
sudo bash installer/install.sh
```

Optional Docker installation:

```bash
sudo bash installer/install.sh --with-docker
```

Then open:

```text
https://SERVER_IP:8443
```

The installer prints the initial `admin` password once. The first panel certificate is self-signed.

## Upgrade

```bash
cd Nexvary-Panel
sudo bash installer/upgrade.sh
```

The upgrade path preserves the bootstrap administrator credentials and `/var/lib/nexvary-panel/panel.db`.

## GitHub Release Gate

A pull request to `main` must pass three independent checks:

1. **Code and security smoke checks** — Python compilation, shell syntax, authentication, CSRF and dashboard smoke tests.
2. **Ubuntu 24.04 full installer gate** — runs the real installer on a clean GitHub runner, verifies systemd services, installed package files, NGINX and the HTTPS login page.
3. **Real browser UI gate** — starts the actual Flask app, signs in with an ephemeral CI identity, tests desktop and 390px mobile layouts, checks required sections and horizontal overflow, then uploads real Chromium screenshots as a GitHub Actions artifact.

## Safety boundaries in 0.2.1

- No arbitrary web terminal with root privileges.
- No arbitrary root command runner.
- No arbitrary Docker image execution from the panel.
- No destructive database/site delete or backup restore yet.
- Node/Python modes create hardened starter services; full Git-based deployments are planned for a later release.

## Roadmap

**0.3** — jailed File Manager, WordPress Manager, Git deployment, restore testing, S3/Rclone targets, 2FA/TOTP, notifications and richer live logs.

**0.4** — DNS/mail modules, staging/clone/sync, package quotas, reseller/client subscriptions, Cloudflare integration and migration tooling.

**0.5+** — multi-server fleet management, high availability, extension catalog, policy engine, automated update regression gates and white-label themes.

## Licensing note

No open-source license has been selected yet. A license should be chosen deliberately before third-party distribution or contribution rules are finalized.
