# Nexvary Panel

Nexvary Panel is a security-first Linux hosting and application control plane with a Royal Electric interface and strict privilege separation.

Current development track: **0.6.0**

## Core architecture

- Unprivileged Flask control plane.
- Privileged root-agent over a Unix socket with an explicit allow-list.
- No arbitrary root terminal from the web interface.
- CSRF protection, PBKDF2 passwords, secure sessions and TOTP 2FA.
- Admin / Operator / Viewer RBAC and per-site ownership.
- Audit trail and operational notifications.
- Ubuntu 24.04 full-install CI gate and Chromium UI release gate.

## Hosting capabilities

- Static, PHP-FPM, Node.js, Python and reverse-proxy sites.
- NGINX configuration validation before reload.
- Let's Encrypt via Certbot.
- MariaDB database/user provisioning.
- Site-aware backup and restore with safety snapshot.
- Safe site-root File Manager with symlink/traversal blocking.
- Git Deploy from allow-listed public Git hosts.
- WordPress core preparation and secure wp-config generation.
- Docker inventory/lifecycle controls.
- NEXVARY Doctor and service health.
- Site Health Inspector for DNS, TLS certificate/protocol/cipher and bounded Web Edge HEAD checks.

## NEXVARY Fusion Architecture

0.6 introduces a provider framework so Nexvary Panel can integrate mature open-source engines instead of reimplementing them.

The current read-only provider registry detects:

- NGINX
- Caddy
- Traefik
- CrowdSec
- Fail2Ban
- Authelia
- restic
- rclone
- Docker
- Podman
- PowerDNS

Fusion discovery uses fixed argv only, never `shell=True`, never auto-installs missing providers, and never gives the browser a generic command interface. Future write-capable adapters must pass through the root-agent allow-list and their own action schemas.

See `docs/FUSION_COMPONENTS.md` for the component/integration boundary manifest.

## Install

On a fresh supported Linux VPS:

```bash
sudo bash installer/install.sh
```

Optional Docker installation where supported by the installer:

```bash
sudo bash installer/install.sh --with-docker
```

Upgrade an existing Nexvary Panel installation while preserving panel state:

```bash
sudo bash installer/upgrade.sh
```

## Release policy

Changes are developed in branches and are not merged into `main` until the release gates pass. The gate includes Python compilation, shell syntax checks, security smoke tests, a clean Ubuntu 24.04 installation and real Chromium UI/overflow checks with screenshots.

## Security boundaries

- Treat the panel as internet-facing administrative infrastructure.
- Keep the web process unprivileged.
- Do not weaken the Unix-socket root-agent boundary to simplify a feature.
- Do not store database passwords, cloud tokens or provider secrets in page HTML or audit details.
- Provider adapters must not concatenate user input into shell commands.
- Validate and test configuration changes before reload and preserve rollback paths for destructive operations.

## Visual identity

The approved interface direction is deep navy + electric violet with luminous gold framing, electric green for healthy/live states and electric crimson for warnings/danger states. The approved Nexvary Panel brand image is used in the login and control shell.
