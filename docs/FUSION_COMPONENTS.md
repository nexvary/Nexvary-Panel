# Nexvary Fusion Components Policy

This file is the engineering allow-list for third-party technology used by Nexvary Panel.
It is not a substitute for legal review. Before redistributing any third-party source or binary, re-check the exact upstream version and license.

## Integration modes

- **native-adapter** — Nexvary Panel owns the adapter code. The external product remains an independently installed component and is accessed using a fixed CLI/API contract.
- **library-review** — source/library reuse may be considered only after license and dependency review.
- **concept-only** — use product/workflow ideas only; do not copy proprietary code, branding, assets, or UI.

| Provider | Role | Default Nexvary mode | License family recorded in registry | Current 0.6 scope |
|---|---|---|---|---|
| NGINX | Web/Reverse Proxy | native-adapter | BSD-2-Clause | Detect + existing site configuration |
| Caddy | Edge/Automatic HTTPS | native-adapter | Apache-2.0 | Detect/read-only |
| Traefik | Edge/Service Discovery | native-adapter | MIT | Detect/read-only |
| CrowdSec | Behavior Security | native-adapter | MIT | Detect/read-only |
| Fail2Ban | Brute-force defense | native-adapter | GPL-family | Separate component; detect + existing service integration |
| Authelia | Identity/MFA/OIDC | native-adapter | Apache-2.0 | Detect/read-only |
| restic | Encrypted backup engine | native-adapter | BSD-2-Clause | Detect/read-only; backup adapter planned |
| rclone | Remote storage transport | native-adapter | MIT | Detect/read-only; remote target adapter planned |
| Docker | Containers | native-adapter | Apache-2.0-components | Detect + existing constrained lifecycle controls |
| Podman | Rootless containers | native-adapter | Apache-2.0 | Detect/read-only |
| PowerDNS | Authoritative DNS | native-adapter | GPL-family | Separate component; detect/read-only |

## Mandatory provider rules

1. No provider command may be created by concatenating user input into a shell string.
2. `shell=True`, `os.system`, and arbitrary terminal execution are forbidden in provider adapters.
3. Read-only discovery runs fixed argv only and must have short timeouts.
4. Privileged writes must go through the root-agent allow-list with a strict action schema.
5. Provider APIs must not expose secrets, environment variables, tokens, or full configuration files by default.
6. No automatic install is performed merely because a provider is missing.
7. Every write-capable provider adapter must have rollback/validation behavior where the underlying technology supports it.
8. GPL-family components remain separate processes by default. Any source redistribution or derivative integration requires version-specific license review.
9. Proprietary products such as Plesk, cPanel, and DirectAdmin are concept/UX references only unless an official public API is used under its terms.
10. Every new provider must add CI coverage for its ID, fixed argv definition, permissions boundary, and UI rendering.

## Why this speeds development

Nexvary Panel builds one stable control plane and many small provider adapters instead of re-implementing mature engines. The UI, RBAC, audit trail, policy enforcement, safety snapshots, and release gates stay Nexvary-owned; specialized engines remain replaceable providers behind the same contract.
