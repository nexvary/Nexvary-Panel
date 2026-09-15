# Platform 0.8 — Targeted Competitive Parity Closure

Platform 0.8 closes the specific competitive gaps called out at the end of the 0.7 track. This document is a release contract, not a claim that Nexvary Panel duplicates every feature of every long-established hosting product.

## Closure scope

| Gap from 0.7 | Platform 0.8 closure criterion | Verification |
| --- | --- | --- |
| Server update lifecycle stopped at preview | Reviewed update snapshot is fingerprinted, revalidated immediately before apply, and stale plans fail closed | `server_lifecycle_test.py`, `server_agent_test.py`, Platform 0.8 parity gate |
| Fleet was a foundation/preview surface | Authenticated outbound and inbound apply exists for a fixed allow-list; Vault refs stay out of browser payloads; pairing tokens are hashed; requests are timestamped and idempotent | `fleet_orchestration_test.py`, Extension Hub gate, Platform 0.8 parity gate |
| Migration was NEXVARY-only | cPanel, DirectAdmin and Plesk archive layouts receive safe inspection, compatibility reporting and normalization into the existing NEXVARY restore/rollback format | `migration_adapters_test.py`, `migration_center_test.py`, Platform 0.8 parity gate |
| Large migration archives were impractical through the web tier | Browser upload remains under the reverse-proxy limit; privileged local staging supports archives up to the migration policy limit | installer/quality gate and Platform 0.8 parity gate |
| Extension depth had no 0.8 contract for the new surfaces | Fleet and Migration Center are curated Extension Hub entries with kill-switch enforcement and provider-service declarations | `extension_hub_test.py`, Platform 0.8 parity gate |
| Release install path could diverge from source-tree behavior | `install-0.8.sh` / `upgrade-0.8.sh` pre-stage privileged modules and wait for real provider/ops sockets plus panel HTTP readiness | Ubuntu 24.04 installer, Email, SFTP and PostgreSQL gates |

## Security invariants

- No arbitrary remote shell or browser-supplied command execution is introduced by parity work.
- Fleet apply accepts only explicit operations declared by the control plane.
- Secret Vault values remain inside privileged/provider boundaries.
- System package application requires the exact reviewed fingerprint and rejects stale previews.
- Fleet machine requests use authentication, timestamp windows, request IDs and idempotency keys.
- Migration archives reject path traversal, links, devices and unsafe archive entries; database selection fails closed when ambiguous.
- Foreign DNS/mail configuration is reported for compatibility but is not silently rewritten during normalization.
- Destructive or externally visible administrative changes continue to require Step-Up where applicable.

## Release gate

0.8 can be called closed only when the final candidate head passes all of these on the same commit:

1. Code/security quality gate, including `platform_08_parity_test.py`.
2. Ubuntu 24.04 clean installation and site-control verification.
3. Ubuntu 24.04 Email Stack installation gate.
4. Ubuntu 24.04 key-only SFTP installation gate.
5. Ubuntu 24.04 PostgreSQL provider installation gate.
6. Real Chromium desktop/mobile UI gate and screenshot artifact generation.

The VERSION/README release declaration is intentionally the final step after these gates pass. A green gate validates the tested release candidate and does not imply universal compatibility with every distribution, provider, external panel archive or workload.
