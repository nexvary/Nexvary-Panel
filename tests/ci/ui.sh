#!/usr/bin/env bash
set -euo pipefail
node tests/ui_gate.mjs
node tests/backups_ui_gate.mjs
node tests/vault_ui_gate.mjs
node tests/integrations_ui_gate.mjs
node tests/approved_theme_ui_gate.mjs
node tests/internal_workspace_ui_gate.mjs
node tests/hosting_ui_gate.mjs
node tests/schedules_ui_gate.mjs
node tests/accounts_ui_gate.mjs
node tests/mail_ui_gate.mjs
node tests/transfer_ui_gate.mjs
node tests/advanced_ops_ui_gate.mjs
node tests/domain_health_ui_gate.mjs
node tests/wordpress_lifecycle_ui_gate.mjs
