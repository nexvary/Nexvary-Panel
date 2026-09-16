#!/usr/bin/env bash
set -euo pipefail

run_ui_gate() {
  local test_file="$1"
  local code=0
  echo "::group::UI gate ${test_file}"
  if timeout --signal=TERM --kill-after=10s 120s node "$test_file"; then
    echo "::endgroup::"
    return 0
  else
    code=$?
    echo "UI gate failed or timed out: ${test_file} (exit=${code})" >&2
    echo "::endgroup::"
    return "$code"
  fi
}

for test_file in \
  tests/final_design_review_ui_gate.mjs \
  tests/ui_gate.mjs \
  tests/backups_ui_gate.mjs \
  tests/vault_ui_gate.mjs \
  tests/integrations_ui_gate.mjs \
  tests/approved_theme_ui_gate.mjs \
  tests/andalusian_visual_gate.mjs \
  tests/internal_workspace_ui_gate.mjs \
  tests/hosting_ui_gate.mjs \
  tests/schedules_ui_gate.mjs \
  tests/accounts_ui_gate.mjs \
  tests/database_access_ui_gate.mjs \
  tests/database_lifecycle_ui_gate.mjs \
  tests/mail_ui_gate.mjs \
  tests/transfer_ui_gate.mjs \
  tests/advanced_ops_ui_gate.mjs \
  tests/dynamic_dns_ui_gate.mjs \
  tests/site_controls_ui_gate.mjs \
  tests/domain_health_ui_gate.mjs \
  tests/domain_guardian_ui_gate.mjs \
  tests/doctor_remediation_ui_gate.mjs \
  tests/change_safety_ui_gate.mjs \
  tests/wordpress_lifecycle_ui_gate.mjs \
  tests/wordpress_selective_ui_gate.mjs \
  tests/wordpress_smart_guard_ui_gate.mjs \
  tests/extension_hub_ui_gate.mjs
do
  run_ui_gate "$test_file"
done
