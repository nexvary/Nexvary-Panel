#!/usr/bin/env bash
set -euo pipefail
python -m compileall -q app.py panel agent tests
bash -n installer/install.sh installer/upgrade.sh installer/configure-mail.sh installer/configure-sftp.sh agent/nvpctl tests/ci/*.sh
python tests/smoke_test.py
python tests/vault_test.py
python tests/integrations_test.py
python tests/provider_backup_test.py
python tests/trust_test.py
python tests/hosting_features_test.py
python tests/schedules_test.py
python tests/accounts_scope_test.py
python tests/mail_policy_test.py
python tests/transfer_policy_test.py
python tests/advanced_ops_test.py
python tests/module_registry_test.py
python tests/entitlements_test.py
python tests/session_revocation_test.py
python tests/domain_agent_test.py
python tests/domain_lifecycle_test.py
python tests/autossl_test.py
python tests/autossl_routes_test.py
python tests/deliverability_test.py
