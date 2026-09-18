from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
script = (ROOT / "agent" / "nvpctl").read_text(encoding="utf-8")

# Service mutations must be bounded by an operation-specific health pre-check and
# both active-state and health post-checks. A config/daemon failure must therefore
# block the mutation rather than merely reporting it after restart.
assert "service_precheck" in script
assert 'service_precheck "$name" || { echo "$name pre-check failed; restart blocked"' in script
assert 'systemctl is-active --quiet "$name" || { echo "$name post-check failed: service inactive"' in script
assert 'service_precheck "$name" || { echo "$name post-check failed: health probe failed"' in script
assert "nginx -t" in script
assert "mariadb-admin ping --silent" in script
assert "fail2ban-client ping" in script
assert "docker info" in script

# Docker lifecycle mutations capture pre-state, verify the requested post-state,
# and restore the captured state after a failed start/stop post-check. Restart is
# intentionally marked non-rollbackable in maintenance policy and is not faked.
assert 'was_running=false; docker_running "$container" && was_running=true' in script
assert 'expected=true; [[ "$desired" == stop ]] && expected=false' in script
assert 'if [[ "$is_running" != "$expected" ]]' in script
assert 'if [[ "$desired" != restart ]]' in script
assert 'docker start "$container" >/dev/null 2>&1 || true' in script
assert 'docker stop "$container" >/dev/null 2>&1 || true' in script

policy = (ROOT / "panel" / "maintenance_policy.py").read_text(encoding="utf-8")
assert '"docker-start"' in policy and 'rollback="stop-container"' in policy
assert '"docker-stop"' in policy and 'rollback="start-container"' in policy
assert '"docker-restart"' in policy and 'rollback="not-applicable"' in policy

# The privileged helper remains a finite dispatcher: never add a browser-facing
# shell/eval primitive while extending graphical maintenance operations.
assert "eval " not in script
assert "bash -c" not in script
assert "sh -c" not in script

print("NEXVARY Maintenance Center lifecycle enforcement contract: PASS")
