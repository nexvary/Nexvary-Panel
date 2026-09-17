from __future__ import annotations

# Central control-plane metadata for privileged server operations.  The browser
# never supplies these values; routes and agents select a known operation ID.
PRIVILEGED_OPERATIONS: dict[str, dict[str, object]] = {
    "server-overview": {"capability": "server.read", "step_up": False, "timeout": 15, "risk": "low", "pre_check": "authenticated-admin", "post_check": "response-schema", "rollback": "not-applicable", "audit": "read-summary"},
    "server-network": {"capability": "server.read", "step_up": False, "timeout": 15, "risk": "low", "pre_check": "authenticated-admin", "post_check": "response-schema", "rollback": "not-applicable", "audit": "read-summary"},
    "server-processes": {"capability": "server.read", "step_up": False, "timeout": 15, "risk": "low", "pre_check": "authenticated-admin", "post_check": "bounded-process-list", "rollback": "not-applicable", "audit": "read-summary"},
    "server-updates-preview": {"capability": "maintenance.preview", "step_up": False, "timeout": 90, "risk": "medium", "pre_check": "apt-simulation", "post_check": "fingerprint", "rollback": "not-applicable", "audit": "preview"},
    "server-updates-apply": {"capability": "maintenance.apply", "step_up": True, "timeout": 1900, "risk": "high", "pre_check": "fresh-preview-fingerprint", "post_check": "apt-resimulation", "rollback": "manual-package-recovery", "audit": "attempt-and-result"},
    "server-time-enable-ntp": {"capability": "maintenance.time", "step_up": True, "timeout": 25, "risk": "medium", "pre_check": "known-operation", "post_check": "ntp-enabled", "rollback": "manual", "audit": "attempt-and-result"},
    "server-hostname-set": {"capability": "maintenance.hostname", "step_up": True, "timeout": 45, "risk": "high", "pre_check": "fresh-hostname-preview", "post_check": "hostname-verified", "rollback": "restore-previous-hostname", "audit": "attempt-and-result"},
    "service-restart": {"capability": "maintenance.service", "step_up": True, "timeout": 30, "risk": "medium", "pre_check": "service-allowlist", "post_check": "service-active", "rollback": "not-applicable", "audit": "attempt-and-result"},
}


def operation_policy(action: str) -> dict[str, object]:
    """Fail closed: callers must use a registered operation ID."""
    policy = PRIVILEGED_OPERATIONS.get(str(action))
    if policy is None:
        raise KeyError("privileged-operation-not-registered")
    return dict(policy)
