from __future__ import annotations

from dataclasses import dataclass

from .privileged_policy import operation_policy


@dataclass(frozen=True, slots=True)
class MaintenanceOperation:
    id: str
    label: str
    agent_action: str
    target: str
    roles: tuple[str, ...]
    step_up: bool
    timeout: int
    precheck: str
    postcheck: str
    rollback: str | None = None
    risk: str = "medium"


# Deliberately finite: the browser never supplies an executable, argv, shell fragment,
# unit name, filesystem path or other root-controlled primitive.  The submitted
# operation ID is resolved here to a fixed privileged-agent action and target.
# Per-operation timeouts must never exceed the central privileged-policy ceiling.
OPERATIONS: dict[str, MaintenanceOperation] = {
    "restart-nginx": MaintenanceOperation("restart-nginx", "إعادة تشغيل Nginx", "service-restart", "nginx", ("admin",), True, 30, "nginx-config", "nginx-active", risk="medium"),
    "restart-mariadb": MaintenanceOperation("restart-mariadb", "إعادة تشغيل MariaDB", "service-restart", "mariadb", ("admin",), True, 30, "mariadb-ping", "mariadb-ping", risk="high"),
    "restart-fail2ban": MaintenanceOperation("restart-fail2ban", "إعادة تشغيل Fail2ban", "service-restart", "fail2ban", ("admin",), True, 30, "fail2ban-config", "fail2ban-active", risk="medium"),
    "restart-docker": MaintenanceOperation("restart-docker", "إعادة تشغيل Docker", "service-restart", "docker", ("admin",), True, 30, "docker-service-known", "docker-active", risk="high"),
    "docker-start": MaintenanceOperation("docker-start", "تشغيل حاوية Docker", "docker-control", "start", ("admin", "operator"), True, 35, "container-name-and-action-allowlist", "container-running", rollback="stop-container", risk="high"),
    "docker-stop": MaintenanceOperation("docker-stop", "إيقاف حاوية Docker", "docker-control", "stop", ("admin", "operator"), True, 35, "container-name-and-action-allowlist", "container-stopped", rollback="start-container", risk="high"),
    "docker-restart": MaintenanceOperation("docker-restart", "إعادة تشغيل حاوية Docker", "docker-control", "restart", ("admin", "operator"), True, 35, "container-name-and-action-allowlist", "container-running", rollback="not-applicable", risk="high"),
}


def _validate_registry() -> None:
    """Fail closed at startup if UI policy drifts below the privileged boundary."""
    allowed_roles = {"admin", "operator"}
    allowed_risks = {"low", "medium", "high"}
    for key, operation in OPERATIONS.items():
        if key != operation.id or not operation.roles or not set(operation.roles) <= allowed_roles:
            raise RuntimeError(f"invalid-maintenance-operation:{key}")
        if operation.timeout <= 0 or operation.risk not in allowed_risks:
            raise RuntimeError(f"invalid-maintenance-safety-metadata:{key}")
        privileged = operation_policy(operation.agent_action)
        if operation.timeout > int(privileged["timeout"]):
            raise RuntimeError(f"maintenance-timeout-exceeds-privileged-ceiling:{key}")
        if bool(privileged.get("step_up")) and not operation.step_up:
            raise RuntimeError(f"maintenance-step-up-weakened:{key}")
        if not operation.precheck or not operation.postcheck:
            raise RuntimeError(f"maintenance-lifecycle-check-missing:{key}")


_validate_registry()


def operation_for(operation_id: str) -> MaintenanceOperation | None:
    return OPERATIONS.get(operation_id)


def restart_operation_for_target(target: str) -> MaintenanceOperation | None:
    """Resolve a browser service choice to a fixed policy entry; fail closed."""
    for operation in OPERATIONS.values():
        if operation.agent_action == "service-restart" and operation.target == target:
            return operation
    return None


def docker_operation_for(desired: str) -> MaintenanceOperation | None:
    """Resolve a requested lifecycle state to a fixed Docker policy entry."""
    operation = OPERATIONS.get(f"docker-{desired}")
    return operation if operation and operation.agent_action == "docker-control" else None
