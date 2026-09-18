from __future__ import annotations

from dataclasses import dataclass


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
}


def operation_for(operation_id: str) -> MaintenanceOperation | None:
    return OPERATIONS.get(operation_id)


def restart_operation_for_target(target: str) -> MaintenanceOperation | None:
    """Resolve a browser service choice to a fixed policy entry; fail closed."""
    for operation in OPERATIONS.values():
        if operation.agent_action == "service-restart" and operation.target == target:
            return operation
    return None
