from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MaintenanceOperation:
    id: str
    label: str
    agent_action: str
    roles: tuple[str, ...]
    step_up: bool
    timeout: int
    precheck: str
    postcheck: str
    rollback: str | None = None
    risk: str = "medium"


# Deliberately finite: the browser never supplies an executable, argv, shell fragment,
# unit name, filesystem path or other root-controlled primitive.
OPERATIONS: dict[str, MaintenanceOperation] = {
    "restart-nginx": MaintenanceOperation("restart-nginx", "إعادة تشغيل Nginx", "maintenance-restart-nginx", ("admin",), True, 35, "nginx-config", "nginx-active", risk="medium"),
    "restart-mariadb": MaintenanceOperation("restart-mariadb", "إعادة تشغيل MariaDB", "maintenance-restart-mariadb", ("admin",), True, 45, "mariadb-ping", "mariadb-ping", risk="high"),
    "restart-fail2ban": MaintenanceOperation("restart-fail2ban", "إعادة تشغيل Fail2ban", "maintenance-restart-fail2ban", ("admin",), True, 35, "fail2ban-config", "fail2ban-active", risk="medium"),
    "reload-nginx": MaintenanceOperation("reload-nginx", "إعادة تحميل إعدادات Nginx", "maintenance-reload-nginx", ("admin", "operator"), True, 30, "nginx-config", "nginx-active", risk="low"),
}


def operation_for(operation_id: str) -> MaintenanceOperation | None:
    return OPERATIONS.get(operation_id)
