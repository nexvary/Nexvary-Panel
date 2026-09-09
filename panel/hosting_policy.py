from __future__ import annotations

from flask import session

from .db_layer import db
from .hosting_features import FEATURES

DEFAULT_ACCOUNT_FEATURES = {
    "files.file_manager", "files.disk_usage", "files.backups", "files.backup_wizard", "files.git",
    "domains.domains", "domains.redirects", "domains.zone_editor",
    "email.accounts", "email.forwarders", "email.deliverability",
    "databases.mariadb", "databases.wizard",
    "metrics.visitors", "metrics.errors", "metrics.bandwidth", "metrics.resource_usage",
    "security.ssl_tls", "security.two_factor", "security.ssl_status",
    "software.wordpress", "software.php_manager", "software.node", "software.python", "software.optimize",
    "advanced.cron", "advanced.dns_trace", "advanced.error_pages",
    "preferences.password", "preferences.language", "preferences.users",
}


def package_for_user(conn, username: str, role: str):
    row = conn.execute(
        """SELECT p.* FROM user_hosting_package u
           JOIN hosting_packages p ON p.id=u.package_id
           WHERE u.username=? AND p.enabled=1""",
        (username,),
    ).fetchone()
    if row:
        return row
    fallback = "NEXVARY Unlimited" if role == "admin" else "NEXVARY Core"
    return conn.execute("SELECT * FROM hosting_packages WHERE name=? AND enabled=1", (fallback,)).fetchone()


def enabled_features(conn, package_id: int | None, role: str) -> set[str]:
    explicit: dict[str, bool] = {}
    if package_id is not None:
        rows = conn.execute(
            "SELECT feature_id,enabled FROM hosting_package_features WHERE package_id=?", (package_id,)
        ).fetchall()
        explicit = {str(row["feature_id"]): bool(row["enabled"]) for row in rows if row["feature_id"] in FEATURES}
    base = set(FEATURES) if role == "admin" else set(DEFAULT_ACCOUNT_FEATURES)
    for feature_id, enabled in explicit.items():
        if enabled:
            base.add(feature_id)
        else:
            base.discard(feature_id)
    return base


def effective_feature_ids(username: str | None = None, role: str | None = None) -> set[str]:
    username = str(username if username is not None else session.get("user", ""))[:64]
    role = str(role if role is not None else session.get("role", "viewer"))
    with db() as conn:
        package = package_for_user(conn, username, role)
        package_id = int(package["id"]) if package else None
        return enabled_features(conn, package_id, role)


def feature_allowed(feature_id: str, username: str | None = None, role: str | None = None) -> bool:
    if feature_id not in FEATURES:
        return False
    return feature_id in effective_feature_ids(username=username, role=role)
