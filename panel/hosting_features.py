from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Iterable


@dataclass(frozen=True)
class HostingFeature:
    feature_id: str
    category: str
    label: str
    scope: str
    maturity: str
    risk: str = "normal"
    provider: str = "native"
    description: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


# Clean-room capability catalogue inspired by mainstream hosting-control-panel workflows.
# It intentionally describes capabilities, not proprietary implementation details or assets.
_FEATURES: tuple[HostingFeature, ...] = (
    HostingFeature("files.file_manager", "files", "File Manager", "account", "native", description="Scoped site-root file management"),
    HostingFeature("files.images", "files", "Images", "account", "planned"),
    HostingFeature("files.directory_privacy", "files", "Directory Privacy", "account", "planned"),
    HostingFeature("files.disk_usage", "files", "Disk Usage", "account", "foundation"),
    HostingFeature("files.web_disk", "files", "Web Disk", "account", "planned"),
    HostingFeature("files.ftp_accounts", "files", "FTP Accounts", "account", "foundation", provider="ftp"),
    HostingFeature("files.backups", "files", "Backups", "account", "native"),
    HostingFeature("files.backup_wizard", "files", "Backup Wizard", "account", "foundation"),
    HostingFeature("files.git", "files", "Git Version Control", "account", "native"),

    HostingFeature("domains.domains", "domains", "Domains", "account", "native"),
    HostingFeature("domains.redirects", "domains", "Redirects", "account", "foundation"),
    HostingFeature("domains.zone_editor", "domains", "Zone Editor", "account", "foundation", risk="sensitive", provider="dns"),
    HostingFeature("domains.dynamic_dns", "domains", "Dynamic DNS", "account", "planned", provider="dns"),

    HostingFeature("email.accounts", "email", "Email Accounts", "account", "foundation", provider="mail"),
    HostingFeature("email.forwarders", "email", "Forwarders", "account", "foundation", provider="mail"),
    HostingFeature("email.routing", "email", "Email Routing", "account", "planned", provider="mail"),
    HostingFeature("email.autoresponders", "email", "Autoresponders", "account", "planned", provider="mail"),
    HostingFeature("email.default_address", "email", "Default Address", "account", "planned", provider="mail"),
    HostingFeature("email.mailing_lists", "email", "Mailing Lists", "account", "planned", provider="mail"),
    HostingFeature("email.delivery_trace", "email", "Track Delivery", "account", "planned", provider="mail"),
    HostingFeature("email.global_filters", "email", "Global Email Filters", "account", "planned", provider="mail"),
    HostingFeature("email.filters", "email", "Email Filters", "account", "planned", provider="mail"),
    HostingFeature("email.deliverability", "email", "Email Deliverability", "account", "foundation", provider="mail"),
    HostingFeature("email.address_importer", "email", "Address Importer", "account", "planned", provider="mail"),
    HostingFeature("email.spam_filters", "email", "Spam Filters", "account", "planned", provider="mail"),
    HostingFeature("email.calendars_contacts", "email", "Calendars & Contacts", "account", "planned", provider="mail"),
    HostingFeature("email.encryption", "email", "Email Encryption", "account", "planned", risk="sensitive", provider="mail"),

    HostingFeature("databases.mariadb", "databases", "MariaDB Databases", "account", "native"),
    HostingFeature("databases.wizard", "databases", "Database Wizard", "account", "foundation"),
    HostingFeature("databases.remote_access", "databases", "Remote Database Access", "account", "planned", risk="sensitive"),
    HostingFeature("databases.postgresql", "databases", "PostgreSQL Databases", "account", "planned", provider="postgresql"),
    HostingFeature("databases.web_admin", "databases", "Web Database Administration", "account", "planned", provider="db-admin"),

    HostingFeature("metrics.visitors", "metrics", "Visitors", "account", "foundation"),
    HostingFeature("metrics.errors", "metrics", "Errors", "account", "foundation"),
    HostingFeature("metrics.bandwidth", "metrics", "Bandwidth", "account", "foundation"),
    HostingFeature("metrics.raw_access", "metrics", "Raw Access", "account", "planned"),
    HostingFeature("metrics.analytics", "metrics", "Web Analytics", "account", "planned", provider="analytics"),
    HostingFeature("metrics.resource_usage", "metrics", "Resource Usage", "account", "native"),

    HostingFeature("security.ssh", "security", "SSH Access", "account", "foundation", risk="sensitive"),
    HostingFeature("security.ip_blocker", "security", "IP Blocker", "account", "foundation", risk="sensitive"),
    HostingFeature("security.ssl_tls", "security", "SSL/TLS", "account", "foundation", risk="sensitive"),
    HostingFeature("security.api_tokens", "security", "API Tokens", "account", "planned", risk="sensitive"),
    HostingFeature("security.hotlink", "security", "Hotlink Protection", "account", "planned"),
    HostingFeature("security.leech", "security", "Leech Protection", "account", "planned"),
    HostingFeature("security.waf", "security", "Web Application Firewall", "account", "foundation", risk="sensitive", provider="waf"),
    HostingFeature("security.two_factor", "security", "Two-Factor Authentication", "account", "native", risk="sensitive"),
    HostingFeature("security.ssl_status", "security", "SSL/TLS Status", "account", "native"),
    HostingFeature("security.malware_scan", "security", "Malware Scanner", "account", "planned", provider="malware"),

    HostingFeature("software.wordpress", "software", "WordPress Manager", "account", "native"),
    HostingFeature("software.php_manager", "software", "PHP Version Manager", "account", "foundation", risk="sensitive"),
    HostingFeature("software.php_ini", "software", "PHP INI Editor", "account", "planned", risk="sensitive"),
    HostingFeature("software.node", "software", "Node.js Apps", "account", "native"),
    HostingFeature("software.python", "software", "Python Apps", "account", "native"),
    HostingFeature("software.ruby", "software", "Ruby Apps", "account", "planned"),
    HostingFeature("software.optimize", "software", "Optimize Website", "account", "foundation"),

    HostingFeature("advanced.cron", "advanced", "Cron Jobs", "account", "foundation", risk="sensitive"),
    HostingFeature("advanced.dns_trace", "advanced", "DNS Trace", "account", "foundation"),
    HostingFeature("advanced.indexes", "advanced", "Indexes", "account", "planned"),
    HostingFeature("advanced.error_pages", "advanced", "Error Pages", "account", "foundation"),
    HostingFeature("advanced.mime_types", "advanced", "MIME Types", "account", "planned"),
    HostingFeature("advanced.handlers", "advanced", "Web Handlers", "account", "planned"),
    HostingFeature("advanced.virus_scan", "advanced", "Virus Scanner", "account", "planned", provider="antivirus"),

    HostingFeature("preferences.password", "preferences", "Password & Security", "account", "native", risk="sensitive"),
    HostingFeature("preferences.language", "preferences", "Language", "account", "foundation"),
    HostingFeature("preferences.users", "preferences", "User Manager", "account", "native", risk="sensitive"),
    HostingFeature("preferences.contact", "preferences", "Contact Information", "account", "planned"),

    HostingFeature("whm.basic_setup", "server", "Basic Server Setup", "server", "foundation", risk="privileged"),
    HostingFeature("whm.quotas", "server", "Quota Setup", "server", "foundation", risk="privileged"),
    HostingFeature("whm.server_profile", "server", "Server Profile", "server", "foundation", risk="privileged"),
    HostingFeature("whm.server_time", "server", "Server Time", "server", "planned", risk="privileged"),
    HostingFeature("whm.stats_config", "server", "Statistics Configuration", "server", "planned", risk="privileged"),
    HostingFeature("whm.tweak_settings", "server", "Server Settings", "server", "planned", risk="privileged"),
    HostingFeature("whm.system_cron", "server", "System Scheduled Tasks", "server", "planned", risk="privileged"),
    HostingFeature("whm.updates", "server", "System Updates", "server", "planned", risk="privileged"),
    HostingFeature("whm.networking", "server", "Networking Setup", "server", "planned", risk="privileged"),
    HostingFeature("whm.hostname", "server", "Hostname & Resolvers", "server", "planned", risk="privileged"),
    HostingFeature("whm.security_advisor", "server", "Security Advisor", "server", "native", risk="privileged"),
    HostingFeature("whm.firewall", "server", "Firewall Management", "server", "foundation", risk="privileged", provider="firewall"),
    HostingFeature("whm.host_access", "server", "Host Access Control", "server", "planned", risk="privileged"),
    HostingFeature("whm.resellers", "resellers", "Reseller Management", "server", "foundation", risk="privileged"),
    HostingFeature("whm.service_config", "services", "Service Configuration", "server", "foundation", risk="privileged"),
    HostingFeature("whm.backup_config", "backup", "Backup Configuration", "server", "foundation", risk="privileged"),
    HostingFeature("whm.backup_restore", "backup", "Backup Restore", "server", "native", risk="privileged"),
    HostingFeature("whm.clusters", "cluster", "Cluster Management", "server", "planned", risk="privileged"),
    HostingFeature("whm.system_health", "monitoring", "System Health", "server", "native"),
    HostingFeature("whm.restart_services", "services", "Restart Services", "server", "native", risk="privileged"),
    HostingFeature("whm.accounts", "accounts", "Account Management", "server", "foundation", risk="privileged"),
    HostingFeature("whm.multi_account", "accounts", "Multi-Account Functions", "server", "planned", risk="privileged"),
    HostingFeature("whm.transfers", "accounts", "Account Transfers", "server", "planned", risk="privileged"),
    HostingFeature("whm.packages", "packages", "Hosting Packages", "server", "foundation", risk="privileged"),
    HostingFeature("whm.feature_manager", "packages", "Feature Manager", "server", "foundation", risk="privileged"),
    HostingFeature("whm.dns_functions", "dns", "DNS Functions", "server", "foundation", risk="privileged", provider="dns"),
    HostingFeature("whm.dns_cluster", "dns", "DNS Cluster", "server", "planned", risk="privileged", provider="dns"),
    HostingFeature("whm.sql_services", "databases", "SQL Services", "server", "foundation", risk="privileged"),
    HostingFeature("whm.ip_functions", "networking", "IP Functions", "server", "planned", risk="privileged"),
    HostingFeature("whm.software", "software", "Server Software", "server", "planned", risk="privileged"),
    HostingFeature("whm.mail_server", "email", "Mail Server Configuration", "server", "planned", risk="privileged", provider="mail"),
    HostingFeature("whm.mail_queue", "email", "Mail Queue", "server", "planned", risk="privileged", provider="mail"),
    HostingFeature("whm.ssl", "security", "Server SSL/TLS", "server", "foundation", risk="privileged"),
    HostingFeature("whm.service_status", "monitoring", "Service Status", "server", "native"),
    HostingFeature("whm.web_server", "services", "Web Server Configuration", "server", "foundation", risk="privileged"),
    HostingFeature("whm.php_config", "software", "PHP Configuration", "server", "foundation", risk="privileged"),
    HostingFeature("whm.mail_config", "email", "Mail Transport Configuration", "server", "planned", risk="privileged", provider="mail"),
    HostingFeature("whm.nameserver", "dns", "Nameserver Selection", "server", "planned", risk="privileged", provider="dns"),
    HostingFeature("whm.locales", "preferences", "Locales", "server", "planned", risk="privileged"),
    HostingFeature("whm.plugins", "plugins", "Plugin Manager", "server", "foundation", risk="privileged"),
    HostingFeature("whm.api_tokens", "security", "Server API Tokens", "server", "planned", risk="privileged"),
    HostingFeature("whm.logs", "monitoring", "Server Logs", "server", "native"),
    HostingFeature("whm.processes", "monitoring", "Process Manager", "server", "planned", risk="privileged"),
    HostingFeature("whm.disk_usage", "monitoring", "Disk Usage", "server", "native"),
    HostingFeature("whm.reboot", "server", "System Reboot", "server", "planned", risk="privileged"),
)

FEATURES: dict[str, HostingFeature] = {item.feature_id: item for item in _FEATURES}

CATEGORY_LABELS = {
    "files": "الملفات",
    "domains": "النطاقات وDNS",
    "email": "البريد",
    "databases": "قواعد البيانات",
    "metrics": "الإحصاءات",
    "security": "الأمن",
    "software": "البرمجيات",
    "advanced": "متقدم",
    "preferences": "التفضيلات",
    "server": "إدارة الخادم",
    "resellers": "الموزعون",
    "services": "الخدمات",
    "backup": "النسخ والاستعادة",
    "cluster": "العناقيد",
    "monitoring": "المراقبة",
    "accounts": "الحسابات",
    "packages": "الحزم والصلاحيات",
    "dns": "DNS",
    "networking": "الشبكات",
    "plugins": "الإضافات",
}


def feature_catalog(scope: str | None = None) -> list[dict]:
    values: Iterable[HostingFeature] = _FEATURES
    if scope:
        values = (item for item in values if item.scope == scope)
    return [item.as_dict() for item in values]


def feature_ids() -> set[str]:
    return set(FEATURES)


def maturity_summary() -> dict[str, int]:
    out = {"native": 0, "foundation": 0, "planned": 0}
    for item in _FEATURES:
        out[item.maturity] = out.get(item.maturity, 0) + 1
    return out
