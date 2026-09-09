from panel.routes_auth import _trust_posture

all_services = {"nginx": True, "mariadb": True, "fail2ban": True, "ssh": True, "docker": True}
healthy = _trust_posture(enabled_2fa=True, services=all_services, backups_count=2, disk_percent=42, critical_unread=0)
assert healthy["score"] == 100
assert healthy["level"] == "excellent"
assert healthy["passed"] == healthy["total"] == 7
assert sum(item["weight"] for item in healthy["checks"]) == 100

weak = _trust_posture(enabled_2fa=False, services={}, backups_count=0, disk_percent=96, critical_unread=3)
assert 0 <= weak["score"] <= 100
assert weak["score"] == 15  # CSRF + secure-session policy is always part of the panel baseline.
assert weak["level"] == "risk"

mixed = _trust_posture(
    enabled_2fa=True,
    services={"nginx": True, "mariadb": True, "fail2ban": False},
    backups_count=1,
    disk_percent=70,
    critical_unread=0,
)
assert mixed["score"] == 85
assert mixed["level"] == "good"
assert all(isinstance(item["ok"], bool) for item in mixed["checks"])
print("Nexvary Panel operational trust score tests: PASS")
