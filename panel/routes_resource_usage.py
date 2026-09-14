from __future__ import annotations

import math
import re

from flask import jsonify, request, session

from .core import db
from .hosting_policy import feature_allowed, package_for_user
from .security import login_required
from .webtools_client import webtools_call

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MAX_SITES_PER_MEASUREMENT = 200


def _counts(conn, username: str) -> dict[str, int]:
    mariadb = int(conn.execute("SELECT COUNT(*) FROM databases WHERE owner=?", (username,)).fetchone()[0])
    postgres = int(conn.execute("SELECT COUNT(*) FROM postgres_resources WHERE owner=?", (username,)).fetchone()[0])
    return {
        "max_sites": int(conn.execute("SELECT COUNT(*) FROM sites WHERE owner=?", (username,)).fetchone()[0]),
        "max_databases": mariadb + postgres,
        "max_mailboxes": int(conn.execute("SELECT COUNT(*) FROM mailboxes WHERE owner=? AND enabled=1", (username,)).fetchone()[0]),
        "max_ftp_accounts": int(conn.execute("SELECT COUNT(*) FROM transfer_accounts WHERE owner=? AND enabled=1", (username,)).fetchone()[0]),
        "max_cron_jobs": int(conn.execute("SELECT COUNT(*) FROM scheduled_tasks WHERE owner=?", (username,)).fetchone()[0]),
        "max_subdomains": int(conn.execute("SELECT COUNT(*) FROM domain_aliases WHERE owner=?", (username,)).fetchone()[0]),
        "max_backups": int(conn.execute("SELECT COUNT(*) FROM backups WHERE owner=?", (username,)).fetchone()[0]),
    }


def _ratio(used: int | None, limit: int) -> dict:
    if used is None:
        return {"used": None, "limit": limit, "remaining": None, "percent": None, "over": False, "measured": False}
    remaining = max(0, limit - used)
    percent = 0.0 if limit <= 0 and used <= 0 else (100.0 if limit <= 0 else min(999.0, round((used / limit) * 100.0, 1)))
    return {"used": used, "limit": limit, "remaining": remaining, "percent": percent, "over": used > limit, "measured": True}


def register_resource_usage_routes(app):
    @app.get("/api/hosting/resource-usage")
    @login_required
    def hosting_resource_usage():
        actor = str(session.get("user", ""))[:64]
        role = str(session.get("role", "viewer"))
        requested = str(request.args.get("username", actor)).strip()
        if not USERNAME_RE.fullmatch(requested):
            return jsonify(ok=False, error="invalid username"), 400
        if role != "admin" and requested != actor:
            return jsonify(ok=False, error="account outside your scope"), 403
        effective_role = role if requested == actor else "operator"
        if not feature_allowed("metrics.resource_usage", username=requested, role=effective_role):
            return jsonify(ok=False, error="resource usage disabled by hosting package policy"), 403

        with db() as conn:
            user = conn.execute("SELECT username,role,enabled FROM users WHERE username=?", (requested,)).fetchone()
            if requested != "admin" and not user:
                return jsonify(ok=False, error="user not found"), 404
            user_role = "admin" if requested == "admin" else str(user["role"])
            package = package_for_user(conn, requested, user_role)
            if not package:
                return jsonify(ok=False, error="hosting package unavailable"), 409
            domains = [str(row["domain"]) for row in conn.execute("SELECT domain FROM sites WHERE owner=? ORDER BY domain", (requested,)).fetchall()]
            counts = _counts(conn, requested)
            limits = {key: int(package[key]) for key in (
                "disk_mb", "bandwidth_mb", "max_sites", "max_databases", "max_mailboxes",
                "max_ftp_accounts", "max_cron_jobs", "max_subdomains", "max_backups",
            )}
            package_name = str(package["name"])

        disk_bytes = 0
        bandwidth_sample_bytes = 0
        measured_sites = 0
        failures: list[str] = []
        site_rows: list[dict] = []
        capped = len(domains) > MAX_SITES_PER_MEASUREMENT
        for domain in domains[:MAX_SITES_PER_MEASUREMENT]:
            try:
                result = webtools_call({"action": "site-resource-usage", "domain": domain}, timeout=25)
            except Exception:
                result = {"ok": False, "error": "provider unavailable"}
            if not result.get("ok"):
                failures.append(domain)
                site_rows.append({"domain": domain, "measured": False})
                continue
            measured_sites += 1
            site_disk = max(0, int(result.get("disk_bytes") or 0))
            sample = result.get("bandwidth_bytes")
            sample_value = max(0, int(sample or 0)) if sample is not None else None
            disk_bytes += site_disk
            if sample_value is not None:
                bandwidth_sample_bytes += sample_value
            site_rows.append({
                "domain": domain,
                "measured": True,
                "disk_bytes": site_disk,
                "bandwidth_sample_bytes": sample_value,
                "bandwidth_scope": str(result.get("bandwidth_scope") or "unavailable"),
                "filesystem_entries": max(0, int(result.get("filesystem_entries") or 0)),
            })

        disk_complete = not capped and measured_sites == len(domains)
        disk_mb = int(math.ceil(disk_bytes / (1024 * 1024))) if disk_complete else None
        telemetry = {
            "disk": {
                **_ratio(disk_mb, limits["disk_mb"]),
                "bytes": disk_bytes if disk_complete else None,
                "scope": "managed-site-roots",
                "hard_quota_safe": disk_complete,
            },
            "bandwidth": {
                "sample_bytes": bandwidth_sample_bytes,
                "limit_mb": limits["bandwidth_mb"],
                "scope": "latest-nginx-log-window-per-site",
                "hard_quota_safe": False,
                "note": "Telemetry only until persistent monthly accounting across log rotation is available.",
            },
        }
        quota = {key: _ratio(value, limits[key]) for key, value in counts.items()}
        return jsonify(
            ok=True,
            username=requested,
            package=package_name,
            sites_total=len(domains),
            sites_measured=measured_sites,
            measurement_complete=disk_complete,
            capped=capped,
            failures=failures[:20],
            telemetry=telemetry,
            quota=quota,
            sites=site_rows,
            enforcement={"disk": "eligible-when-complete", "bandwidth": "telemetry-only"},
        )
