from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass

SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")
SAFE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent"}


@dataclass(frozen=True)
class ProviderSpec:
    provider_id: str
    label: str
    category: str
    binary: str
    version_args: tuple[str, ...]
    capabilities: tuple[str, ...]
    license_family: str
    service_unit: str | None = None


REGISTRY: tuple[ProviderSpec, ...] = (
    ProviderSpec("nginx", "NGINX", "edge", "nginx", ("-v",), ("web-server", "reverse-proxy"), "BSD-2-Clause", "nginx"),
    ProviderSpec("caddy", "Caddy", "edge", "caddy", ("version",), ("automatic-https", "reverse-proxy", "config-api"), "Apache-2.0", "caddy"),
    ProviderSpec("traefik", "Traefik", "edge", "traefik", ("version",), ("service-discovery", "reverse-proxy", "load-balancing", "acme"), "MIT", "traefik"),
    ProviderSpec("crowdsec", "CrowdSec", "security", "cscli", ("version",), ("behavior-detection", "decisions", "collections"), "MIT", "crowdsec"),
    ProviderSpec("fail2ban", "Fail2Ban", "security", "fail2ban-client", ("--version",), ("bruteforce-protection", "jails"), "GPL-family", "fail2ban"),
    ProviderSpec("authelia", "Authelia", "identity", "authelia", ("--version",), ("mfa", "oidc", "webauthn", "policy"), "Apache-2.0", "authelia"),
    ProviderSpec("restic", "restic", "backup", "restic", ("version",), ("encrypted-snapshots", "deduplication", "restore"), "BSD-2-Clause"),
    ProviderSpec("rclone", "rclone", "backup", "rclone", ("version",), ("s3", "webdav", "cloud-remotes", "sync"), "MIT"),
    ProviderSpec("docker", "Docker", "containers", "docker", ("--version",), ("containers", "images", "networks", "volumes"), "Apache-2.0-components", "docker"),
    ProviderSpec("podman", "Podman", "containers", "podman", ("--version",), ("rootless-containers", "pods", "images"), "Apache-2.0"),
    ProviderSpec("powerdns", "PowerDNS", "dns", "pdns_server", ("--version",), ("authoritative-dns", "zones", "api"), "GPL-family", "pdns"),
)


def _service_state(unit: str | None) -> str:
    if not unit or not shutil.which("systemctl"):
        return "unknown"
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", unit], capture_output=True, text=True, timeout=2,
            env=SAFE_ENV, check=False,
        )
        state = (proc.stdout or "").strip().lower()
        return state if state in {"active", "inactive", "failed", "activating", "deactivating"} else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def detect_provider(spec: ProviderSpec) -> dict:
    if not SAFE_ID_RE.match(spec.provider_id):
        raise ValueError("unsafe provider id")
    path = shutil.which(spec.binary)
    version = ""
    if path:
        try:
            proc = subprocess.run(
                [path, *spec.version_args], capture_output=True, text=True, timeout=3,
                env=SAFE_ENV, check=False,
            )
            raw = (proc.stdout or proc.stderr or "").strip().replace("\x00", "")
            version = (raw.splitlines()[0] if raw else "")[:180]
        except (OSError, subprocess.SubprocessError):
            version = "version unavailable"
    item = asdict(spec)
    item.update(
        installed=bool(path),
        executable=path or "",
        version=version,
        service_state=_service_state(spec.service_unit) if path else "not-installed",
    )
    return item


def provider_snapshot() -> dict:
    providers = [detect_provider(spec) for spec in REGISTRY]
    installed = [p for p in providers if p["installed"]]
    categories: dict[str, dict[str, int]] = {}
    for provider in providers:
        bucket = categories.setdefault(provider["category"], {"total": 0, "installed": 0})
        bucket["total"] += 1
        bucket["installed"] += int(provider["installed"])
    covered = sum(1 for values in categories.values() if values["installed"] > 0)
    coverage = round((covered / len(categories)) * 100) if categories else 0
    return {
        "providers": providers,
        "summary": {
            "registered": len(providers),
            "installed": len(installed),
            "categories": len(categories),
            "covered_categories": covered,
            "integration_coverage": coverage,
        },
        "categories": categories,
        "policy": {
            "execution": "fixed-argv-only",
            "shell": False,
            "automatic_install": False,
            "privileged_actions": "root-agent-allowlist-only",
            "provider_detection": "read-only",
        },
    }
