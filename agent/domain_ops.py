from __future__ import annotations

import re
from pathlib import Path

from webtools import DOMAIN_RE, MAX_SITE_CONF, NGINX_BASE, _atomic_write, _run, _safe_regular, _valid_domain

MAX_ALIASES = 100


def _alias(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid-domain-alias")
    value = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(value):
        raise ValueError("invalid-domain-alias")
    return value


def sync_domain_aliases(domain: str, aliases: object) -> dict:
    domain = _valid_domain(domain.lower().strip())
    if not isinstance(aliases, list) or len(aliases) > MAX_ALIASES:
        return {"ok": False, "error": "invalid-domain-alias-set"}
    try:
        normalized = sorted({_alias(value) for value in aliases})
    except ValueError:
        return {"ok": False, "error": "invalid-domain-alias-set"}
    forbidden = {domain, f"www.{domain}"}
    if any(alias in forbidden for alias in normalized):
        return {"ok": False, "error": "primary-domain-cannot-be-an-alias"}

    conf = NGINX_BASE / f"{domain}.conf"
    try:
        _safe_regular(conf)
        old = conf.read_bytes()
        if len(old) > MAX_SITE_CONF:
            return {"ok": False, "error": "site-configuration-too-large"}
        names = " ".join([domain, f"www.{domain}", *normalized]).encode("ascii")
        replacement = b"server_name " + names + b";"
        updated, count = re.subn(rb"\bserver_name\s+[^;]+;", replacement, old, count=1)
        if count != 1:
            return {"ok": False, "error": "managed-server-name-directive-not-found"}
        if updated == old:
            return {"ok": True, "meta": {"aliases": len(normalized)}}
        _atomic_write(conf, updated, 0o644)
        if not _run(["nginx", "-t"]).get("ok"):
            _atomic_write(conf, old, 0o644)
            _run(["nginx", "-t"])
            return {"ok": False, "error": "alias-configuration-rejected"}
        if not _run(["systemctl", "reload", "nginx"]).get("ok"):
            _atomic_write(conf, old, 0o644)
            _run(["nginx", "-t"])
            _run(["systemctl", "reload", "nginx"])
            return {"ok": False, "error": "alias-reload-failed-previous-state-restored"}
        return {"ok": True, "meta": {"aliases": len(normalized)}}
    except (OSError, ValueError):
        return {"ok": False, "error": "domain-alias-synchronization-failed"}
