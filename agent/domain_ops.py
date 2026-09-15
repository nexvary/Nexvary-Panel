from __future__ import annotations

import re
from pathlib import Path

from webtools import DOMAIN_RE, MAX_SITE_CONF, NGINX_BASE, _atomic_write, _run, _safe_regular, _valid_domain

MAX_ALIASES = 100
SERVER_NAME_RE = re.compile(rb"\bserver_name\s+([^;]+);")


def _alias(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid-domain-alias")
    value = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(value):
        raise ValueError("invalid-domain-alias")
    return value


def _rewrite_managed_server_names(raw: bytes, domain: str, aliases: list[str]) -> tuple[bytes, int]:
    """Rewrite every server_name directive that already owns the primary domain.

    Certbot may split an HTTP vhost into HTTP and TLS server blocks. Updating only
    the first directive leaves aliases inconsistent across protocols. We update all
    server_name directives that contain the exact primary domain or www variant,
    while leaving unrelated vhosts in the same file untouched.
    """
    names = " ".join([domain, f"www.{domain}", *aliases]).encode("ascii")
    replacement = b"server_name " + names + b";"
    managed = {domain.encode("ascii"), f"www.{domain}".encode("ascii")}
    count = 0

    def repl(match: re.Match[bytes]) -> bytes:
        nonlocal count
        tokens = {token.strip() for token in match.group(1).split() if token.strip()}
        if not tokens.intersection(managed):
            return match.group(0)
        count += 1
        return replacement

    return SERVER_NAME_RE.sub(repl, raw), count


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
        updated, count = _rewrite_managed_server_names(old, domain, normalized)
        if count < 1:
            return {"ok": False, "error": "managed-server-name-directive-not-found"}
        if updated == old:
            return {"ok": True, "meta": {"aliases": len(normalized), "server_blocks": count}}
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
        return {"ok": True, "meta": {"aliases": len(normalized), "server_blocks": count}}
    except (OSError, ValueError):
        return {"ok": False, "error": "domain-alias-synchronization-failed"}
