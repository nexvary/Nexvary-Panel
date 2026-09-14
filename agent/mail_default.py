from __future__ import annotations

import re

from mail_backend import VIRTUAL_FILE, _read_map, _reload, _rollback, _snapshot, _write_state

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}$")


def _domain(value: object) -> str:
    domain = str(value or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("invalid-mail-domain")
    return domain


def _destination(value: object, domain: str) -> str:
    address = str(value or "").strip().lower()
    if len(address) > 320 or not EMAIL_RE.fullmatch(address) or ".." in address:
        raise ValueError("invalid-forward-destination")
    # A catch-all that forwards back into the same virtual domain can recurse on unknown recipients.
    if address.rsplit("@", 1)[1] == domain:
        raise ValueError("catchall-loop-risk")
    return address


def default_address_sync(domain: object, mode: object, destination: object = "") -> dict:
    domain = _domain(domain)
    mode = str(mode or "").strip().lower()
    if mode not in {"reject", "forward"}:
        raise ValueError("invalid-default-address-mode")
    target = ""
    if mode == "forward":
        target = _destination(destination, domain)

    snapshot = _snapshot()
    state = {name: dict(values) for name, values in snapshot.items()}
    key = f"@{domain}"
    # Explicit aliases/mailboxes remain more specific than the @domain catch-all in Postfix.
    if mode == "forward":
        state["domains"][domain] = "OK"
        state["aliases"][key] = target
    else:
        state["aliases"].pop(key, None)
    try:
        _write_state(state)
        _reload()
    except Exception:
        _rollback(snapshot)
        raise
    return {"ok": True, "domain": domain, "mode": mode, "destination": target}
