from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

from mail_backend import MAIL_ROOT, _address, _vmail_identity

MAX_FILTERS = 40
MAX_PATTERN = 200
MAX_BODY = 5000
FOLDER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}$")
FIELDS = {"from": "From", "to": "To", "subject": "Subject", "spam_flag": "X-Spam-Flag"}
MATCHES = {"contains": ":contains", "is": ":is"}
ACTIONS = {"fileinto", "redirect", "discard"}


def _quoted(value: object, limit: int) -> str:
    text = str(value or "")
    if len(text) > limit or any(ch in text for ch in "\x00\r\n"):
        raise ValueError("invalid-sieve-string")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _multiline(value: object) -> str:
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    if len(text) > MAX_BODY or "\x00" in text:
        raise ValueError("invalid-vacation-body")
    lines = []
    for line in text.split("\n"):
        lines.append("." + line if line.startswith(".") else line)
    return "text:\n" + "\n".join(lines) + "\n.\n"


def _mailbox_home(address: str) -> tuple[str, Path]:
    localpart, domain = _address(address)
    home = MAIL_ROOT / domain / localpart
    try:
        st = os.lstat(home)
    except FileNotFoundError as exc:
        raise ValueError("mailbox-home-not-found") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise ValueError("unsafe-mailbox-home")
    expected = (MAIL_ROOT / domain / localpart).resolve(strict=False)
    if home.resolve(strict=True) != expected:
        raise ValueError("unsafe-mailbox-home")
    return f"{localpart}@{domain}", home


def _normalize_autoresponder(raw: object) -> dict:
    data = raw if isinstance(raw, dict) else {}
    enabled = bool(data.get("enabled"))
    try:
        days = int(data.get("interval_days", 1))
    except (TypeError, ValueError):
        raise ValueError("invalid-autoresponder")
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", "")).strip()
    if not 1 <= days <= 30 or len(subject) > 180 or len(body) > MAX_BODY or "\x00" in subject + body or "\r" in subject:
        raise ValueError("invalid-autoresponder")
    if enabled and (not subject or not body):
        raise ValueError("invalid-autoresponder")
    return {"enabled": enabled, "subject": subject, "body": body, "interval_days": days}


def _normalize_filters(raw: object) -> list[dict]:
    if not isinstance(raw, list) or len(raw) > MAX_FILTERS:
        raise ValueError("invalid-filter-set")
    out: list[dict] = []
    for item in raw:
        if not isinstance(item, dict) or not bool(item.get("enabled", True)):
            continue
        field = str(item.get("field", "")).strip().lower()
        match_type = str(item.get("match_type", "")).strip().lower()
        action = str(item.get("action", "")).strip().lower()
        pattern = str(item.get("pattern", "")).strip()
        destination = str(item.get("destination", "")).strip()
        try:
            priority = int(item.get("priority", 100))
        except (TypeError, ValueError):
            raise ValueError("invalid-filter")
        if field not in FIELDS or match_type not in MATCHES or action not in ACTIONS or not pattern or len(pattern) > MAX_PATTERN or not 1 <= priority <= 10000:
            raise ValueError("invalid-filter")
        if any(ch in pattern for ch in "\x00\r\n"):
            raise ValueError("invalid-filter")
        if action == "fileinto" and not FOLDER_RE.fullmatch(destination):
            raise ValueError("invalid-filter-destination")
        if action == "redirect" and (not EMAIL_RE.fullmatch(destination) or ".." in destination):
            raise ValueError("invalid-filter-destination")
        if action == "discard":
            destination = ""
        out.append({"field": field, "match_type": match_type, "pattern": pattern, "action": action, "destination": destination, "priority": priority})
    out.sort(key=lambda item: item["priority"])
    return out


def _normalize_spam(raw: object) -> dict:
    data = raw if isinstance(raw, dict) else {}
    enabled = bool(data.get("enabled"))
    action = str(data.get("action", "junk")).strip().lower()
    if action not in {"junk", "discard"}:
        raise ValueError("invalid-spam-policy")
    return {"enabled": enabled, "action": action}


def _build_script(address: str, autoresponder: dict, filters: list[dict], spam: dict) -> str:
    requires: set[str] = set()
    if autoresponder["enabled"]:
        requires.add("vacation")
    if spam["enabled"] and spam["action"] == "junk":
        requires.update({"fileinto", "mailbox"})
    for item in filters:
        if item["action"] == "fileinto":
            requires.update({"fileinto", "mailbox"})

    lines = ["# Managed by Nexvary Panel. Do not edit manually."]
    if requires:
        lines.append("require [" + ", ".join(_quoted(name, 40) for name in sorted(requires)) + "];")

    if spam["enabled"]:
        lines.append('if header :is "X-Spam-Flag" "YES" {')
        if spam["action"] == "junk":
            lines.append('  fileinto :create "Junk";')
        else:
            lines.append("  discard;")
        lines.append("  stop;")
        lines.append("}")

    for item in filters:
        header = FIELDS[item["field"]]
        match = MATCHES[item["match_type"]]
        lines.append(f"if header {match} {_quoted(header, 64)} {_quoted(item['pattern'], MAX_PATTERN)} {{")
        if item["action"] == "fileinto":
            lines.append(f"  fileinto :create {_quoted(item['destination'], 64)};")
        elif item["action"] == "redirect":
            lines.append(f"  redirect {_quoted(item['destination'], 320)};")
        else:
            lines.append("  discard;")
        lines.append("  stop;")
        lines.append("}")

    if autoresponder["enabled"]:
        lines.append(
            f"vacation :days {autoresponder['interval_days']} :subject {_quoted(autoresponder['subject'], 180)} {_multiline(autoresponder['body'])};"
        )
    return "\n".join(lines) + "\n"


def sieve_sync(address: str, autoresponder: object, filters: object, spam: object) -> dict:
    address, home = _mailbox_home(address)
    auto = _normalize_autoresponder(autoresponder)
    normalized_filters = _normalize_filters(filters)
    spam_policy = _normalize_spam(spam)
    active = home / ".dovecot.sieve"
    compiled = home / ".dovecot.svbin"
    if active.is_symlink() or compiled.is_symlink():
        raise ValueError("unsafe-sieve-boundary")

    has_rules = auto["enabled"] or bool(normalized_filters) or spam_policy["enabled"]
    if not has_rules:
        active.unlink(missing_ok=True)
        compiled.unlink(missing_ok=True)
        return {"ok": True, "address": address, "enabled": False, "filters": 0}

    sievec = shutil.which("sievec")
    if not sievec:
        return {"ok": False, "error": "dovecot-sieve-provider-not-installed"}
    script = _build_script(address, auto, normalized_filters, spam_policy)
    uid, gid = _vmail_identity()
    old_script = active.read_bytes() if active.exists() and active.is_file() else None
    old_bin = compiled.read_bytes() if compiled.exists() and compiled.is_file() else None
    tmp_script: Path | None = None
    tmp_bin: Path | None = None
    try:
        fd, name = tempfile.mkstemp(prefix=".nvp-sieve-", suffix=".sieve", dir=str(home))
        tmp_script = Path(name)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(script)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(tmp_script, uid, gid)
        os.chmod(tmp_script, 0o600)
        tmp_bin = tmp_script.with_suffix(".svbin")
        proc = subprocess.run([sievec, str(tmp_script), str(tmp_bin)], capture_output=True, text=True, timeout=15, check=False)
        if proc.returncode != 0 or not tmp_bin.is_file() or tmp_bin.is_symlink():
            raise RuntimeError("sieve-validation-failed")
        os.chown(tmp_bin, uid, gid)
        os.chmod(tmp_bin, 0o600)
        os.replace(tmp_script, active)
        tmp_script = None
        os.replace(tmp_bin, compiled)
        tmp_bin = None
        os.chown(active, uid, gid)
        os.chmod(active, 0o600)
        os.chown(compiled, uid, gid)
        os.chmod(compiled, 0o600)
    except Exception:
        try:
            if old_script is None:
                active.unlink(missing_ok=True)
            else:
                active.write_bytes(old_script)
                os.chown(active, uid, gid)
                os.chmod(active, 0o600)
            if old_bin is None:
                compiled.unlink(missing_ok=True)
            else:
                compiled.write_bytes(old_bin)
                os.chown(compiled, uid, gid)
                os.chmod(compiled, 0o600)
        finally:
            if tmp_script:
                tmp_script.unlink(missing_ok=True)
            if tmp_bin:
                tmp_bin.unlink(missing_ok=True)
        raise
    return {
        "ok": True,
        "address": address,
        "enabled": True,
        "filters": len(normalized_filters),
        "autoresponder": bool(auto["enabled"]),
        "spam_policy": bool(spam_policy["enabled"]),
    }
