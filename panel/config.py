from __future__ import annotations

import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip() or "0.7.0"
except OSError:
    VERSION = "0.7.0"
APP_DIR = Path(os.environ.get("NVP_DATA_DIR", "/var/lib/nexvary-panel"))
DB_PATH = Path(os.environ.get("NVP_DB_PATH", str(APP_DIR / "panel.db")))
ADMIN_FILE = Path(os.environ.get("NVP_ADMIN_FILE", "/etc/nexvary-panel/admin.env"))
AGENT_SOCK = os.environ.get("NVP_AGENT_SOCK", "/run/nexvary-panel/agent.sock")
WEBTOOLS_SOCK = os.environ.get("NVP_WEBTOOLS_SOCK", "/run/nexvary-panel/webtools.sock")
MAIL_SOCK = os.environ.get("NVP_MAIL_SOCK", "/run/nexvary-panel/mail.sock")
TRANSFER_SOCK = os.environ.get("NVP_TRANSFER_SOCK", "/run/nexvary-panel/transfer.sock")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$")
DB_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
USER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{2,31}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9_@%+=:.,!$#?-]{14,128}$")
ROLES = {"admin", "reseller", "operator", "viewer"}
