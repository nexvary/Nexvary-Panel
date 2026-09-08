from __future__ import annotations

import os
import re
from pathlib import Path

VERSION = "0.4.0"
APP_DIR = Path(os.environ.get("NVP_DATA_DIR", "/var/lib/nexvary-panel"))
DB_PATH = Path(os.environ.get("NVP_DB_PATH", str(APP_DIR / "panel.db")))
ADMIN_FILE = Path(os.environ.get("NVP_ADMIN_FILE", "/etc/nexvary-panel/admin.env"))
AGENT_SOCK = os.environ.get("NVP_AGENT_SOCK", "/run/nexvary-panel/agent.sock")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$")
DB_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
USER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{2,31}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9_@%+=:.,!$#?-]{14,128}$")
ROLES = {"admin", "operator", "viewer"}
