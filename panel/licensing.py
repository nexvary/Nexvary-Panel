from __future__ import annotations

import base64, json, os, socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import APP_DIR

LICENSE_FILE = Path(os.environ.get("NVP_LICENSE_FILE", str(APP_DIR / "license.json")))
PUBLIC_KEY_FILE = Path(os.environ.get("NVP_LICENSE_PUBLIC_KEY", "/etc/nexvary-panel/license-public.pem"))

@dataclass(frozen=True)
class LicenseState:
    status: str
    reason: str
    claims: dict

    @property
    def valid(self) -> bool:
        return self.status in {"VALID", "GRACE"}

    def feature(self, name: str) -> bool:
        return self.valid and name in set(self.claims.get("features", []))

def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def _server_id() -> str:
    machine = Path("/etc/machine-id")
    raw = machine.read_text(encoding="utf-8").strip() if machine.exists() else socket.gethostname()
    import hashlib
    return hashlib.sha256(("nexvary-panel:"+raw).encode()).hexdigest()

def verify_license(now: datetime | None = None) -> LicenseState:
    now = now or datetime.now(timezone.utc)
    try:
        envelope = json.loads(LICENSE_FILE.read_text(encoding="utf-8"))
        payload = envelope["payload"]
        signature = base64.b64decode(envelope["signature"], validate=True)
        key = serialization.load_pem_public_key(PUBLIC_KEY_FILE.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            return LicenseState("LOCKED", "unsupported-key", {})
        key.verify(signature, _canonical(payload))
    except (OSError, KeyError, ValueError, json.JSONDecodeError, InvalidSignature):
        return LicenseState("LOCKED", "missing-or-invalid-license", {})

    bound = payload.get("server_id")
    if bound and bound != _server_id():
        return LicenseState("LOCKED", "server-mismatch", payload)
    try:
        expires = datetime.fromisoformat(payload["expires_at"].replace("Z","+00:00"))
    except (KeyError, ValueError):
        return LicenseState("LOCKED", "invalid-expiry", payload)
    if now <= expires:
        return LicenseState("VALID", "ok", payload)
    grace_days = max(0, min(int(payload.get("grace_days", 0)), 30))
    if (now - expires).days < grace_days:
        return LicenseState("GRACE", "expired-in-grace", payload)
    return LicenseState("LOCKED", "expired", payload)

def server_fingerprint() -> str:
    return _server_id()
