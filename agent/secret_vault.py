#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import stat
import tempfile
import time
from pathlib import Path

DEFAULT_VAULT_DIR = Path("/etc/nexvary-panel/credentials")
SECRET_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{2,47}$")
SECRET_KINDS = {"cloudflare", "powerdns", "s3", "restic", "rclone"}
MAX_SECRET_BYTES = 16 * 1024
MIN_SECRET_BYTES = 8


class SecretVault:
    """Root-owned credential storage. Deliberately exposes metadata, not secret values."""

    def __init__(self, base: Path = DEFAULT_VAULT_DIR):
        self.base = Path(base)

    def ensure(self) -> None:
        self.base.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.base.is_symlink() or not self.base.is_dir():
            raise ValueError("vault path must be a real directory")
        os.chmod(self.base, 0o700)

    def _validate(self, secret_id: str, kind: str) -> tuple[str, str]:
        if not isinstance(secret_id, str) or not SECRET_ID_RE.fullmatch(secret_id):
            raise ValueError("invalid secret id")
        if kind not in SECRET_KINDS:
            raise ValueError("secret kind is not allowed")
        return secret_id, kind

    def _path(self, secret_id: str, kind: str) -> Path:
        secret_id, kind = self._validate(secret_id, kind)
        return self.base / f"{kind}--{secret_id}.secret"

    def put(self, secret_id: str, kind: str, value: str) -> dict:
        path = self._path(secret_id, kind)
        if not isinstance(value, str) or "\x00" in value:
            raise ValueError("invalid secret value")
        payload = value.encode("utf-8")
        if not MIN_SECRET_BYTES <= len(payload) <= MAX_SECRET_BYTES:
            raise ValueError("secret length is outside allowed bounds")
        self.ensure()
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(prefix=".nvp-secret-", dir=self.base, delete=False) as handle:
                temp_path = Path(handle.name)
                os.chmod(temp_path, 0o600)
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, path)
            os.chmod(path, 0o600)
            dir_fd = os.open(self.base, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            if temp_path and temp_path.exists():
                temp_path.unlink(missing_ok=True)
        st = path.stat()
        return {"id": secret_id, "kind": kind, "bytes": st.st_size, "updated_at": int(st.st_mtime)}

    def delete(self, secret_id: str, kind: str) -> bool:
        path = self._path(secret_id, kind)
        if not path.exists():
            return False
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
            raise ValueError("vault entry is not a regular file")
        path.unlink()
        return True

    def list_metadata(self) -> list[dict]:
        self.ensure()
        rows: list[dict] = []
        for path in sorted(self.base.glob("*.secret")):
            try:
                st = os.lstat(path)
                if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
                    continue
                stem = path.name[:-7]
                kind, sep, secret_id = stem.partition("--")
                if not sep:
                    continue
                self._validate(secret_id, kind)
                rows.append({"id": secret_id, "kind": kind, "bytes": st.st_size, "updated_at": int(st.st_mtime)})
            except (OSError, ValueError):
                continue
        return rows

    def credential_path(self, secret_id: str, kind: str) -> Path:
        """Internal provider-only path accessor. Never expose its contents through the web API."""
        path = self._path(secret_id, kind)
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
            raise ValueError("credential not available")
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise ValueError("credential permissions are too broad")
        return path


if __name__ == "__main__":
    vault = SecretVault()
    vault.ensure()
    print(f"Nexvary Secret Vault ready: {len(vault.list_metadata())} credential metadata entries")
