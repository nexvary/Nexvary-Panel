#!/usr/bin/env python3
from __future__ import annotations

import configparser
import grp
import ipaddress
import json
import os
import re
import shutil
import socket
import stat
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from secret_vault import SecretVault

SOCK = Path(os.environ.get("NVP_PROVIDER_SOCK", "/run/nexvary-panel/provider.sock"))
BACKUP_BASE = Path("/var/backups/nexvary-panel")
VAULT = SecretVault(Path(os.environ.get("NVP_VAULT_DIR", "/etc/nexvary-panel/credentials")))
MAX_REQUEST_BYTES = 32 * 1024
MAX_OUTPUT = 5000
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
BACKUP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,220}\.tar\.gz$")


def _reply(conn: socket.socket, payload: dict) -> None:
    conn.sendall((json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8"))


def _run(args: list[str], timeout: int = 900) -> dict:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C.UTF-8",
                "HOME": "/tmp",
                "XDG_CONFIG_HOME": "/tmp/nexvary-provider-config",
                "XDG_CACHE_HOME": "/tmp/nexvary-provider-cache",
            },
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "provider operation timed out", "code": "provider-timeout"}
    except (OSError, subprocess.SubprocessError):
        return {"ok": False, "error": "provider execution failed", "code": "provider-exec-failed"}
    if proc.returncode:
        # Do not return provider stderr/stdout to the web tier: CLIs may echo endpoints or provider details.
        return {"ok": False, "error": f"provider operation failed (exit {proc.returncode})", "code": "provider-command-failed"}
    return {"ok": True, "output": (proc.stdout or "")[-MAX_OUTPUT:]}


def _validate_vault_boundary() -> None:
    """Provider Agent is a read-only Vault consumer; it must never chmod/create the Vault."""
    try:
        st = os.lstat(VAULT.base)
    except OSError as exc:
        raise RuntimeError("Secret Vault directory is unavailable") from exc
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise RuntimeError("Secret Vault boundary is invalid")
    if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o077:
        raise RuntimeError("Secret Vault ownership or permissions are unsafe")


def _split_remote(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or len(value) > 380 or "\x00" in value or "\r" in value or "\n" in value or ":" not in value:
        raise ValueError("invalid rclone target")
    remote, path = value.split(":", 1)
    if not REMOTE_RE.fullmatch(remote) or not path or path.startswith("/"):
        raise ValueError("rclone target must be named-remote:relative/path")
    parts = [p for p in path.split("/") if p]
    if not parts or any(p in {".", ".."} for p in parts):
        raise ValueError("unsafe remote path")
    return remote, "/".join(parts)


def _publicish_https(value: str) -> bool:
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    if parts.scheme != "https" or not parts.hostname or parts.username is not None or parts.password is not None or parts.fragment:
        return False
    host = parts.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return bool(re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9.-]+", host))


def _rclone_contract(secret_id: str, endpoint: str) -> dict:
    config_path = VAULT.credential_path(secret_id, "rclone")
    st = os.lstat(config_path)
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or stat.S_IMODE(st.st_mode) & 0o077:
        raise ValueError("rclone credential permissions are unsafe")
    remote_name, remote_path = _split_remote(endpoint)
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str.lower
    with config_path.open("r", encoding="utf-8") as fh:
        parser.read_file(fh)
    if remote_name not in parser:
        raise ValueError("selected rclone remote is missing from Vault config")
    crypt = parser[remote_name]
    if crypt.get("type", "").strip().lower() != "crypt":
        raise ValueError("selected rclone remote must be type=crypt")
    if crypt.get("no_data_encryption", "false").strip().lower() in {"1", "true", "yes", "on"}:
        raise ValueError("crypt data encryption cannot be disabled")
    if crypt.get("filename_encryption", "standard").strip().lower() == "off":
        raise ValueError("crypt filename encryption cannot be disabled")
    if not crypt.get("password", "").strip():
        raise ValueError("crypt remote has no encryption password")
    wrapped = crypt.get("remote", "").strip()
    base_name, _ = _split_remote(wrapped)
    if base_name not in parser:
        raise ValueError("crypt backing remote is missing")
    base = parser[base_name]
    if base.get("type", "").strip().lower() != "s3":
        raise ValueError("initial encrypted backup policy allows crypt over S3 only")
    custom_endpoint = base.get("endpoint", "").strip()
    if custom_endpoint and not _publicish_https(custom_endpoint):
        raise ValueError("S3 custom endpoint must be public HTTPS")
    return {
        "config_path": str(config_path),
        "remote": remote_name,
        "remote_path": remote_path,
        "backing_remote": base_name,
        "backing_type": "s3",
        "custom_endpoint": bool(custom_endpoint),
    }


def _backup_file(domain: str, archive: str) -> Path:
    if not isinstance(domain, str) or not DOMAIN_RE.fullmatch(domain):
        raise ValueError("invalid backup domain")
    if not isinstance(archive, str) or len(archive) > 800:
        raise ValueError("invalid backup archive")
    expected = (BACKUP_BASE / domain).resolve()
    path = Path(archive)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError("backup archive not found") from exc
    if resolved.parent != expected or not BACKUP_NAME_RE.fullmatch(resolved.name):
        raise ValueError("backup archive is outside the allowed vault or has an unsafe name")
    st = os.lstat(resolved)
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise ValueError("backup archive must be a regular file")
    return resolved


def rclone_preflight(secret_id: str, endpoint: str) -> dict:
    rclone = shutil.which("rclone")
    if not rclone:
        return {"ok": False, "error": "rclone is not installed", "code": "provider-missing"}
    try:
        contract = _rclone_contract(secret_id, endpoint)
    except (OSError, ValueError, configparser.Error, UnicodeError) as exc:
        return {"ok": False, "error": str(exc), "code": "contract-invalid"}
    version = _run([rclone, "version"], timeout=8)
    return {
        "ok": True,
        "provider": "rclone",
        "version": (version.get("output") or "").splitlines()[0][:160] if version.get("ok") else "",
        "contract": {k: v for k, v in contract.items() if k != "config_path"},
        "network_tested": False,
    }


def rclone_upload(domain: str, archive: str, secret_id: str, endpoint: str) -> dict:
    rclone = shutil.which("rclone")
    if not rclone:
        return {"ok": False, "error": "rclone is not installed"}
    try:
        source = _backup_file(domain, archive)
        contract = _rclone_contract(secret_id, endpoint)
    except (OSError, ValueError, configparser.Error, UnicodeError) as exc:
        return {"ok": False, "error": str(exc)}
    destination_dir = f"{contract['remote']}:{contract['remote_path']}"
    destination = destination_dir.rstrip("/") + "/" + source.name
    result = _run([
        rclone, "copyto", "--config", contract["config_path"], "--immutable", "--no-traverse",
        "--retries", "2", "--low-level-retries", "2", "--contimeout", "10s", "--timeout", "60s",
        "--", str(source), destination,
    ], timeout=1800)
    if not result.get("ok"):
        return result
    check = _run([
        rclone, "size", "--config", contract["config_path"], "--json", "--max-depth", "1",
        "--include", source.name, "--", destination_dir,
    ], timeout=120)
    verified = False
    remote_bytes = 0
    if check.get("ok"):
        try:
            data = json.loads(check.get("output") or "{}")
            remote_bytes = int(data.get("bytes", 0) or 0)
            verified = int(data.get("count", 0) or 0) == 1 and remote_bytes == source.stat().st_size
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
    if not verified:
        return {"ok": False, "error": "upload completed but remote size verification failed"}
    return {
        "ok": True,
        "meta": {
            "provider": "rclone",
            "encryption": "rclone-crypt",
            "backing": "s3",
            "object": destination,
            "bytes": remote_bytes,
            "verification": "remote-size",
        },
    }


def handle(req: dict) -> dict:
    action = req.get("action")
    if action == "rclone-preflight":
        return rclone_preflight(str(req.get("secret_id", "")), str(req.get("endpoint", "")))
    if action == "rclone-upload-backup":
        return rclone_upload(
            str(req.get("domain", "")), str(req.get("archive", "")),
            str(req.get("secret_id", "")), str(req.get("endpoint", "")),
        )
    return {"ok": False, "error": "action not allowed"}


def main() -> None:
    _validate_vault_boundary()
    SOCK.parent.mkdir(parents=True, exist_ok=True)
    if SOCK.exists() or SOCK.is_symlink():
        SOCK.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(SOCK))
    gid = grp.getgrnam("nexvary-panel").gr_gid
    os.chown(SOCK, 0, gid)
    os.chmod(SOCK, 0o660)
    server.listen(16)
    while True:
        conn, _ = server.accept()
        with conn:
            try:
                data = b""
                while not data.endswith(b"\n") and len(data) <= MAX_REQUEST_BYTES:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                if not data.endswith(b"\n") or len(data) > MAX_REQUEST_BYTES:
                    raise ValueError("request too large or incomplete")
                req = json.loads(data.decode("utf-8"))
                if not isinstance(req, dict):
                    raise ValueError("object required")
                _reply(conn, handle(req))
            except Exception:
                _reply(conn, {"ok": False, "error": "bad request"})


if __name__ == "__main__":
    main()
