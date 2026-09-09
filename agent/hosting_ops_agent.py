#!/usr/bin/env python3
from __future__ import annotations

import grp
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

from secret_vault import SecretVault

SOCK = Path(os.environ.get("NVP_OPS_SOCK", "/run/nexvary-panel/ops.sock"))
SITE_BASE = Path("/var/www")
NGINX_SITES = Path("/etc/nginx/sites-available")
NGINX_MANAGED = Path("/etc/nginx/nexvary")
MIGRATION_BASE = Path("/var/backups/nexvary-panel/migrations")
VAULT = SecretVault(Path(os.environ.get("NVP_VAULT_DIR", "/etc/nexvary-panel/credentials")))
MAX_REQUEST = 64 * 1024
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
DB_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9_@%+=:.,!$#?-]{14,128}$")
PHP_RE = re.compile(r"^[0-9]{1,2}\.[0-9]{1,2}$")
RECORD_TYPES = {"A", "AAAA", "CNAME", "TXT", "MX"}
ACTIONS = {
    "status", "dns-apply", "dns-rollback", "ssl-status", "ssl-issue", "ssl-renew",
    "mail-queue", "mail-flush", "php-list", "php-set", "postgres-create", "postgres-delete",
    "migration-export", "migration-restore", "service-status", "service-action",
}
ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": "/root"}


def _run(args: list[str], timeout: int = 60, stdin: str | None = None, ok_codes=(0,)) -> subprocess.CompletedProcess:
    proc = subprocess.run(args, capture_output=True, text=True, input=stdin, timeout=timeout, env=ENV, check=False)
    if proc.returncode not in ok_codes:
        raise RuntimeError("ops-command-failed")
    return proc


def _domain(value: object) -> str:
    domain = str(value or "").strip().lower()
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("invalid-domain")
    return domain


def _site_root(domain: str) -> Path:
    root = SITE_BASE / _domain(domain)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("site-root-not-found")
    if os.path.commonpath((str(SITE_BASE), str(root.resolve()))) != str(SITE_BASE):
        raise ValueError("unsafe-site-root")
    return root


def _db(value: object) -> str:
    value = str(value or "").strip()
    if not DB_RE.fullmatch(value):
        raise ValueError("invalid-database-identifier")
    return value


def _public_https(url: str, allow_host: str | None = None) -> str:
    parts = urllib.parse.urlsplit(str(url or "").strip())
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError("invalid-provider-endpoint")
    host = parts.hostname.rstrip(".").lower()
    if allow_host and host != allow_host:
        raise ValueError("provider-host-not-allowed")
    if host == "localhost" or host.endswith((".localhost", ".local")):
        raise ValueError("provider-host-not-allowed")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9.-]+", host):
            raise ValueError("provider-host-not-allowed")
    else:
        if not address.is_global:
            raise ValueError("provider-host-not-allowed")
    return urllib.parse.urlunsplit(parts)


def _secret(secret_id: str, kind: str) -> str:
    path = VAULT.credential_path(str(secret_id), str(kind))
    value = path.read_text(encoding="utf-8").strip()
    if not value or "\x00" in value or len(value) > 16384:
        raise ValueError("invalid-provider-secret")
    return value


def _http(url: str, method: str = "GET", headers: dict | None = None, body: dict | None = None, timeout: int = 20) -> dict:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    req = urllib.request.Request(url, data=data, headers={"Accept": "application/json", "User-Agent": "Nexvary-Panel/0.7", **(headers or {})}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as response:
            raw = response.read(512 * 1024)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"provider-http-{exc.code}")
    except (OSError, urllib.error.URLError):
        raise RuntimeError("provider-network-failed")
    if not raw:
        return {}
    try:
        parsed = json.loads(raw.decode())
    except Exception:
        raise RuntimeError("provider-invalid-json")
    return parsed if isinstance(parsed, dict) else {"data": parsed}


def _record(data: dict) -> dict:
    domain = _domain(data.get("domain"))
    record_type = str(data.get("record_type", "")).upper()
    name = str(data.get("record_name", "")).strip().rstrip(".").lower()
    value = str(data.get("record_value", "")).strip()
    if record_type not in RECORD_TYPES:
        raise ValueError("record-type-not-allowed")
    if name not in {domain, "@"} and not (name.endswith("." + domain) and DOMAIN_RE.fullmatch(name)):
        raise ValueError("record-name-outside-zone")
    if not value or len(value) > 4096 or any(c in value for c in "\r\n\x00"):
        raise ValueError("invalid-record-value")
    ttl = int(data.get("ttl", 300))
    priority = int(data.get("priority", 0))
    if not 60 <= ttl <= 86400 or not 0 <= priority <= 65535:
        raise ValueError("invalid-record-options")
    return {"domain": domain, "type": record_type, "name": domain if name == "@" else name, "content": value, "ttl": ttl, "priority": priority}


def _cloudflare_target(endpoint: str) -> str:
    url = _public_https(endpoint, "api.cloudflare.com")
    parts = urllib.parse.urlsplit(url)
    if not re.fullmatch(r"/client/v4/zones/[A-Za-z0-9_-]{8,80}/?", parts.path):
        raise ValueError("cloudflare-endpoint-must-be-zone-url")
    return url.rstrip("/")


def _dns_apply(data: dict) -> dict:
    provider = str(data.get("provider", "")).lower()
    operation = str(data.get("operation", "")).lower()
    record = _record(data)
    record_id = str(data.get("provider_record_id", "")).strip()
    if operation not in {"create", "update", "delete"}:
        raise ValueError("dns-operation-not-allowed")
    if provider == "cloudflare":
        base = _cloudflare_target(str(data.get("endpoint", "")))
        token = _secret(str(data.get("secret_id", "")), "cloudflare")
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        before = []
        if record_id:
            current = _http(f"{base}/dns_records/{urllib.parse.quote(record_id, safe='')}", headers=headers)
            if current.get("success") and isinstance(current.get("result"), dict):
                before = [current["result"]]
        else:
            query = urllib.parse.urlencode({"type": record["type"], "name": record["name"]})
            current = _http(f"{base}/dns_records?{query}", headers=headers)
            if current.get("success") and isinstance(current.get("result"), list):
                before = current["result"][:20]
        payload = {"type": record["type"], "name": record["name"], "content": record["content"], "ttl": record["ttl"]}
        if record["type"] == "MX":
            payload["priority"] = record["priority"]
        if operation == "create":
            result = _http(f"{base}/dns_records", "POST", headers, payload)
        elif operation == "update":
            if not record_id:
                raise ValueError("provider-record-id-required")
            result = _http(f"{base}/dns_records/{urllib.parse.quote(record_id, safe='')}", "PUT", headers, payload)
        else:
            if not record_id:
                raise ValueError("provider-record-id-required")
            result = _http(f"{base}/dns_records/{urllib.parse.quote(record_id, safe='')}", "DELETE", headers)
        if result.get("success") is not True:
            raise RuntimeError("dns-provider-rejected-change")
        created = (result.get("result") or {}).get("id", "") if isinstance(result.get("result"), dict) else ""
        return {"ok": True, "provider": provider, "provider_record_id": created or record_id, "snapshot": {"records": before, "created_id": created if operation == "create" else ""}}
    if provider == "powerdns":
        endpoint = _public_https(str(data.get("endpoint", "")))
        key = _secret(str(data.get("secret_id", "")), "powerdns")
        headers = {"X-API-Key": key, "Content-Type": "application/json"}
        zone = _http(endpoint, headers=headers)
        rrsets = zone.get("rrsets", []) if isinstance(zone, dict) else []
        before = [x for x in rrsets if isinstance(x, dict) and str(x.get("name", "")).rstrip(".").lower() == record["name"] and str(x.get("type", "")).upper() == record["type"]][:5]
        if operation == "delete":
            rrset = {"name": record["name"] + ".", "type": record["type"], "changetype": "DELETE"}
        else:
            content = record["content"]
            if record["type"] == "MX":
                content = f"{record['priority']} {content}"
            if record["type"] == "TXT" and not (content.startswith('"') and content.endswith('"')):
                content = json.dumps(content)
            rrset = {"name": record["name"] + ".", "type": record["type"], "ttl": record["ttl"], "changetype": "REPLACE", "records": [{"content": content, "disabled": False}]}
        _http(endpoint, "PATCH", headers, {"rrsets": [rrset]})
        return {"ok": True, "provider": provider, "provider_record_id": "", "snapshot": {"rrsets": before}}
    raise ValueError("dns-provider-not-supported")


def _dns_rollback(data: dict) -> dict:
    provider = str(data.get("provider", "")).lower()
    snapshot = data.get("snapshot")
    if not isinstance(snapshot, dict):
        raise ValueError("invalid-dns-snapshot")
    if provider == "cloudflare":
        base = _cloudflare_target(str(data.get("endpoint", "")))
        token = _secret(str(data.get("secret_id", "")), "cloudflare")
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        records = snapshot.get("records", [])
        created = str(snapshot.get("created_id", ""))
        if isinstance(records, list) and records:
            for record in records[:20]:
                if not isinstance(record, dict) or not record.get("id"):
                    continue
                payload = {k: record[k] for k in ("type", "name", "content", "ttl", "priority", "proxied") if k in record}
                _http(f"{base}/dns_records/{urllib.parse.quote(str(record['id']), safe='')}", "PUT", headers, payload)
        elif created:
            _http(f"{base}/dns_records/{urllib.parse.quote(created, safe='')}", "DELETE", headers)
        return {"ok": True, "restored": len(records) if isinstance(records, list) else 0}
    if provider == "powerdns":
        endpoint = _public_https(str(data.get("endpoint", "")))
        key = _secret(str(data.get("secret_id", "")), "powerdns")
        headers = {"X-API-Key": key, "Content-Type": "application/json"}
        rrsets = snapshot.get("rrsets", [])
        if not isinstance(rrsets, list):
            raise ValueError("invalid-dns-snapshot")
        restored = []
        for item in rrsets[:5]:
            if isinstance(item, dict) and item.get("name") and item.get("type"):
                restored.append({"name": item["name"], "type": item["type"], "ttl": int(item.get("ttl", 300)), "changetype": "REPLACE", "records": item.get("records", [])})
        if restored:
            _http(endpoint, "PATCH", headers, {"rrsets": restored})
        return {"ok": True, "restored": len(restored)}
    raise ValueError("dns-provider-not-supported")


def _nginx_conf(domain: str) -> Path:
    path = NGINX_SITES / f"{_domain(domain)}.conf"
    if not path.is_file() or path.is_symlink():
        raise ValueError("managed-nginx-site-not-found")
    return path


def _bind_ssl(domain: str) -> None:
    domain = _domain(domain)
    conf = _nginx_conf(domain)
    old = conf.read_text(encoding="utf-8")
    managed = NGINX_MANAGED / domain
    managed.mkdir(parents=True, exist_ok=True)
    tls = managed / "tls.conf"
    old_tls = tls.read_text(encoding="utf-8") if tls.exists() and tls.is_file() and not tls.is_symlink() else None
    cert = Path("/etc/letsencrypt/live") / domain / "fullchain.pem"
    key = Path("/etc/letsencrypt/live") / domain / "privkey.pem"
    if not cert.is_file() or not key.is_file():
        raise RuntimeError("certificate-files-missing")
    new = old
    if not re.search(r"\blisten\s+443\s+ssl\s*;", new):
        new, count = re.subn(r"(\blisten\s+80\s*;)", r"\1\n    listen 443 ssl;", new, count=1)
        if count != 1:
            raise RuntimeError("managed-http-listener-not-found")
    include = f"include /etc/nginx/nexvary/{domain}/*.conf;"
    if include not in new:
        pos = new.rfind("}")
        if pos < 0:
            raise RuntimeError("invalid-nginx-site-config")
        new = new[:pos] + "    " + include + "\n" + new[pos:]
    conf.write_text(new, encoding="utf-8")
    tls.write_text(f"ssl_certificate {cert};\nssl_certificate_key {key};\nssl_protocols TLSv1.2 TLSv1.3;\n", encoding="utf-8")
    try:
        _run(["nginx", "-t"], 20)
        _run(["systemctl", "reload", "nginx"], 25)
    except Exception:
        conf.write_text(old, encoding="utf-8")
        if old_tls is None:
            tls.unlink(missing_ok=True)
        else:
            tls.write_text(old_tls, encoding="utf-8")
        subprocess.run(["nginx", "-t"], capture_output=True, text=True, env=ENV, check=False)
        subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True, env=ENV, check=False)
        raise


def _ssl_status(domain: str) -> dict:
    domain = _domain(domain)
    cert = Path("/etc/letsencrypt/live") / domain / "fullchain.pem"
    if not cert.is_file():
        return {"ok": True, "installed": False, "domain": domain}
    proc = _run(["openssl", "x509", "-in", str(cert), "-noout", "-enddate", "-issuer", "-subject"], 15)
    return {"ok": True, "installed": True, "domain": domain, "detail": proc.stdout[-4000:]}


def _ssl_issue(data: dict) -> dict:
    domain = _domain(data.get("domain"))
    email = str(data.get("email", "")).strip().lower()
    if not EMAIL_RE.fullmatch(email):
        raise ValueError("invalid-contact-email")
    root = _site_root(domain)
    _run(["certbot", "certonly", "--webroot", "-w", str(root), "-d", domain, "--non-interactive", "--agree-tos", "--email", email, "--keep-until-expiring"], 220)
    _bind_ssl(domain)
    return _ssl_status(domain)


def _ssl_renew(domain: str) -> dict:
    domain = _domain(domain)
    _run(["certbot", "renew", "--cert-name", domain, "--non-interactive"], 220)
    _bind_ssl(domain)
    return _ssl_status(domain)


def _mail_queue() -> dict:
    if not shutil.which("postqueue"):
        return {"ok": False, "error": "postfix-not-installed"}
    proc = _run(["postqueue", "-j"], 20)
    rows = []
    for line in proc.stdout.splitlines()[:300]:
        try:
            item = json.loads(line)
        except Exception:
            continue
        if not isinstance(item, dict):
            continue
        recipients = item.get("recipients", []) if isinstance(item.get("recipients"), list) else []
        rows.append({"queue_id": str(item.get("queue_id", ""))[:32], "queue_name": str(item.get("queue_name", ""))[:32], "arrival_time": int(item.get("arrival_time", 0) or 0), "message_size": int(item.get("message_size", 0) or 0), "sender": str(item.get("sender", ""))[:320], "recipients": len(recipients)})
    return {"ok": True, "count": len(rows), "messages": rows[:100]}


def _php_versions() -> list[str]:
    versions = []
    run_dir = Path("/run/php")
    for path in run_dir.glob("php*-fpm.sock") if run_dir.is_dir() else []:
        match = re.fullmatch(r"php([0-9]+\.[0-9]+)-fpm\.sock", path.name)
        if match and PHP_RE.fullmatch(match.group(1)):
            versions.append(match.group(1))
    return sorted(set(versions))


def _php_set(domain: str, version: str) -> dict:
    domain = _domain(domain)
    if version not in _php_versions():
        raise ValueError("php-version-not-installed")
    conf = _nginx_conf(domain)
    old = conf.read_text(encoding="utf-8")
    new, count = re.subn(r"fastcgi_pass\s+unix:/run/php/php[0-9]+\.[0-9]+-fpm\.sock\s*;", f"fastcgi_pass unix:/run/php/php{version}-fpm.sock;", old)
    if count < 1:
        raise RuntimeError("php-runtime-location-not-managed")
    conf.write_text(new, encoding="utf-8")
    try:
        _run(["nginx", "-t"], 20)
        _run(["systemctl", "reload", "nginx"], 25)
    except Exception:
        conf.write_text(old, encoding="utf-8")
        raise
    return {"ok": True, "domain": domain, "version": version}


def _postgres_create(data: dict) -> dict:
    name = _db(data.get("db_name"))
    user = _db(data.get("db_user"))
    password = str(data.get("password", ""))
    if not PASSWORD_RE.fullmatch(password):
        raise ValueError("invalid-database-password")
    if not shutil.which("psql") or not shutil.which("createdb"):
        return {"ok": False, "error": "postgresql-not-installed"}
    escaped_password = password.replace("'", "''")
    sql = f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{user}') THEN CREATE ROLE \"{user}\" LOGIN PASSWORD '{escaped_password}'; ELSE ALTER ROLE \"{user}\" WITH LOGIN PASSWORD '{escaped_password}'; END IF; END $$;\n"
    _run(["runuser", "-u", "postgres", "--", "psql", "-v", "ON_ERROR_STOP=1", "-d", "postgres"], 30, sql)
    exists = _run(["runuser", "-u", "postgres", "--", "psql", "-tAc", f"SELECT 1 FROM pg_database WHERE datname='{name}'"], 15).stdout.strip() == "1"
    if not exists:
        _run(["runuser", "-u", "postgres", "--", "createdb", "-O", user, name], 30)
    return {"ok": True, "db_name": name, "db_user": user}


def _postgres_delete(data: dict) -> dict:
    name = _db(data.get("db_name"))
    user = _db(data.get("db_user"))
    if not shutil.which("dropdb"):
        return {"ok": False, "error": "postgresql-not-installed"}
    _run(["runuser", "-u", "postgres", "--", "dropdb", "--if-exists", name], 30)
    _run(["runuser", "-u", "postgres", "--", "dropuser", "--if-exists", user], 30)
    return {"ok": True, "deleted": True}


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    for member in tar.getmembers():
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
            raise ValueError("unsafe-migration-archive")
        target = dest.joinpath(*[x for x in path.parts if x != "."])
        if os.path.commonpath((str(dest), str(target))) != str(dest):
            raise ValueError("unsafe-migration-archive")
    tar.extractall(dest)


def _migration_export(data: dict) -> dict:
    domain = _domain(data.get("domain"))
    root = _site_root(domain)
    raw_db = str(data.get("db_name", "")).strip()
    db_name = _db(raw_db) if raw_db else ""
    MIGRATION_BASE.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    archive = MIGRATION_BASE / f"{domain}-{stamp}.tar.gz"
    tmp = Path(tempfile.mkdtemp(prefix="nvp-migrate-"))
    try:
        manifest = {"version": 1, "domain": domain, "database": db_name, "created_at": int(time.time())}
        (tmp / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        if db_name:
            proc = _run(["mariadb-dump", "--single-transaction", "--skip-lock-tables", "--", db_name], 120)
            (tmp / "database.sql").write_text(proc.stdout, encoding="utf-8")
        with tarfile.open(archive, "w:gz") as out:
            out.add(root, arcname="site", recursive=True)
            out.add(tmp / "manifest.json", arcname="manifest.json")
            if (tmp / "database.sql").exists():
                out.add(tmp / "database.sql", arcname="database.sql")
        os.chmod(archive, 0o600)
        digest = hashlib.sha256()
        with archive.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return {"ok": True, "archive": str(archive), "size_bytes": archive.stat().st_size, "sha256": digest.hexdigest()}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _migration_restore(data: dict) -> dict:
    domain = _domain(data.get("domain"))
    root = _site_root(domain)
    archive = Path(str(data.get("archive", "")))
    raw_db = str(data.get("db_name", "")).strip()
    db_name = _db(raw_db) if raw_db else ""
    try:
        if archive.resolve().parent != MIGRATION_BASE.resolve() or not archive.is_file() or archive.is_symlink():
            raise ValueError("migration-archive-outside-vault")
    except OSError:
        raise ValueError("migration-archive-not-found")
    tmp = Path(tempfile.mkdtemp(prefix="nvp-migration-restore-"))
    rollback = MIGRATION_BASE / f"{domain}-rollback-{int(time.time())}.tar.gz"
    old = root.with_name(root.name + ".migration-old")
    try:
        with tarfile.open(rollback, "w:gz") as out:
            out.add(root, arcname="site", recursive=True)
        with tarfile.open(archive, "r:gz") as src:
            _safe_extract(src, tmp)
        site = tmp / "site"
        if not site.is_dir():
            raise ValueError("migration-site-missing")
        shutil.rmtree(old, ignore_errors=True)
        root.rename(old)
        shutil.copytree(site, root, symlinks=False)
        shutil.rmtree(old, ignore_errors=True)
        if db_name and (tmp / "database.sql").is_file():
            _run(["mariadb", "--", db_name], 120, (tmp / "database.sql").read_text(encoding="utf-8"))
        return {"ok": True, "rollback": str(rollback)}
    except Exception:
        if old.exists() and not root.exists():
            old.rename(root)
        raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _service_names() -> list[str]:
    names = ["nginx", "mariadb", "fail2ban", "postfix", "dovecot", "postgresql", "ssh"]
    names.extend(f"php{version}-fpm" for version in _php_versions())
    return names


def _service_status() -> dict:
    rows = []
    for name in _service_names():
        proc = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=5, env=ENV, check=False)
        rows.append({"name": name, "active": proc.stdout.strip() == "active"})
    return {"ok": True, "services": rows}


def _service_action(name: str, operation: str) -> dict:
    if name not in set(_service_names()) or operation not in {"reload", "restart"}:
        raise ValueError("service-action-not-allowed")
    _run(["systemctl", operation, name], 35)
    return {"ok": True, "name": name, "action": operation}


def _status() -> dict:
    return {"ok": True, "engine": "nexvary-hosting-ops", "capabilities": {
        "dns": True,
        "ssl": bool(shutil.which("certbot")),
        "mail_queue": bool(shutil.which("postqueue")),
        "php": bool(_php_versions()),
        "postgres": bool(shutil.which("psql")),
        "migrations": bool(shutil.which("mariadb-dump")),
        "service_control": True,
    }}


def dispatch(data: dict) -> dict:
    action = str(data.get("action", ""))
    if action not in ACTIONS:
        return {"ok": False, "error": "ops-action-not-allowed"}
    if action == "status":
        return _status()
    if action == "dns-apply":
        return _dns_apply(data)
    if action == "dns-rollback":
        return _dns_rollback(data)
    if action == "ssl-status":
        return _ssl_status(str(data.get("domain", "")))
    if action == "ssl-issue":
        return _ssl_issue(data)
    if action == "ssl-renew":
        return _ssl_renew(str(data.get("domain", "")))
    if action == "mail-queue":
        return _mail_queue()
    if action == "mail-flush":
        if not shutil.which("postqueue"):
            return {"ok": False, "error": "postfix-not-installed"}
        _run(["postqueue", "-f"], 20)
        return {"ok": True}
    if action == "php-list":
        return {"ok": True, "versions": _php_versions()}
    if action == "php-set":
        return _php_set(str(data.get("domain", "")), str(data.get("version", "")))
    if action == "postgres-create":
        return _postgres_create(data)
    if action == "postgres-delete":
        return _postgres_delete(data)
    if action == "migration-export":
        return _migration_export(data)
    if action == "migration-restore":
        return _migration_restore(data)
    if action == "service-status":
        return _service_status()
    return _service_action(str(data.get("name", "")), str(data.get("operation", "")))


def main() -> None:
    SOCK.parent.mkdir(parents=True, exist_ok=True)
    if SOCK.exists() or SOCK.is_symlink():
        SOCK.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(SOCK))
    os.chown(SOCK, 0, grp.getgrnam("nexvary-panel").gr_gid)
    os.chmod(SOCK, 0o660)
    server.listen(32)
    while True:
        conn, _ = server.accept()
        with conn:
            try:
                raw = b""
                while not raw.endswith(b"\n") and len(raw) <= MAX_REQUEST:
                    chunk = conn.recv(8192)
                    if not chunk:
                        break
                    raw += chunk
                if not raw.endswith(b"\n") or len(raw) > MAX_REQUEST:
                    raise ValueError("request-too-large")
                data = json.loads(raw.decode())
                if not isinstance(data, dict):
                    raise ValueError("object-required")
                result = dispatch(data)
            except ValueError as exc:
                result = {"ok": False, "error": str(exc)[:160]}
            except Exception as exc:
                result = {"ok": False, "error": str(exc)[:160] if str(exc) else "ops-operation-failed"}
            conn.sendall((json.dumps(result, separators=(",", ":")) + "\n").encode())


if __name__ == "__main__":
    main()
