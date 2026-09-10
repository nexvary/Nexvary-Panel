#!/usr/bin/env python3
from __future__ import annotations

import grp
import hashlib
import http.client
import ipaddress
import json
import os
import pwd
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
from pathlib import Path, PurePosixPath

from secret_vault import SecretVault

SOCK = Path(os.environ.get("NVP_OPS_SOCK", "/run/nexvary-panel/ops.sock"))
SITE_BASE = Path("/var/www")
NGINX_SITES = Path("/etc/nginx/sites-available")
NGINX_MANAGED = Path("/etc/nginx/nexvary")
MIGRATION_BASE = Path("/var/backups/nexvary-panel/migrations")
VAULT = SecretVault(Path(os.environ.get("NVP_VAULT_DIR", "/etc/nexvary-panel/credentials")))
MAX_REQUEST = 64 * 1024
MAX_HTTP_BODY = 512 * 1024
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
BASE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": "/root"}


def _run(
    args: list[str],
    timeout: int = 60,
    stdin: str | None = None,
    ok_codes: tuple[int, ...] = (0,),
    run_as: str | None = None,
) -> subprocess.CompletedProcess:
    env = dict(BASE_ENV)
    kwargs: dict = {}
    if run_as:
        try:
            account = pwd.getpwnam(run_as)
            group = grp.getgrnam(run_as)
        except KeyError as exc:
            raise RuntimeError("ops-service-account-missing") from exc
        env["HOME"] = account.pw_dir if account.pw_dir and account.pw_dir != "/nonexistent" else "/tmp"
        kwargs.update(user=account.pw_uid, group=group.gr_gid, extra_groups=[])
    proc = subprocess.run(
        args,
        capture_output=True,
        text=True,
        input=stdin,
        timeout=timeout,
        env=env,
        check=False,
        **kwargs,
    )
    if proc.returncode not in ok_codes:
        command = Path(args[0]).name[:48]
        # Never journal command input: PostgreSQL/MariaDB stdin may contain passwords or database contents.
        detail = "" if stdin is not None else (proc.stderr or proc.stdout or "").strip().replace("\n", " ")[-180:]
        suffix = f":{detail}" if detail else ""
        raise RuntimeError(f"ops-command-failed:{command}:{proc.returncode}{suffix}")
    return proc


def _domain(value: object) -> str:
    domain = str(value or "").strip().lower().rstrip(".")
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


def _global_addresses(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise RuntimeError("provider-dns-failed") from exc
    found: list[str] = []
    for info in infos:
        value = str(info[4][0])
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("provider-host-not-allowed")
        if not address.is_global or address.is_multicast or address.is_unspecified:
            raise ValueError("provider-host-not-allowed")
        if value not in found:
            found.append(value)
    if not found:
        raise RuntimeError("provider-dns-failed")
    return found[:8]


def _public_https(url: str, allow_host: str | None = None) -> tuple[urllib.parse.SplitResult, str]:
    parts = urllib.parse.urlsplit(str(url or "").strip())
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError("invalid-provider-endpoint")
    host = parts.hostname.rstrip(".").lower()
    if allow_host and host != allow_host:
        raise ValueError("provider-host-not-allowed")
    if host == "localhost" or host.endswith((".localhost", ".local")):
        raise ValueError("provider-host-not-allowed")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9.-]+", host):
            raise ValueError("provider-host-not-allowed")
    else:
        if not literal.is_global:
            raise ValueError("provider-host-not-allowed")
    port = int(parts.port or 443)
    addresses = _global_addresses(host, port) if not allow_host else _global_addresses(host, port)
    return parts, addresses[0]


def _secret(secret_id: str, kind: str) -> str:
    path = VAULT.credential_path(str(secret_id), str(kind))
    value = path.read_text(encoding="utf-8").strip()
    if not value or "\x00" in value or len(value) > 16384:
        raise ValueError("invalid-provider-secret")
    return value


def _http(url: str, method: str = "GET", headers: dict | None = None, body: dict | None = None, timeout: int = 20, allow_host: str | None = None) -> dict:
    parts, ip = _public_https(url, allow_host)
    host = parts.hostname.rstrip(".").lower()
    port = int(parts.port or 443)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    payload = b"" if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    final_headers = {"Accept": "application/json", "User-Agent": "Nexvary-Panel/0.7", "Connection": "close", **(headers or {})}
    if body is not None:
        final_headers.setdefault("Content-Type", "application/json")
        final_headers["Content-Length"] = str(len(payload))
    for key, value in final_headers.items():
        if any(c in str(key) + str(value) for c in "\r\n\x00"):
            raise ValueError("invalid-provider-header")
    raw = socket.create_connection((ip, port), timeout=timeout)
    tls: ssl.SSLSocket | None = None
    try:
        tls = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        host_header = host if port == 443 else f"{host}:{port}"
        request_lines = [f"{method} {path} HTTP/1.1", f"Host: {host_header}"]
        request_lines.extend(f"{key}: {value}" for key, value in final_headers.items())
        tls.sendall(("\r\n".join(request_lines) + "\r\n\r\n").encode("iso-8859-1") + payload)
        response = http.client.HTTPResponse(tls)
        response.begin()
        raw_body = response.read(MAX_HTTP_BODY + 1)
        if len(raw_body) > MAX_HTTP_BODY:
            raise RuntimeError("provider-response-too-large")
        if not 200 <= response.status < 300:
            raise RuntimeError(f"provider-http-{response.status}")
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise RuntimeError("provider-network-failed") from exc
    finally:
        try:
            if tls is not None:
                tls.close()
            else:
                raw.close()
        except OSError:
            pass
    if not raw_body:
        return {}
    try:
        parsed = json.loads(raw_body.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("provider-invalid-json") from exc
    return parsed if isinstance(parsed, dict) else {"data": parsed}


def _record(data: dict) -> dict:
    domain = _domain(data.get("domain"))
    record_type = str(data.get("record_type", "")).upper()
    name = str(data.get("record_name", "")).strip().rstrip(".").lower()
    value = str(data.get("record_value", "")).strip()
    if record_type not in RECORD_TYPES:
        raise ValueError("record-type-not-allowed")
    if name == "@":
        name = domain
    if name != domain and not (name.endswith("." + domain) and DOMAIN_RE.fullmatch(name)):
        raise ValueError("record-name-outside-zone")
    if not value or len(value) > 4096 or any(c in value for c in "\r\n\x00"):
        raise ValueError("invalid-record-value")
    if record_type == "A":
        try:
            if ipaddress.ip_address(value).version != 4:
                raise ValueError
        except ValueError as exc:
            raise ValueError("invalid-a-record") from exc
    elif record_type == "AAAA":
        try:
            if ipaddress.ip_address(value).version != 6:
                raise ValueError
        except ValueError as exc:
            raise ValueError("invalid-aaaa-record") from exc
    elif record_type in {"CNAME", "MX"}:
        value = value.rstrip(".").lower()
        if not DOMAIN_RE.fullmatch(value):
            raise ValueError("invalid-hostname-record")
    try:
        ttl = int(data.get("ttl", 300))
        priority = int(data.get("priority", 0))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid-record-options") from exc
    if not 60 <= ttl <= 86400 or not 0 <= priority <= 65535:
        raise ValueError("invalid-record-options")
    return {"domain": domain, "type": record_type, "name": name, "content": value, "ttl": ttl, "priority": priority}


def _cloudflare_target(endpoint: str) -> str:
    parts, _ = _public_https(endpoint, "api.cloudflare.com")
    if not re.fullmatch(r"/client/v4/zones/[A-Za-z0-9_-]{8,80}/?", parts.path):
        raise ValueError("cloudflare-endpoint-must-be-zone-url")
    return urllib.parse.urlunsplit(parts).rstrip("/")


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
        before: list[dict] = []
        if record_id:
            current = _http(f"{base}/dns_records/{urllib.parse.quote(record_id, safe='')}", headers=headers, allow_host="api.cloudflare.com")
            if current.get("success") and isinstance(current.get("result"), dict):
                before = [current["result"]]
        else:
            query = urllib.parse.urlencode({"type": record["type"], "name": record["name"]})
            current = _http(f"{base}/dns_records?{query}", headers=headers, allow_host="api.cloudflare.com")
            if current.get("success") and isinstance(current.get("result"), list):
                before = [x for x in current["result"][:20] if isinstance(x, dict)]
        payload = {"type": record["type"], "name": record["name"], "content": record["content"], "ttl": record["ttl"]}
        if record["type"] == "MX":
            payload["priority"] = record["priority"]
        if operation == "create":
            result = _http(f"{base}/dns_records", "POST", headers, payload, allow_host="api.cloudflare.com")
        elif operation == "update":
            if not record_id:
                raise ValueError("provider-record-id-required")
            result = _http(f"{base}/dns_records/{urllib.parse.quote(record_id, safe='')}", "PUT", headers, payload, allow_host="api.cloudflare.com")
        else:
            if not record_id:
                raise ValueError("provider-record-id-required")
            result = _http(f"{base}/dns_records/{urllib.parse.quote(record_id, safe='')}", "DELETE", headers, allow_host="api.cloudflare.com")
        if result.get("success") is not True:
            raise RuntimeError("dns-provider-rejected-change")
        created = (result.get("result") or {}).get("id", "") if isinstance(result.get("result"), dict) else ""
        return {"ok": True, "provider": provider, "provider_record_id": created or record_id, "snapshot": {"operation": operation, "records": before, "created_id": created if operation == "create" else ""}}
    if provider == "powerdns":
        endpoint = urllib.parse.urlunsplit(_public_https(str(data.get("endpoint", "")))[0])
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
        return {"ok": True, "provider": provider, "provider_record_id": "", "snapshot": {"operation": operation, "rrsets": before, "name": record["name"], "type": record["type"]}}
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
        operation = str(snapshot.get("operation", ""))
        restored = 0
        if created:
            _http(f"{base}/dns_records/{urllib.parse.quote(created, safe='')}", "DELETE", headers, allow_host="api.cloudflare.com")
        elif isinstance(records, list):
            for record in records[:20]:
                if not isinstance(record, dict):
                    continue
                payload = {k: record[k] for k in ("type", "name", "content", "ttl", "priority", "proxied") if k in record}
                if not payload.get("type") or not payload.get("name") or "content" not in payload:
                    continue
                if operation == "delete":
                    _http(f"{base}/dns_records", "POST", headers, payload, allow_host="api.cloudflare.com")
                elif record.get("id"):
                    _http(f"{base}/dns_records/{urllib.parse.quote(str(record['id']), safe='')}", "PUT", headers, payload, allow_host="api.cloudflare.com")
                restored += 1
        return {"ok": True, "restored": restored}
    if provider == "powerdns":
        endpoint = urllib.parse.urlunsplit(_public_https(str(data.get("endpoint", "")))[0])
        key = _secret(str(data.get("secret_id", "")), "powerdns")
        headers = {"X-API-Key": key, "Content-Type": "application/json"}
        rrsets = snapshot.get("rrsets", [])
        if not isinstance(rrsets, list):
            raise ValueError("invalid-dns-snapshot")
        restored = []
        for item in rrsets[:5]:
            if isinstance(item, dict) and item.get("name") and item.get("type"):
                restored.append({"name": item["name"], "type": item["type"], "ttl": int(item.get("ttl", 300)), "changetype": "REPLACE", "records": item.get("records", [])})
        if not restored:
            name = str(snapshot.get("name", "")).rstrip(".")
            rtype = str(snapshot.get("type", "")).upper()
            if name and rtype in RECORD_TYPES:
                restored.append({"name": name + ".", "type": rtype, "changetype": "DELETE"})
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
        subprocess.run(["nginx", "-t"], capture_output=True, text=True, env=BASE_ENV, check=False)
        subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True, env=BASE_ENV, check=False)
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
    versions: list[str] = []
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
        subprocess.run(["nginx", "-t"], capture_output=True, text=True, env=BASE_ENV, check=False)
        subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True, env=BASE_ENV, check=False)
        raise
    return {"ok": True, "domain": domain, "version": version}


def _pg(args: list[str], timeout: int = 30, stdin: str | None = None) -> subprocess.CompletedProcess:
    return _run(args, timeout, stdin, run_as="postgres")


def _pg_exists(kind: str, value: str) -> bool:
    if kind == "role":
        query = f"SELECT 1 FROM pg_roles WHERE rolname='{value}'"
    elif kind == "database":
        query = f"SELECT 1 FROM pg_database WHERE datname='{value}'"
    else:
        raise ValueError("invalid-postgres-object")
    return _pg(["psql", "-X", "-tAc", query, "-d", "postgres"], 15).stdout.strip() == "1"


def _postgres_create(data: dict) -> dict:
    name = _db(data.get("db_name"))
    user = _db(data.get("db_user"))
    password = str(data.get("password", ""))
    if not PASSWORD_RE.fullmatch(password):
        raise ValueError("invalid-database-password")
    required = ("psql", "createuser", "createdb", "dropuser", "dropdb")
    if any(not shutil.which(command) for command in required):
        return {"ok": False, "error": "postgresql-not-installed"}
    if _pg_exists("role", user) or _pg_exists("database", name):
        return {"ok": False, "error": "postgres-resource-conflict"}
    role_created = False
    db_created = False
    try:
        _pg(["createuser", "--no-password", "--login", "--", user], 30)
        role_created = True
        # PASSWORD_RE deliberately excludes quotes; password is sent only over stdin and never argv/journal.
        _pg(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", "postgres"], 30, f"ALTER ROLE \"{user}\" WITH LOGIN PASSWORD '{password}';\n")
        _pg(["createdb", "-O", user, "--", name], 30)
        db_created = True
    except Exception:
        if db_created:
            try:
                _pg(["dropdb", "--if-exists", "--", name], 20)
            except Exception:
                pass
        if role_created:
            try:
                _pg(["dropuser", "--if-exists", "--", user], 20)
            except Exception:
                pass
        raise
    return {"ok": True, "db_name": name, "db_user": user}


def _postgres_delete(data: dict) -> dict:
    name = _db(data.get("db_name"))
    user = _db(data.get("db_user"))
    if not shutil.which("dropdb") or not shutil.which("dropuser"):
        return {"ok": False, "error": "postgresql-not-installed"}
    _pg(["dropdb", "--if-exists", "--", name], 30)
    _pg(["dropuser", "--if-exists", "--", user], 30)
    return {"ok": True, "deleted": True}


def _assert_site_tree_safe(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("migration-site-symlink-not-supported")
        try:
            resolved = path.resolve()
        except OSError as exc:
            raise ValueError("unsafe-site-entry") from exc
        if os.path.commonpath((str(root), str(resolved))) != str(root):
            raise ValueError("unsafe-site-entry")


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    members = tar.getmembers()
    if len(members) > 250_000:
        raise ValueError("migration-archive-too-many-files")
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
            raise ValueError("unsafe-migration-archive")
        target = dest.joinpath(*[x for x in path.parts if x != "."])
        if os.path.commonpath((str(dest), str(target))) != str(dest):
            raise ValueError("unsafe-migration-archive")
    tar.extractall(dest, members=members, numeric_owner=True)


def _maria_db_exists(name: str) -> bool:
    query = f"SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME='{name}'"
    return _run(["mariadb", "-Nse", query], 15).stdout.strip() == name


def _maria_dump(name: str) -> str:
    return _run(["mariadb-dump", "--single-transaction", "--skip-lock-tables", "--routines", "--events", "--triggers", "--add-drop-table", "--", name], 180).stdout


def _migration_export(data: dict) -> dict:
    domain = _domain(data.get("domain"))
    root = _site_root(domain)
    _assert_site_tree_safe(root)
    raw_db = str(data.get("db_name", "")).strip()
    db_name = _db(raw_db) if raw_db else ""
    if db_name and not _maria_db_exists(db_name):
        raise ValueError("migration-database-not-found")
    MIGRATION_BASE.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(3)
    archive = MIGRATION_BASE / f"{domain}-{stamp}.tar.gz"
    tmp = Path(tempfile.mkdtemp(prefix="nvp-migrate-"))
    try:
        manifest = {"version": 1, "domain": domain, "database": db_name, "created_at": int(time.time())}
        (tmp / "manifest.json").write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
        if db_name:
            (tmp / "database.sql").write_text(_maria_dump(db_name), encoding="utf-8")
        with tarfile.open(archive, "w:gz") as out:
            out.dereference = True
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


def _restore_maria_snapshot(db_name: str, existed: bool, old_sql: str) -> None:
    _run(["mariadb", "-e", f"DROP DATABASE IF EXISTS `{db_name}`;"], 30)
    if existed:
        _run(["mariadb", "-e", f"CREATE DATABASE `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"], 30)
        _run(["mariadb", "--", db_name], 180, old_sql)


def _migration_restore(data: dict) -> dict:
    domain = _domain(data.get("domain"))
    root = _site_root(domain)
    archive = Path(str(data.get("archive", "")))
    raw_db = str(data.get("db_name", "")).strip()
    db_name = _db(raw_db) if raw_db else ""
    try:
        resolved = archive.resolve()
        if resolved.parent != MIGRATION_BASE.resolve() or not archive.is_file() or archive.is_symlink() or archive.suffix != ".gz":
            raise ValueError("migration-archive-outside-vault")
    except OSError as exc:
        raise ValueError("migration-archive-not-found") from exc
    work = Path(tempfile.mkdtemp(prefix=".nvp-restore-", dir=str(root.parent)))
    rollback = MIGRATION_BASE / f"{domain}-rollback-{int(time.time())}-{secrets.token_hex(3)}.tar.gz"
    old = root.with_name(root.name + f".migration-old-{secrets.token_hex(3)}")
    db_existed = False
    old_db_sql = ""
    swapped = False
    try:
        with tarfile.open(archive, "r:gz") as src:
            _safe_extract(src, work)
        site = work / "site"
        manifest_path = work / "manifest.json"
        if not site.is_dir() or site.is_symlink() or not manifest_path.is_file() or manifest_path.is_symlink():
            raise ValueError("migration-site-or-manifest-missing")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ValueError("invalid-migration-manifest") from exc
        if not isinstance(manifest, dict) or manifest.get("version") != 1 or str(manifest.get("domain", "")) != domain:
            raise ValueError("migration-manifest-mismatch")
        archive_db = str(manifest.get("database", "") or "")
        if archive_db and db_name and archive_db != db_name:
            raise ValueError("migration-database-mismatch")
        if db_name and (work / "database.sql").is_file():
            db_existed = _maria_db_exists(db_name)
            old_db_sql = _maria_dump(db_name) if db_existed else ""
        with tarfile.open(rollback, "w:gz") as out:
            out.dereference = True
            out.add(root, arcname="site", recursive=True)
            rollback_manifest = {"version": 1, "domain": domain, "database": db_name if db_existed else "", "created_at": int(time.time()), "rollback": True}
            info = tarfile.TarInfo("manifest.json")
            raw_manifest = json.dumps(rollback_manifest, separators=(",", ":")).encode("utf-8")
            info.size = len(raw_manifest); info.mode = 0o600; info.mtime = int(time.time())
            import io
            out.addfile(info, io.BytesIO(raw_manifest))
            if old_db_sql:
                sql_info = tarfile.TarInfo("database.sql")
                raw_sql = old_db_sql.encode("utf-8")
                sql_info.size = len(raw_sql); sql_info.mode = 0o600; sql_info.mtime = int(time.time())
                out.addfile(sql_info, io.BytesIO(raw_sql))
        os.chmod(rollback, 0o600)
        root.rename(old)
        site.rename(root)
        swapped = True
        if db_name and (work / "database.sql").is_file():
            if not _maria_db_exists(db_name):
                _run(["mariadb", "-e", f"CREATE DATABASE `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"], 30)
            _run(["mariadb", "--", db_name], 180, (work / "database.sql").read_text(encoding="utf-8"))
        shutil.rmtree(old, ignore_errors=True)
        return {"ok": True, "rollback": str(rollback)}
    except Exception:
        if swapped and old.exists():
            try:
                if root.exists():
                    shutil.rmtree(root, ignore_errors=True)
                old.rename(root)
            except OSError:
                pass
        if db_name and (db_existed or old_db_sql):
            try:
                _restore_maria_snapshot(db_name, db_existed, old_db_sql)
            except Exception:
                pass
        elif db_name:
            try:
                _restore_maria_snapshot(db_name, False, "")
            except Exception:
                pass
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _service_names() -> list[str]:
    names = ["nginx", "mariadb", "fail2ban", "postfix", "dovecot", "postgresql", "ssh"]
    names.extend(f"php{version}-fpm" for version in _php_versions())
    return names


def _service_status() -> dict:
    rows = []
    for name in _service_names():
        proc = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=5, env=BASE_ENV, check=False)
        rows.append({"name": name, "active": proc.stdout.strip() == "active"})
    return {"ok": True, "services": rows}


def _service_action(name: str, operation: str) -> dict:
    if name not in set(_service_names()) or operation not in {"reload", "restart"}:
        raise ValueError("service-action-not-allowed")
    _run(["systemctl", operation, name], 35)
    return {"ok": True, "name": name, "action": operation}


def _status() -> dict:
    pg = all(shutil.which(x) for x in ("psql", "createuser", "createdb", "dropuser", "dropdb"))
    return {"ok": True, "engine": "nexvary-hosting-ops", "capabilities": {
        "dns": True,
        "ssl": bool(shutil.which("certbot")),
        "mail_queue": bool(shutil.which("postqueue")),
        "php": bool(_php_versions()),
        "postgres": bool(pg),
        "migrations": bool(shutil.which("mariadb-dump") and shutil.which("mariadb")),
        "service_control": True,
    }}


def dispatch(data: dict) -> dict:
    action = str(data.get("action", ""))
    if action not in ACTIONS:
        return {"ok": False, "error": "ops-action-not-allowed"}
    if action == "status": return _status()
    if action == "dns-apply": return _dns_apply(data)
    if action == "dns-rollback": return _dns_rollback(data)
    if action == "ssl-status": return _ssl_status(str(data.get("domain", "")))
    if action == "ssl-issue": return _ssl_issue(data)
    if action == "ssl-renew": return _ssl_renew(str(data.get("domain", "")))
    if action == "mail-queue": return _mail_queue()
    if action == "mail-flush":
        if not shutil.which("postqueue"):
            return {"ok": False, "error": "postfix-not-installed"}
        _run(["postqueue", "-f"], 20); return {"ok": True}
    if action == "php-list": return {"ok": True, "versions": _php_versions()}
    if action == "php-set": return _php_set(str(data.get("domain", "")), str(data.get("version", "")))
    if action == "postgres-create": return _postgres_create(data)
    if action == "postgres-delete": return _postgres_delete(data)
    if action == "migration-export": return _migration_export(data)
    if action == "migration-restore": return _migration_restore(data)
    if action == "service-status": return _service_status()
    return _service_action(str(data.get("name", "")), str(data.get("operation", "")))


def main() -> None:
    SOCK.parent.mkdir(parents=True, exist_ok=True)
    if SOCK.exists() or SOCK.is_symlink():
        SOCK.unlink()
    old_umask = os.umask(0o117)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(SOCK))
    finally:
        os.umask(old_umask)
    os.chown(SOCK, 0, grp.getgrnam("nexvary-panel").gr_gid)
    os.chmod(SOCK, 0o660)
    server.listen(32)
    try:
        while True:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(250)
                try:
                    raw = b""
                    while not raw.endswith(b"\n") and len(raw) <= MAX_REQUEST:
                        chunk = conn.recv(8192)
                        if not chunk: break
                        raw += chunk
                    if not raw.endswith(b"\n") or len(raw) > MAX_REQUEST:
                        raise ValueError("request-too-large")
                    data = json.loads(raw.decode("utf-8"))
                    if not isinstance(data, dict):
                        raise ValueError("object-required")
                    result = dispatch(data)
                except ValueError as exc:
                    result = {"ok": False, "error": str(exc)[:160]}
                except Exception as exc:
                    error = str(exc)[:160] if str(exc) else "ops-operation-failed"
                    result = {"ok": False, "error": error}
                conn.sendall((json.dumps(result, separators=(",", ":")) + "\n").encode("utf-8"))
    finally:
        server.close()
        SOCK.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
