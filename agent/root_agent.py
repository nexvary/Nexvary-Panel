#!/usr/bin/env python3
from __future__ import annotations

import grp
import json
import os
import pwd
import re
import shutil
import socket
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path, PurePosixPath

SOCK = Path(os.environ.get("NVP_AGENT_SOCK", "/run/nexvary-panel/agent.sock"))
SITE_BASE = Path("/var/www")
BACKUP_BASE = Path("/var/backups/nexvary-panel")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
TARGET_RE = re.compile(r"^https?://[A-Za-z0-9.\-:\[\]]+(?:/.*)?$")
DB_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9_@%+=:.,!$#?-]{14,128}$")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
GIT_URL_RE = re.compile(r"^https://(?:github\.com|gitlab\.com|bitbucket\.org)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,120}$")
ALLOWED_SERVICES = {"nginx", "mariadb", "fail2ban", "docker"}
MAX_TEXT_FILE = 512 * 1024
MAX_WP_ARCHIVE = 48 * 1024 * 1024


def reply(conn, obj):
    conn.sendall((json.dumps(obj, separators=(",", ":")) + "\n").encode())


def valid_domain(value):
    return isinstance(value, str) and bool(DOMAIN_RE.match(value))


def run(args, timeout=120, stdin=None):
    proc = subprocess.run(args, capture_output=True, text=True, input=stdin, timeout=timeout,
        env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": "/root", "GIT_CONFIG_NOSYSTEM": "1"})
    if proc.returncode:
        return {"ok": False, "error": (proc.stderr or proc.stdout or "operation failed")[-4000:]}
    return {"ok": True, "output": (proc.stdout or "")[-12000:]}


def _site_root(domain: str) -> Path:
    if not valid_domain(domain):
        raise ValueError("invalid domain")
    root = SITE_BASE / domain
    if not root.exists() or not root.is_dir() or root.is_symlink():
        raise ValueError("site root not found")
    return root


def _rel_parts(value: str, allow_root: bool = False) -> tuple[str, ...]:
    if not isinstance(value, str) or len(value) > 500 or "\x00" in value or "\\" in value:
        raise ValueError("invalid path")
    value = value.strip().strip("/")
    if not value:
        return () if allow_root else (_ for _ in ()).throw(ValueError("path required"))
    p = PurePosixPath(value)
    if p.is_absolute() or any(part in {"", ".", ".."} for part in p.parts):
        raise ValueError("unsafe path")
    return p.parts


def _safe_path(domain: str, rel: str, allow_root: bool = False, allow_missing_leaf: bool = False) -> tuple[Path, Path]:
    root = _site_root(domain)
    parts = _rel_parts(rel, allow_root=allow_root)
    current = root
    for idx, part in enumerate(parts):
        nxt = current / part
        exists = nxt.exists() or nxt.is_symlink()
        if exists:
            st = os.lstat(nxt)
            if stat.S_ISLNK(st.st_mode):
                raise ValueError("symlink paths are blocked")
        elif idx < len(parts) - 1 or not allow_missing_leaf:
            raise ValueError("path not found")
        current = nxt
    try:
        if os.path.commonpath((str(root), str(current))) != str(root):
            raise ValueError("path escapes site root")
    except ValueError:
        raise ValueError("path escapes site root")
    return root, current


def _www_ids() -> tuple[int, int]:
    return pwd.getpwnam("www-data").pw_uid, grp.getgrnam("www-data").gr_gid


def _chown_tree(path: Path) -> None:
    uid, gid = _www_ids()
    for base, dirs, files in os.walk(path, followlinks=False):
        os.chown(base, uid, gid)
        for name in dirs + files:
            p = Path(base) / name
            if not p.is_symlink():
                os.chown(p, uid, gid)


def file_list(domain: str, rel: str):
    _, path = _safe_path(domain, rel, allow_root=True)
    if not path.is_dir():
        return {"ok": False, "error": "not a directory"}
    rows = []
    for entry in sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))[:500]:
        try:
            st = entry.lstat()
            if stat.S_ISLNK(st.st_mode):
                kind = "blocked-link"
                size = 0
            elif stat.S_ISDIR(st.st_mode):
                kind = "dir"
                size = 0
            elif stat.S_ISREG(st.st_mode):
                kind = "file"
                size = st.st_size
            else:
                kind = "blocked"
                size = 0
            rows.append({"name": entry.name, "kind": kind, "size": size, "mtime": int(st.st_mtime)})
        except OSError:
            continue
    return {"ok": True, "path": rel.strip("/"), "items": rows}


def file_read(domain: str, rel: str):
    _, path = _safe_path(domain, rel)
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_TEXT_FILE:
        return {"ok": False, "error": "only text files up to 512 KB are supported"}
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {"ok": False, "error": "binary/non-UTF8 file editing is blocked"}
    return {"ok": True, "path": rel.strip("/"), "content": text, "size": len(raw), "mtime": int(st.st_mtime)}


def file_write(domain: str, rel: str, content: str):
    if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_TEXT_FILE:
        return {"ok": False, "error": "file content too large"}
    _, path = _safe_path(domain, rel, allow_missing_leaf=True)
    if path.exists() and not path.is_file():
        return {"ok": False, "error": "target is not a regular file"}
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o640)
    try:
        data = content.encode("utf-8")
        with os.fdopen(fd, "wb", closefd=False) as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        uid, gid = _www_ids()
        os.fchown(fd, uid, gid)
        os.fchmod(fd, 0o640)
    finally:
        os.close(fd)
    return {"ok": True, "path": rel.strip("/"), "size": len(data)}


def file_mkdir(domain: str, rel: str):
    _, path = _safe_path(domain, rel, allow_missing_leaf=True)
    if path.exists():
        return {"ok": False, "error": "path already exists"}
    path.mkdir(mode=0o750)
    uid, gid = _www_ids()
    os.chown(path, uid, gid)
    return {"ok": True, "path": rel.strip("/")}


def file_delete(domain: str, rel: str):
    root, path = _safe_path(domain, rel)
    if path == root:
        return {"ok": False, "error": "site root cannot be deleted"}
    if path.is_file():
        path.unlink()
    elif path.is_dir():
        try:
            path.rmdir()
        except OSError:
            return {"ok": False, "error": "directory must be empty"}
    else:
        return {"ok": False, "error": "unsupported file type"}
    return {"ok": True, "path": rel.strip("/")}


def git_deploy(domain: str, repo_url: str, branch: str, target: str):
    if not valid_domain(domain) or not isinstance(repo_url, str) or not GIT_URL_RE.match(repo_url):
        return {"ok": False, "error": "repository URL is not allowed"}
    if not isinstance(branch, str) or not BRANCH_RE.match(branch) or branch.startswith("-") or ".." in branch or "@{" in branch:
        return {"ok": False, "error": "invalid branch"}
    if target not in {"public", "app"}:
        return {"ok": False, "error": "invalid deploy target"}
    _, dest = _safe_path(domain, target)
    if not dest.is_dir():
        return {"ok": False, "error": "deploy target is not a directory"}
    tmp = Path(tempfile.mkdtemp(prefix="nvp-git-"))
    try:
        result = run(["git", "-c", "core.hooksPath=/dev/null", "clone", "--depth", "1", "--single-branch", "--branch", branch, "--", repo_url, str(tmp / "repo")], timeout=160)
        if not result.get("ok"):
            return result
        repo = tmp / "repo"
        rev = run(["git", "-C", str(repo), "rev-parse", "HEAD"], timeout=15)
        shutil.rmtree(repo / ".git", ignore_errors=True)
        sync = run(["rsync", "-a", "--delete", "--exclude=.env", "--exclude=wp-config.php", "--exclude=.well-known/", str(repo) + "/", str(dest) + "/"], timeout=80)
        if not sync.get("ok"):
            return sync
        _chown_tree(dest)
        unit = "nvp-" + domain.replace(".", "-") + ".service"
        subprocess.run(["systemctl", "try-restart", unit], capture_output=True, timeout=25)
        return {"ok": True, "output": f"deployed {repo_url}#{branch} to {domain}/{target} at {(rev.get('output') or '').strip()[:40]}"}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    for member in tar.getmembers():
        p = PurePosixPath(member.name)
        if p.is_absolute() or ".." in p.parts or member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
            raise ValueError("unsafe backup archive member")
        resolved = dest.joinpath(*[x for x in p.parts if x not in {"."}])
        if os.path.commonpath((str(dest), str(resolved))) != str(dest):
            raise ValueError("backup member escapes extraction root")
    tar.extractall(dest)


def backup_restore(domain: str, archive: str, db_name: str = ""):
    if not valid_domain(domain) or (db_name and (not isinstance(db_name, str) or not DB_RE.match(db_name))):
        return {"ok": False, "error": "invalid restore request"}
    base = BACKUP_BASE / domain
    archive_path = Path(archive)
    try:
        if archive_path.resolve().parent != base.resolve() or not archive_path.name.endswith(".tar.gz") or not archive_path.is_file():
            return {"ok": False, "error": "backup archive is outside the allowed vault"}
    except OSError:
        return {"ok": False, "error": "backup archive not found"}
    root = _site_root(domain)
    tmp = Path(tempfile.mkdtemp(prefix="nvp-restore-"))
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    rollback = base / f"{domain}-pre-restore-{stamp}.tar.gz"
    try:
        with tarfile.open(rollback, "w:gz") as out:
            out.add(root, arcname="site", recursive=True)
        os.chmod(rollback, 0o600)
        with tarfile.open(archive_path, "r:gz") as src:
            _safe_extract(src, tmp)
        restored = tmp / "site"
        if not restored.is_dir():
            return {"ok": False, "error": "backup does not contain a site directory"}
        shutil.rmtree(root)
        shutil.copytree(restored, root)
        _chown_tree(root)
        nginx_src = tmp / "nginx.conf"
        nginx_dst = Path(f"/etc/nginx/sites-available/{domain}.conf")
        old_nginx = nginx_dst.read_bytes() if nginx_dst.exists() else None
        if nginx_src.is_file():
            shutil.copy2(nginx_src, nginx_dst)
            test = run(["nginx", "-t"], timeout=20)
            if not test.get("ok"):
                if old_nginx is None:
                    nginx_dst.unlink(missing_ok=True)
                else:
                    nginx_dst.write_bytes(old_nginx)
                run(["nginx", "-t"], timeout=20)
                return {"ok": False, "error": "restored NGINX configuration failed validation; previous config restored"}
            run(["systemctl", "reload", "nginx"], timeout=25)
        sql = tmp / "database.sql"
        if db_name and sql.is_file():
            with sql.open("rb") as fh:
                proc = subprocess.run(["mariadb", db_name], stdin=fh, capture_output=True, timeout=120,
                                      env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
            if proc.returncode:
                return {"ok": False, "error": "site files restored but database import failed; safety snapshot retained"}
        return {"ok": True, "meta": {"rollback_archive": str(rollback), "database": db_name}}
    except (tarfile.TarError, ValueError, OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "error": f"restore failed: {exc}"}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _php_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def wp_prepare(domain: str, db_name: str, db_user: str, password: str):
    if not valid_domain(domain) or not DB_RE.match(db_name or "") or not DB_RE.match(db_user or "") or not PASSWORD_RE.match(password or ""):
        return {"ok": False, "error": "invalid WordPress request"}
    _, root = _safe_path(domain, "public")
    allowed_existing = {"index.php", "index.html", ".well-known"}
    existing = {p.name for p in root.iterdir()}
    if existing - allowed_existing or (root / "wp-config.php").exists():
        return {"ok": False, "error": "public directory is not clean enough for WordPress provisioning"}
    tmp = Path(tempfile.mkdtemp(prefix="nvp-wp-"))
    archive = tmp / "wordpress.tar.gz"
    try:
        req = urllib.request.Request("https://wordpress.org/latest.tar.gz", headers={"User-Agent": "Nexvary-Panel/0.5"})
        with urllib.request.urlopen(req, timeout=45) as resp:
            length = int(resp.headers.get("Content-Length") or 0)
            if length and length > MAX_WP_ARCHIVE:
                return {"ok": False, "error": "WordPress archive is unexpectedly large"}
            total = 0
            with archive.open("wb") as out:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_WP_ARCHIVE:
                        return {"ok": False, "error": "WordPress archive exceeded size limit"}
                    out.write(chunk)
        extract = tmp / "extract"
        extract.mkdir()
        with tarfile.open(archive, "r:gz") as tar:
            _safe_extract(tar, extract)
        src = extract / "wordpress"
        if not (src / "wp-includes" / "version.php").is_file():
            return {"ok": False, "error": "official WordPress package layout was not recognized"}
        shutil.copytree(src, root, dirs_exist_ok=True)
        version_text = (root / "wp-includes" / "version.php").read_text(errors="ignore")
        m = re.search(r"\$wp_version\s*=\s*'([^']+)'", version_text)
        version = m.group(1) if m else ""
        salts = {name: __import__("secrets").token_urlsafe(48) for name in ["AUTH_KEY","SECURE_AUTH_KEY","LOGGED_IN_KEY","NONCE_KEY","AUTH_SALT","SECURE_AUTH_SALT","LOGGED_IN_SALT","NONCE_SALT"]}
        config = "<?php\n"
        config += f"define('DB_NAME', '{_php_quote(db_name)}');\n"
        config += f"define('DB_USER', '{_php_quote(db_user)}');\n"
        config += f"define('DB_PASSWORD', '{_php_quote(password)}');\n"
        config += "define('DB_HOST', 'localhost');\ndefine('DB_CHARSET', 'utf8mb4');\ndefine('DB_COLLATE', '');\n"
        for key, value in salts.items():
            config += f"define('{key}', '{_php_quote(value)}');\n"
        config += "$table_prefix = 'wp_';\ndefine('DISALLOW_FILE_EDIT', true);\ndefine('WP_AUTO_UPDATE_CORE', 'minor');\n"
        config += "if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');\nrequire_once ABSPATH . 'wp-settings.php';\n"
        (root / "wp-config.php").write_text(config, encoding="utf-8")
        _chown_tree(root)
        os.chmod(root / "wp-config.php", 0o640)
        return {"ok": True, "meta": {"version": version, "status": "prepared"}, "output": f"WordPress {version or 'core'} prepared for {domain}"}
    except Exception as exc:
        return {"ok": False, "error": f"WordPress provisioning failed: {exc}"}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def handle(req):
    action = req.get("action")
    if action == "site-create":
        domain, kind, target, port = req.get("domain", ""), req.get("kind", ""), req.get("target", ""), req.get("app_port")
        if not valid_domain(domain) or kind not in {"static", "php", "node", "python", "reverse"}:
            return {"ok": False, "error": "invalid arguments"}
        args = ["/usr/local/sbin/nvpctl", "site-create", domain, kind]
        if kind == "reverse":
            if not isinstance(target, str) or not TARGET_RE.match(target):
                return {"ok": False, "error": "invalid reverse target"}
            args.append(target)
        elif kind in {"node", "python"}:
            if not isinstance(port, int) or not 1024 <= port <= 65535:
                return {"ok": False, "error": "invalid application port"}
            args.append(str(port))
        return run(args, timeout=45)
    if action == "site-toggle":
        domain, desired = req.get("domain", ""), req.get("desired", "")
        if not valid_domain(domain) or desired not in {"enable", "disable"}:
            return {"ok": False, "error": "invalid arguments"}
        return run(["/usr/local/sbin/nvpctl", "site-toggle", domain, desired], timeout=25)
    if action == "ssl":
        domain, email = req.get("domain", ""), req.get("email", "")
        if not valid_domain(domain) or not isinstance(email, str) or not EMAIL_RE.match(email):
            return {"ok": False, "error": "invalid arguments"}
        return run(["/usr/local/sbin/nvpctl", "ssl", domain, email], timeout=140)
    if action == "db-create":
        db_name, db_user, password = req.get("db_name", ""), req.get("db_user", ""), req.get("password", "")
        if not isinstance(db_name, str) or not DB_RE.match(db_name) or not isinstance(db_user, str) or not DB_RE.match(db_user):
            return {"ok": False, "error": "invalid database identifiers"}
        if not isinstance(password, str) or not PASSWORD_RE.match(password):
            return {"ok": False, "error": "invalid database password"}
        return run(["/usr/local/sbin/nvpctl", "db-create", db_name, db_user], timeout=30, stdin=password + "\n")
    if action == "backup-site":
        domain, db_name = req.get("domain", ""), req.get("db_name", "")
        if not valid_domain(domain) or (db_name and (not isinstance(db_name, str) or not DB_RE.match(db_name))):
            return {"ok": False, "error": "invalid backup request"}
        args = ["/usr/local/sbin/nvpctl", "backup-site", domain] + ([db_name] if db_name else [])
        result = run(args, timeout=130)
        if result.get("ok"):
            try:
                result["meta"] = json.loads(result.get("output", "{}").strip().splitlines()[-1])
            except Exception:
                pass
        return result
    if action == "backup-restore":
        return backup_restore(req.get("domain", ""), req.get("archive", ""), req.get("db_name", ""))
    if action == "file-list":
        try:
            return file_list(req.get("domain", ""), req.get("path", ""))
        except (ValueError, OSError) as exc:
            return {"ok": False, "error": str(exc)}
    if action == "file-read":
        try:
            return file_read(req.get("domain", ""), req.get("path", ""))
        except (ValueError, OSError) as exc:
            return {"ok": False, "error": str(exc)}
    if action == "file-write":
        try:
            return file_write(req.get("domain", ""), req.get("path", ""), req.get("content", ""))
        except (ValueError, OSError) as exc:
            return {"ok": False, "error": str(exc)}
    if action == "file-mkdir":
        try:
            return file_mkdir(req.get("domain", ""), req.get("path", ""))
        except (ValueError, OSError) as exc:
            return {"ok": False, "error": str(exc)}
    if action == "file-delete":
        try:
            return file_delete(req.get("domain", ""), req.get("path", ""))
        except (ValueError, OSError) as exc:
            return {"ok": False, "error": str(exc)}
    if action == "git-deploy":
        return git_deploy(req.get("domain", ""), req.get("repo_url", ""), req.get("branch", ""), req.get("target", ""))
    if action == "wp-prepare":
        return wp_prepare(req.get("domain", ""), req.get("db_name", ""), req.get("db_user", ""), req.get("password", ""))
    if action == "site-logs":
        domain = req.get("domain", "")
        return run(["/usr/local/sbin/nvpctl", "site-logs", domain], timeout=20) if valid_domain(domain) else {"ok": False, "error": "invalid domain"}
    if action == "service-restart":
        name = req.get("name", "")
        return run(["/usr/local/sbin/nvpctl", "service-restart", name], timeout=40) if name in ALLOWED_SERVICES else {"ok": False, "error": "service not allowed"}
    if action == "doctor":
        result = run(["/usr/local/sbin/nvpctl", "doctor"], timeout=50)
        if result.get("ok"):
            try:
                result["checks"] = json.loads(result.get("output", "{}"))
            except Exception:
                return {"ok": False, "error": "doctor returned invalid data"}
        return result
    if action == "docker-list":
        result = run(["/usr/local/sbin/nvpctl", "docker-list"], timeout=20)
        if result.get("ok"):
            rows = []
            for line in result.get("output", "").splitlines():
                parts = line.split("\t", 4)
                if len(parts) == 5:
                    rows.append(dict(id=parts[0], name=parts[1], image=parts[2], status=parts[3], ports=parts[4]))
            result["containers"] = rows
        return result
    if action == "docker-control":
        container, desired = req.get("container", ""), req.get("desired", "")
        if not isinstance(container, str) or not CONTAINER_RE.match(container) or desired not in {"start", "stop", "restart"}:
            return {"ok": False, "error": "invalid docker request"}
        return run(["/usr/local/sbin/nvpctl", "docker-control", container, desired], timeout=40)
    return {"ok": False, "error": "action not allowed"}


def main():
    SOCK.parent.mkdir(parents=True, exist_ok=True)
    if SOCK.exists():
        SOCK.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(SOCK))
    gid = grp.getgrnam("nexvary-panel").gr_gid
    os.chown(SOCK, 0, gid)
    os.chmod(SOCK, 0o660)
    server.listen(32)
    while True:
        conn, _ = server.accept()
        with conn:
            try:
                data = b""
                while not data.endswith(b"\n") and len(data) < 1024 * 1024:
                    chunk = conn.recv(8192)
                    if not chunk:
                        break
                    data += chunk
                req = json.loads(data.decode())
                if not isinstance(req, dict):
                    raise ValueError("object required")
                reply(conn, handle(req))
            except Exception:
                reply(conn, {"ok": False, "error": "bad request"})

if __name__ == "__main__":
    main()
