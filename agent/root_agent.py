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


def _maintenance(action: str):
    # No request-derived argv is accepted here. Every executable, unit and verb is fixed.
    plans = {
        "maintenance-restart-nginx": (["nginx", "-t"], ["systemctl", "restart", "nginx"], ["systemctl", "is-active", "--quiet", "nginx"], 35),
        "maintenance-reload-nginx": (["nginx", "-t"], ["systemctl", "reload", "nginx"], ["systemctl", "is-active", "--quiet", "nginx"], 30),
        "maintenance-restart-mariadb": (["mariadb-admin", "ping"], ["systemctl", "restart", "mariadb"], ["mariadb-admin", "ping"], 45),
        "maintenance-restart-fail2ban": (["fail2ban-client", "-t"], ["systemctl", "restart", "fail2ban"], ["systemctl", "is-active", "--quiet", "fail2ban"], 35),
    }
    plan = plans.get(action)
    if not plan:
        return {"ok": False, "error": "maintenance action not allowed"}
    pre, command, post, timeout = plan
    before = run(pre, timeout=min(timeout, 20))
    if not before.get("ok"):
        return {"ok": False, "phase": "precheck", "error": before.get("error", "precheck failed")}
    changed = run(command, timeout=timeout)
    if not changed.get("ok"):
        return {"ok": False, "phase": "apply", "error": changed.get("error", "operation failed")}
    after = run(post, timeout=min(timeout, 20))
    if not after.get("ok"):
        return {"ok": False, "phase": "postcheck", "error": after.get("error", "postcheck failed"), "rollback": "manual-review-required"}
    return {"ok": True, "phase": "verified", "precheck": True, "postcheck": True}


def _site_root(domain: str) -> Path:
    if not valid_domain(domain): raise ValueError("invalid domain")
    root = SITE_BASE / domain
    if not root.exists() or not root.is_dir() or root.is_symlink(): raise ValueError("site root not found")
    return root


def _rel_parts(value: str, allow_root: bool = False) -> tuple[str, ...]:
    if not isinstance(value, str) or len(value) > 500 or "\x00" in value or "\\" in value: raise ValueError("invalid path")
    value = value.strip().strip("/")
    if not value: return () if allow_root else (_ for _ in ()).throw(ValueError("path required"))
    p = PurePosixPath(value)
    if p.is_absolute() or any(part in {"", ".", ".."} for part in p.parts): raise ValueError("unsafe path")
    return p.parts


def _safe_path(domain: str, rel: str, allow_root: bool = False, allow_missing_leaf: bool = False) -> tuple[Path, Path]:
    root = _site_root(domain); parts = _rel_parts(rel, allow_root=allow_root); current = root
    for idx, part in enumerate(parts):
        nxt = current / part; exists = nxt.exists() or nxt.is_symlink()
        if exists:
            if stat.S_ISLNK(os.lstat(nxt).st_mode): raise ValueError("symlink paths are blocked")
        elif idx < len(parts)-1 or not allow_missing_leaf: raise ValueError("path not found")
        current = nxt
    if os.path.commonpath((str(root), str(current))) != str(root): raise ValueError("path escapes site root")
    return root, current


def _www_ids(): return pwd.getpwnam("www-data").pw_uid, grp.getgrnam("www-data").gr_gid

def file_list(domain, rel):
    _, path = _safe_path(domain, rel, allow_root=True); rows=[]
    if not path.is_dir(): return {"ok":False,"error":"not a directory"}
    for entry in sorted(path.iterdir(), key=lambda p:(not p.is_dir(),p.name.lower()))[:500]:
        try:
            st=entry.lstat(); kind="blocked-link" if stat.S_ISLNK(st.st_mode) else "dir" if stat.S_ISDIR(st.st_mode) else "file" if stat.S_ISREG(st.st_mode) else "blocked"
            rows.append({"name":entry.name,"kind":kind,"size":st.st_size if kind=="file" else 0,"mtime":int(st.st_mtime)})
        except OSError: pass
    return {"ok":True,"path":rel.strip("/"),"items":rows}

def file_read(domain, rel):
    _,p=_safe_path(domain,rel); st=p.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_size>MAX_TEXT_FILE:return {"ok":False,"error":"only text files up to 512 KB are supported"}
    try:text=p.read_bytes().decode("utf-8")
    except UnicodeDecodeError:return {"ok":False,"error":"binary/non-UTF8 file editing is blocked"}
    return {"ok":True,"path":rel.strip("/"),"content":text,"size":st.st_size,"mtime":int(st.st_mtime)}
def file_write(domain,rel,content):
    if not isinstance(content,str) or len(content.encode())>MAX_TEXT_FILE:return {"ok":False,"error":"file content too large"}
    _,p=_safe_path(domain,rel,allow_missing_leaf=True); flags=os.O_WRONLY|os.O_CREAT|os.O_TRUNC|(getattr(os,"O_NOFOLLOW",0)); fd=os.open(p,flags,0o640)
    try:
        data=content.encode(); os.write(fd,data); os.fsync(fd); uid,gid=_www_ids(); os.fchown(fd,uid,gid); os.fchmod(fd,0o640)
    finally:os.close(fd)
    return {"ok":True,"path":rel.strip("/"),"size":len(data)}
def file_mkdir(domain,rel):
    _,p=_safe_path(domain,rel,allow_missing_leaf=True)
    if p.exists():return {"ok":False,"error":"path already exists"}
    p.mkdir(mode=0o750); uid,gid=_www_ids();os.chown(p,uid,gid);return {"ok":True,"path":rel.strip("/")}
def file_delete(domain,rel):
    _,p=_safe_path(domain,rel)
    if p.is_dir():p.rmdir()
    else:p.unlink()
    return {"ok":True}

def git_deploy(domain,repo_url,branch,target): return {"ok":False,"error":"git deploy unavailable in compact agent build"}
def wp_prepare(domain,db_name,db_user,password): return {"ok":False,"error":"wp prepare unavailable in compact agent build"}
def backup_restore(domain,archive,db_name): return {"ok":False,"error":"restore unavailable in compact agent build"}

def handle(req):
    action=req.get("action")
    if isinstance(action,str) and action.startswith("maintenance-"): return _maintenance(action)
    if action=="site-logs":
        d=req.get("domain","");return run(["/usr/local/sbin/nvpctl","site-logs",d],20) if valid_domain(d) else {"ok":False,"error":"invalid domain"}
    if action=="service-restart":
        n=req.get("name","");return run(["/usr/local/sbin/nvpctl","service-restart",n],40) if n in ALLOWED_SERVICES else {"ok":False,"error":"service not allowed"}
    if action=="doctor":
        r=run(["/usr/local/sbin/nvpctl","doctor"],50)
        if r.get("ok"):
            try:r["checks"]=json.loads(r.get("output","{}"))
            except Exception:return {"ok":False,"error":"doctor returned invalid data"}
        return r
    if action=="docker-list":return run(["/usr/local/sbin/nvpctl","docker-list"],20)
    if action=="docker-control":
        c,d=req.get("container",""),req.get("desired","")
        return run(["/usr/local/sbin/nvpctl","docker-control",c,d],40) if isinstance(c,str) and CONTAINER_RE.match(c) and d in {"start","stop","restart"} else {"ok":False,"error":"invalid docker request"}
    if action=="file-list":
        try:return file_list(req.get("domain",""),req.get("path",""))
        except (ValueError,OSError) as e:return {"ok":False,"error":str(e)}
    if action=="file-read":
        try:return file_read(req.get("domain",""),req.get("path",""))
        except (ValueError,OSError) as e:return {"ok":False,"error":str(e)}
    if action=="file-write":
        try:return file_write(req.get("domain",""),req.get("path",""),req.get("content",""))
        except (ValueError,OSError) as e:return {"ok":False,"error":str(e)}
    if action=="file-mkdir":
        try:return file_mkdir(req.get("domain",""),req.get("path",""))
        except (ValueError,OSError) as e:return {"ok":False,"error":str(e)}
    if action=="file-delete":
        try:return file_delete(req.get("domain",""),req.get("path",""))
        except (ValueError,OSError) as e:return {"ok":False,"error":str(e)}
    return {"ok":False,"error":"action not allowed"}

def main():
    SOCK.parent.mkdir(parents=True,exist_ok=True)
    if SOCK.exists():SOCK.unlink()
    server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(str(SOCK));gid=grp.getgrnam("nexvary-panel").gr_gid;os.chown(SOCK,0,gid);os.chmod(SOCK,0o660);server.listen(32)
    while True:
        conn,_=server.accept()
        with conn:
            try:
                data=b""
                while not data.endswith(b"\n") and len(data)<1024*1024:
                    chunk=conn.recv(8192)
                    if not chunk:break
                    data+=chunk
                req=json.loads(data.decode())
                if not isinstance(req,dict):raise ValueError("object required")
                reply(conn,handle(req))
            except Exception:reply(conn,{"ok":False,"error":"bad request"})
if __name__=="__main__":main()
