import hashlib
import importlib.util
import io
import os
import pathlib
import sys
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_tmp_ctx = tempfile.TemporaryDirectory()
tmp = _tmp_ctx.name
salt = "11" * 16
password = "Correct-Horse-Panel-2026"
digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 310000).hex()
os.environ["NVP_DATA_DIR"] = tmp
os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
os.environ["NVP_ADMIN_SALT"] = salt
os.environ["NVP_ADMIN_HASH"] = digest
os.environ["NVP_SECRET"] = "test-secret-only"
os.environ["NVP_AGENT_SOCK"] = str(pathlib.Path(tmp) / "missing.sock")
os.environ["NVP_COOKIE_SECURE"] = "0"

from panel.db_layer import db
from panel.providers import REGISTRY, SAFE_ID_RE, provider_snapshot
from panel.routes_health import _is_public_ip, _parse_http_head
from panel.routes_platform import _safe_rel_request
from panel.security import _totp, totp_enabled_for, verify_totp_secret

assert verify_totp_secret("JBSWY3DPEHPK3PXP", _totp("JBSWY3DPEHPK3PXP"))
assert not verify_totp_secret("JBSWY3DPEHPK3PXP", "000000") or _totp("JBSWY3DPEHPK3PXP") == "000000"

# Fusion Provider Framework: declarative, fixed argv, no shell/user-command input.
assert len(REGISTRY) >= 10
assert {"caddy", "traefik", "crowdsec", "restic", "rclone", "docker", "podman", "powerdns"}.issubset({p.provider_id for p in REGISTRY})
for provider in REGISTRY:
    assert SAFE_ID_RE.match(provider.provider_id)
    assert provider.binary and "/" not in provider.binary and "\\" not in provider.binary
    assert all(isinstance(x, str) and x and "\x00" not in x for x in provider.version_args)
snap = provider_snapshot()
assert snap["summary"]["registered"] == len(REGISTRY)
assert snap["policy"]["shell"] is False
assert snap["policy"]["automatic_install"] is False
assert snap["policy"]["privileged_actions"] == "root-agent-allowlist-only"

for blocked_ip in ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.1.1", "::1", "fc00::1", "fe80::1"]:
    assert not _is_public_ip(blocked_ip), f"private/reserved IP accepted: {blocked_ip}"
assert _is_public_ip("8.8.8.8")
assert _is_public_ip("2606:4700:4700::1111")
head = _parse_http_head(b"HTTP/1.1 301 Moved Permanently\r\nServer: nginx\r\nStrict-Transport-Security: max-age=31536000\r\nLocation: https://www.example.com/\r\nContent-Type: text/html\r\n\r\n")
assert head["status"] == 301 and head["hsts"] is True and head["server"] == "nginx" and head["location"].startswith("https://")
assert b"health-btn" in (ROOT / "templates" / "sections" / "sites.html").read_bytes()

for bad in ["../etc/passwd", "/etc/passwd", "public/../../etc", "public\\secret", "./public", "public//x"]:
    assert not _safe_rel_request(bad), f"unsafe request path accepted: {bad}"
assert _safe_rel_request("public/index.php")
assert _safe_rel_request("", allow_root=True)

agent_spec = importlib.util.spec_from_file_location("nvp_root_agent", ROOT / "agent" / "root_agent.py")
agent_mod = importlib.util.module_from_spec(agent_spec)
agent_spec.loader.exec_module(agent_mod)
for bad in ["../etc/passwd", "public/../../etc", "public\\secret"]:
    try:
        agent_mod._rel_parts(bad)
        raise AssertionError(f"unsafe agent path accepted: {bad}")
    except ValueError:
        pass
assert agent_mod.GIT_URL_RE.match("https://github.com/example/project.git")
assert not agent_mod.GIT_URL_RE.match("http://github.com/example/project.git")
assert not agent_mod.GIT_URL_RE.match("https://evil.example/project/repo.git")
with tempfile.TemporaryDirectory() as extract_tmp:
    malicious = io.BytesIO()
    with tarfile.open(fileobj=malicious, mode="w:gz") as tf:
        info = tarfile.TarInfo("../../escape.txt")
        body = b"blocked"
        info.size = len(body)
        tf.addfile(info, io.BytesIO(body))
    malicious.seek(0)
    with tarfile.open(fileobj=malicious, mode="r:gz") as tf:
        try:
            agent_mod._safe_extract(tf, pathlib.Path(extract_tmp))
            raise AssertionError("unsafe archive traversal was accepted")
        except ValueError:
            pass

spec = importlib.util.spec_from_file_location("nvp_app", ROOT / "app.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
app = mod.app
app.config.update(TESTING=True)
client = app.test_client()

r = client.get("/")
assert r.status_code == 302 and "/login" in r.location
r = client.get("/login")
assert r.status_code == 200 and b"Nexvary Panel" in r.data and b"nexvary-panel-primary.jpg" in r.data
with client.session_transaction() as sess:
    csrf = sess["csrf"]
r = client.post("/login", data={"csrf_token": csrf, "username": "admin", "password": "wrong"})
assert r.status_code == 200
r = client.get("/login")
with client.session_transaction() as sess:
    csrf = sess["csrf"]
r = client.post("/login", data={"csrf_token": csrf, "username": "admin", "password": password}, follow_redirects=False)
assert r.status_code == 302 and r.location.endswith("/")
r = client.get("/")
assert r.status_code == 200
for marker in [b"Docker Center", b"NEXVARY Doctor", b'id="sites"', b'id="databases"', b'id="files"', b'id="deploy"', b'id="wordpress"', b'id="notifications"', b'id="fusion"', b'Fusion Center', b'id="fileNewFile"', b'id="healthDialog"', b'notification-filter', b'platform-controls.css', b'platform-controls.js', b'fusion.css', b'fusion.js', b"nexvary-panel-primary.jpg"]:
    assert marker in r.data, marker
r = client.get("/api/metrics")
assert r.status_code == 200 and {"cpu", "ram", "disk"}.issubset(r.get_json())
r = client.get("/api/fusion/providers")
assert r.status_code == 200 and r.get_json().get("ok") is True and len(r.get_json().get("providers", [])) == len(REGISTRY)
r = client.get("/api/fusion/policy")
assert r.status_code == 200 and r.get_json()["policy"]["shell"] is False
r = client.get("/api/site-health?domain=example.com")
assert r.status_code == 403 and r.get_json().get("ok") is False
r = client.post("/sites", data={"domain": "example.com", "kind": "static"})
assert r.status_code == 403
r = client.post("/api/file/save", json={"domain": "example.com", "path": "public/a.txt", "content": "x"})
assert r.status_code == 403
with client.session_transaction() as sess:
    csrf = sess["csrf"]
r = client.post("/2fa/start", data={"csrf_token": csrf}, follow_redirects=False)
assert r.status_code == 302
with client.session_transaction() as sess:
    assert "totp_pending" not in sess
    csrf = sess["csrf"]
with db() as conn:
    sec = conn.execute("SELECT totp_secret,totp_enabled FROM user_security WHERE username='admin'").fetchone()
assert sec and not sec["totp_enabled"] and len(sec["totp_secret"]) >= 16
code = _totp(sec["totp_secret"])
r = client.post("/2fa/enable", data={"csrf_token": csrf, "otp": code}, follow_redirects=False)
assert r.status_code == 302
assert totp_enabled_for("admin")

_tmp_ctx.cleanup()
print("Nexvary Panel platform/security/health/fusion smoke tests: PASS")
