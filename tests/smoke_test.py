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

# Security primitives that do not need a running root agent.
from panel.security import _totp, verify_totp_secret
assert verify_totp_secret("JBSWY3DPEHPK3PXP", _totp("JBSWY3DPEHPK3PXP"))
assert not verify_totp_secret("JBSWY3DPEHPK3PXP", "000000") or _totp("JBSWY3DPEHPK3PXP") == "000000"

agent_spec = importlib.util.spec_from_file_location("nvp_root_agent", ROOT / "agent" / "root_agent.py")
agent_mod = importlib.util.module_from_spec(agent_spec)
agent_spec.loader.exec_module(agent_mod)
for bad in ["../etc/passwd", "/etc/passwd", "public/../../etc", "public\\secret"]:
    try:
        agent_mod._rel_parts(bad)
        raise AssertionError(f"unsafe path accepted: {bad}")
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

with tempfile.TemporaryDirectory() as tmp:
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
    for marker in [b"Docker Center", b"NEXVARY Doctor", b'id="sites"', b'id="databases"', b'id="files"', b'id="deploy"', b'id="wordpress"', b'id="notifications"', b"nexvary-panel-primary.jpg"]:
        assert marker in r.data, marker
    r = client.get("/api/metrics")
    assert r.status_code == 200 and {"cpu", "ram", "disk"}.issubset(r.get_json())
    # CSRF remains enforced on legacy forms and new JSON APIs.
    r = client.post("/sites", data={"domain": "example.com", "kind": "static"})
    assert r.status_code == 403
    r = client.post("/api/file/save", json={"domain": "example.com", "path": "public/a.txt", "content": "x"})
    assert r.status_code == 403
    # Enrollment creates a pending secret but does not enable 2FA until a valid TOTP is supplied.
    with client.session_transaction() as sess:
        csrf = sess["csrf"]
    r = client.post("/2fa/start", data={"csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 302
    with client.session_transaction() as sess:
        pending = sess.get("totp_pending")
        csrf = sess["csrf"]
    assert pending and len(pending) >= 16
    code = _totp(pending)
    r = client.post("/2fa/enable", data={"csrf_token": csrf, "otp": code}, follow_redirects=False)
    assert r.status_code == 302
    from panel.security import totp_enabled_for
    assert totp_enabled_for("admin")

print("Nexvary Panel platform/security smoke tests: PASS")
