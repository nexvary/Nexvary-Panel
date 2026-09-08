import hashlib
import importlib.util
import os
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
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
    assert r.status_code == 200 and b"Nexvary Panel" in r.data
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
    for marker in [b"Docker Center", b"NEXVARY Doctor", b"id=\"sites\"", b"id=\"databases\""]:
        assert marker in r.data
    r = client.get("/api/metrics")
    assert r.status_code == 200 and {"cpu", "ram", "disk"}.issubset(r.get_json())
    r = client.post("/sites", data={"domain": "example.com", "kind": "static"})
    assert r.status_code == 403

print("Nexvary Panel smoke tests: PASS")
