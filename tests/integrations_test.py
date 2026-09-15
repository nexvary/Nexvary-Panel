import hashlib
import importlib.util
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_tmp = tempfile.TemporaryDirectory()
tmp = _tmp.name
salt = "33" * 16
password = "Integration-Gate-Password-2026"
digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 310000).hex()
os.environ["NVP_DATA_DIR"] = tmp
os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
os.environ["NVP_ADMIN_SALT"] = salt
os.environ["NVP_ADMIN_HASH"] = digest
os.environ["NVP_SECRET"] = "integration-test-secret"
os.environ["NVP_COOKIE_SECURE"] = "0"
os.environ["NVP_AGENT_SOCK"] = str(pathlib.Path(tmp) / "missing-agent.sock")
os.environ["NVP_VAULT_SOCK"] = str(pathlib.Path(tmp) / "missing-vault.sock")

from panel.routes_integrations import TARGET_TYPES, _validate_endpoint, _valid_name

assert set(TARGET_TYPES) == {"restic", "rclone", "powerdns", "cloudflare"}
assert TARGET_TYPES["restic"]["secret_kind"] == "restic"
assert TARGET_TYPES["rclone"]["secret_kind"] == "rclone"
assert TARGET_TYPES["powerdns"]["secret_kind"] == "powerdns"
assert TARGET_TYPES["cloudflare"]["secret_kind"] == "cloudflare"
assert TARGET_TYPES["cloudflare"]["capability"] == "authoritative-dns"
assert _valid_name("Primary Backup") == "Primary Backup"

valid = [
    ("restic", "s3:https://storage.example.com/nexvary"),
    ("rclone", "remote:backups/nexvary"),
    ("powerdns", "https://dns.example.com/api/v1"),
    ("cloudflare", "https://api.cloudflare.com/client/v4/zones/abcdefgh"),
]
for provider, endpoint in valid:
    assert _validate_endpoint(provider, endpoint) == endpoint

invalid = [
    ("restic", "s3:http://storage.example.com/bucket"),
    ("restic", "s3:https://user:pass@storage.example.com/bucket"),
    ("restic", "file:/etc"),
    ("rclone", "../remote:backup"),
    ("rclone", "remote:"),
    ("powerdns", "http://dns.example.com/api/v1"),
    ("powerdns", "https://localhost/api/v1"),
    ("powerdns", "https://127.0.0.1/api/v1"),
    ("cloudflare", "https://api.cloudflare.com/client/v4/zones/short"),
    ("cloudflare", "https://example.com/client/v4/zones/abcdefgh"),
    ("cloudflare", "http://api.cloudflare.com/client/v4/zones/abcdefgh"),
]
for provider, endpoint in invalid:
    try:
        _validate_endpoint(provider, endpoint)
        raise AssertionError(f"unsafe target accepted: {provider} {endpoint}")
    except ValueError:
        pass

spec = importlib.util.spec_from_file_location("nvp_integration_app", ROOT / "app.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
app = mod.app
app.config.update(TESTING=True)
client = app.test_client()

client.get("/login")
with client.session_transaction() as sess:
    csrf = sess["csrf"]
r = client.post("/login", data={"csrf_token": csrf, "username": "admin", "password": password}, follow_redirects=False)
assert r.status_code == 302
with client.session_transaction() as sess:
    csrf = sess["csrf"]

r = client.get("/api/integrations/targets")
assert r.status_code == 200 and r.get_json()["targets"] == []
assert "cloudflare" in r.get_json()["types"]

payload = {"name": "Primary Backup", "provider": "restic", "endpoint": "s3:https://storage.example.com/nexvary", "secret_id": "prod-backup"}
r = client.post("/api/integrations/targets", json=payload, headers={"X-CSRF-Token": csrf})
assert r.status_code == 428
r = client.post("/api/integrations/targets/1/toggle", headers={"X-CSRF-Token": csrf})
assert r.status_code == 428
r = client.delete("/api/integrations/targets/1", headers={"X-CSRF-Token": csrf})
assert r.status_code == 428

# After Step-Up, missing Vault reference blocks creation rather than storing a dangling credential pointer.
r = client.post("/security/step-up", data={"csrf_token": csrf, "password": password}, follow_redirects=False)
assert r.status_code == 302
r = client.post("/api/integrations/targets", json=payload, headers={"X-CSRF-Token": csrf})
assert r.status_code == 503 and "Vault" in r.get_json().get("error", "")

_tmp.cleanup()
print("Nexvary Panel Integration Target contract/Step-Up tests: PASS")
