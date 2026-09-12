import hashlib
import importlib.util
import json
import os
import pathlib
import stat
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Test the root-side vault store directly in an isolated directory.
spec = importlib.util.spec_from_file_location("nvp_secret_vault", ROOT / "agent" / "secret_vault.py")
vault_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vault_mod)

with tempfile.TemporaryDirectory() as vault_tmp:
    base = pathlib.Path(vault_tmp) / "credentials"
    vault = vault_mod.SecretVault(base)
    vault.ensure()
    assert stat.S_IMODE(base.stat().st_mode) == 0o700

    marker = "NVP-SECRET-DO-NOT-LEAK-1234567890"
    meta = vault.put("prod-backup", "restic", marker)
    assert meta["id"] == "prod-backup" and meta["kind"] == "restic"
    secret_path = vault.credential_path("prod-backup", "restic")
    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600
    assert secret_path.read_text() == marker
    rows = vault.list_metadata()
    encoded = json.dumps(rows, sort_keys=True)
    assert marker not in encoded and str(secret_path) not in encoded
    assert rows == [meta]

    for bad_id in ["../root", "/etc/passwd", "UPPER", "a", "x..y", "x/y"]:
        try:
            vault.put(bad_id, "restic", marker)
            raise AssertionError(f"unsafe secret id accepted: {bad_id}")
        except ValueError:
            pass
    try:
        vault.put("prod-token", "arbitrary", marker)
        raise AssertionError("unknown secret kind accepted")
    except ValueError:
        pass
    assert vault.delete("prod-backup", "restic") is True
    assert vault.list_metadata() == []

# Test the web boundary: the browser never gets a write before Step-Up.
_tmp_ctx = tempfile.TemporaryDirectory()
tmp = _tmp_ctx.name
salt = "22" * 16
password = "Vault-Gate-Password-2026"
digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 310000).hex()
os.environ["NVP_DATA_DIR"] = tmp
os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
os.environ["NVP_ADMIN_SALT"] = salt
os.environ["NVP_ADMIN_HASH"] = digest
os.environ["NVP_SECRET"] = "vault-test-secret"
os.environ["NVP_COOKIE_SECURE"] = "0"
os.environ["NVP_AGENT_SOCK"] = str(pathlib.Path(tmp) / "missing-agent.sock")
os.environ["NVP_VAULT_SOCK"] = str(pathlib.Path(tmp) / "missing-vault.sock")

app_spec = importlib.util.spec_from_file_location("nvp_vault_app", ROOT / "app.py")
app_mod = importlib.util.module_from_spec(app_spec)
app_spec.loader.exec_module(app_mod)
app = app_mod.app
app.config.update(TESTING=True)
client = app.test_client()

client.get("/login")
with client.session_transaction() as sess:
    csrf = sess["csrf"]
r = client.post("/login", data={"csrf_token": csrf, "username": "admin", "password": password}, follow_redirects=False)
assert r.status_code == 302
with client.session_transaction() as sess:
    csrf = sess["csrf"]

r = client.post(
    "/api/vault/put",
    json={"id": "prod-backup", "kind": "restic", "value": "never-persist-this-test-value"},
    headers={"X-CSRF-Token": csrf},
)
assert r.status_code == 428 and r.get_json().get("ok") is False

# Metadata is readable to admin but the isolated test has no root vault agent.
r = client.get("/api/vault/metadata")
assert r.status_code == 503 and r.get_json().get("entries") == []

# There is deliberately no secret-read route.
r = client.get("/api/vault/read?id=prod-backup&kind=restic")
assert r.status_code == 404

_tmp_ctx.cleanup()
print("Nexvary Panel Secret Vault isolation/Step-Up tests: PASS")
