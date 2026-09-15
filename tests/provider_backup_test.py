import hashlib
import importlib.util
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

vault_spec = importlib.util.spec_from_file_location("nvp_secret_vault_provider_test", ROOT / "agent" / "secret_vault.py")
vault_mod = importlib.util.module_from_spec(vault_spec)
vault_spec.loader.exec_module(vault_mod)
sys.modules["secret_vault"] = vault_mod
provider_spec = importlib.util.spec_from_file_location("nvp_provider_agent_test", ROOT / "agent" / "provider_agent.py")
provider = importlib.util.module_from_spec(provider_spec)
provider_spec.loader.exec_module(provider)

GOOD_CONFIG = """[secure]
type = crypt
remote = s3base:nexvary
password = obscured-value
filename_encryption = standard
no_data_encryption = false

[s3base]
type = s3
provider = AWS
region = us-east-1
"""

with tempfile.TemporaryDirectory() as tmp:
    base = pathlib.Path(tmp)
    vault = vault_mod.SecretVault(base / "credentials")
    vault.put("prod-rclone", "rclone", GOOD_CONFIG)
    provider.VAULT = vault
    contract = provider._rclone_contract("prod-rclone", "secure:server-a/backups")
    assert contract["remote"] == "secure"
    assert contract["backing_type"] == "s3"
    assert contract["remote_path"] == "server-a/backups"
    assert "password" not in repr(contract).lower()

    bad_configs = {
        "local-backend": GOOD_CONFIG.replace("type = s3", "type = local"),
        "no-data-encryption": GOOD_CONFIG.replace("no_data_encryption = false", "no_data_encryption = true"),
        "filename-off": GOOD_CONFIG.replace("filename_encryption = standard", "filename_encryption = off"),
        "private-endpoint": GOOD_CONFIG + "endpoint = https://127.0.0.1:9000\n",
    }
    for secret_id, config in bad_configs.items():
        vault.put(secret_id, "rclone", config)
        try:
            provider._rclone_contract(secret_id, "secure:server-a/backups")
            raise AssertionError(f"unsafe rclone contract accepted: {secret_id}")
        except ValueError:
            pass

    for target in ["secure:/etc", "secure:../etc", "localpath", "-bad:path", "secure:"]:
        try:
            provider._split_remote(target)
            raise AssertionError(f"unsafe rclone target accepted: {target}")
        except ValueError:
            pass

    backup_base = base / "backups"
    domain_dir = backup_base / "example.com"
    domain_dir.mkdir(parents=True)
    archive = domain_dir / "example.com-20260909.tar.gz"
    archive.write_bytes(b"backup")
    provider.BACKUP_BASE = backup_base
    assert provider._backup_file("example.com", str(archive)) == archive.resolve()
    outside = base / "outside.tar.gz"
    outside.write_bytes(b"no")
    try:
        provider._backup_file("example.com", str(outside))
        raise AssertionError("outside backup path accepted")
    except ValueError:
        pass

# UI wiring is static-gated even when CI has no real restore points to render.
backup_template = (ROOT / "templates" / "sections" / "backups.html").read_bytes()
index_template = (ROOT / "templates" / "index.html").read_bytes()
assert b"remote-backup-slot" in backup_template and b"LOCAL + FUSION" in backup_template
assert b"/static/remote-backup.css" in index_template and b"/static/remote-backup.js" in index_template

# Web action is Step-Up protected before target/backup lookup or provider execution.
_tmp = tempfile.TemporaryDirectory()
tmp = _tmp.name
salt = "44" * 16
password = "Remote-Backup-Gate-2026"
digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 310000).hex()
os.environ["NVP_DATA_DIR"] = tmp
os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
os.environ["NVP_ADMIN_SALT"] = salt
os.environ["NVP_ADMIN_HASH"] = digest
os.environ["NVP_SECRET"] = "remote-backup-test-secret"
os.environ["NVP_COOKIE_SECURE"] = "0"
os.environ["NVP_AGENT_SOCK"] = str(pathlib.Path(tmp) / "missing-agent.sock")
os.environ["NVP_VAULT_SOCK"] = str(pathlib.Path(tmp) / "missing-vault.sock")
os.environ["NVP_PROVIDER_SOCK"] = str(pathlib.Path(tmp) / "missing-provider.sock")

app_spec = importlib.util.spec_from_file_location("nvp_remote_backup_app", ROOT / "app.py")
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
r = client.post("/api/remote-backup/push", json={"backup_id": 1, "target_id": 1}, headers={"X-CSRF-Token": csrf})
assert r.status_code == 428
r = client.get("/api/remote-backup/targets/1/preflight")
assert r.status_code == 404
_tmp.cleanup()
print("Nexvary Panel rclone crypt-over-S3 Provider Agent tests: PASS")
