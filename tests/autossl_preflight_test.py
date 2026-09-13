from __future__ import annotations

import importlib
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent"
sys.path.insert(0, str(AGENT))
sys.path.insert(0, str(ROOT))

entry = importlib.import_module("hosting_ops_entry")

with tempfile.TemporaryDirectory(prefix="nvp-autossl-preflight-") as tmp:
    site_root = Path(tmp) / "site"
    webroot = site_root / "public"
    webroot.mkdir(parents=True)
    conf = Path(tmp) / "example.com.conf"

    def write_conf(names: str, root_path: Path = webroot):
        conf.write_text(
            f"server {{ listen 80; server_name {names}; root {root_path}; }}\n",
            encoding="utf-8",
        )

    write_conf("example.com shop.example.com")
    entry.core._site_root = lambda domain: site_root
    entry.core._nginx_conf = lambda domain: conf
    entry._resolve_public = lambda host: ["198.51.100.10"]
    probes = []

    def probe(host, ip, path, token):
        probes.append((host, ip, path, token))
        challenge = webroot / path.lstrip("/")
        assert challenge.read_text(encoding="ascii") == token
        return {"ok": True, "status": 200, "error": ""}

    entry._probe_http = probe
    result = entry._autossl_preflight({"domain": "example.com", "domains": ["shop.example.com"]})
    assert result["ok"] is True and result["ready"] is True
    assert result["domains"] == ["example.com", "shop.example.com"]
    assert result["webroot"] == str(webroot.resolve())
    assert len(result["checks"]) == 2 and all(row["ready"] for row in result["checks"])
    assert len(probes) == 2
    assert not any((webroot / ".well-known" / "acme-challenge").glob("nexvary-autossl-*"))

    write_conf("example.com")
    result = entry._autossl_preflight({"domain": "example.com", "domains": ["shop.example.com"]})
    failed = {row["domain"]: row for row in result["checks"]}
    assert result["ready"] is False
    assert failed["shop.example.com"]["reason"] == "domain-not-bound-to-managed-nginx-site"

    write_conf("example.com shop.example.com")
    entry._resolve_public = lambda host: [] if host == "shop.example.com" else ["198.51.100.10"]
    result = entry._autossl_preflight({"domain": "example.com", "domains": ["shop.example.com"]})
    failed = {row["domain"]: row for row in result["checks"]}
    assert result["ready"] is False and failed["shop.example.com"]["reason"] == "no-public-dns-address"

    # A configured NGINX root outside the managed site tree must be rejected.
    outside = Path(tmp) / "outside"
    outside.mkdir()
    write_conf("example.com shop.example.com", outside)
    try:
        entry._autossl_preflight({"domain": "example.com", "domains": ["shop.example.com"]})
        raise AssertionError("AutoSSL accepted an unmanaged HTTP webroot")
    except ValueError as exc:
        assert str(exc) == "managed-http-webroot-not-found"

    write_conf("example.com shop.example.com")
    entry._resolve_public = lambda host: ["198.51.100.10"]
    commands = []
    entry.core._run = lambda args, timeout=60, **kwargs: commands.append(list(args)) or type("Proc", (), {"stdout": ""})()
    entry.core._bind_ssl = lambda domain: None
    entry._ssl_status_with_names = lambda domain: {"ok": True, "installed": True, "domain": domain, "names": ["example.com", "shop.example.com"]}
    issued = entry._ssl_issue_with_names(
        {"domain": "example.com", "domains": ["shop.example.com"], "email": "ops@example.com"},
        {"ok": True, "ready": True, "checks": [], "webroot": str(webroot)},
    )
    assert issued["ok"] is True
    certbot = commands[0]
    assert certbot[:2] == ["certbot", "certonly"]
    assert certbot.count("-d") == 2
    assert "example.com" in certbot and "shop.example.com" in certbot
    assert "--cert-name" in certbot
    assert certbot[certbot.index("-w") + 1] == str(webroot.resolve())

print("Nexvary Panel AutoSSL preflight/SAN gate: PASS")
