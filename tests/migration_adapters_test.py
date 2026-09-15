from __future__ import annotations

import io
import json
import os
import pathlib
import sys
import tarfile
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from migration_adapters import inspect_import, normalize_import  # noqa: E402


def add_tar_file(tar: tarfile.TarFile, name: str, body: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(body)
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(body))


with tempfile.TemporaryDirectory(prefix="nvp-migration-adapters-") as tmp:
    root = pathlib.Path(tmp)
    out = root / "normalized"

    cpanel = root / "cpmove-demo.tar.gz"
    with tarfile.open(cpanel, "w:gz") as tar:
        add_tar_file(tar, "cpmove-demo/homedir/public_html/index.php", b"<?php echo 'cpanel';")
        add_tar_file(tar, "cpmove-demo/homedir/public_html/assets/app.css", b"body{}")
        add_tar_file(tar, "cpmove-demo/mysql/demo_wp.sql", b"CREATE TABLE test(id INT);\n")
        add_tar_file(tar, "cpmove-demo/mail/example.com/user", b"mail")
    report = inspect_import(cpanel)
    assert report["panel"] == "cpanel", report
    assert report["capabilities"]["website"] is True
    assert report["capabilities"]["mariadb_sql"] is True
    assert report["capabilities"]["mail_discovery"] is True
    assert report["capabilities"]["mail_import"] is False
    result = normalize_import(
        cpanel,
        out,
        target_domain="example.com",
        source_db="demo_wp",
        target_db="example_wp",
    )
    assert result["ok"] is True and result["panel"] == "cpanel"
    assert result["website_files"] == 2 and result["database_included"] is True
    normalized = pathlib.Path(result["archive"])
    assert normalized.is_file()
    with tarfile.open(normalized, "r:gz") as tar:
        names = set(tar.getnames())
        assert "site/index.php" in names
        assert "site/assets/app.css" in names
        assert "database.sql" in names
        manifest = json.loads(tar.extractfile("manifest.json").read().decode())
        assert manifest["domain"] == "example.com"
        assert manifest["database"] == "example_wp"
        assert manifest["adapter"]["source_panel"] == "cpanel"

    directadmin = root / "directadmin-user.tar.gz"
    with tarfile.open(directadmin, "w:gz") as tar:
        add_tar_file(tar, "backup/user.conf", b"username=demo\n")
        add_tar_file(tar, "domains/da.example/public_html/index.html", b"directadmin")
        add_tar_file(tar, "domains/da.example/public_html/.htaccess", b"RewriteEngine On\n")
        add_tar_file(tar, "backup/database/da_db.sql", b"CREATE TABLE da(id INT);\n")
        add_tar_file(tar, "domains/da.example/email/passwd", b"mail")
    report = inspect_import(directadmin, "da.example")
    assert report["panel"] == "directadmin", report
    assert report["selected_domain"] == "da.example"
    assert report["capabilities"]["website"] is True
    result = normalize_import(directadmin, out, target_domain="target.example", source_domain="da.example")
    assert result["panel"] == "directadmin" and result["website_files"] == 2

    plesk = root / "plesk-backup.zip"
    with zipfile.ZipFile(plesk, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("backup_info_260915.xml", "<backup/>")
        archive.writestr("domains/plesk.example/httpdocs/index.html", "plesk")
        archive.writestr("domains/plesk.example/httpdocs/js/app.js", "console.log(1)")
        archive.writestr("databases/plesk_db.sql", "CREATE TABLE p(id INT);")
    report = inspect_import(plesk, "plesk.example")
    assert report["panel"] == "plesk", report
    assert report["capabilities"]["website"] is True
    result = normalize_import(
        plesk,
        out,
        target_domain="plesk-target.example",
        source_domain="plesk.example",
        source_db="plesk_db",
        target_db="plesk_target",
    )
    assert result["panel"] == "plesk" and result["database_included"] is True

    ambiguous = root / "multi-db.tar.gz"
    with tarfile.open(ambiguous, "w:gz") as tar:
        add_tar_file(tar, "cpmove-u/homedir/public_html/index.html", b"ok")
        add_tar_file(tar, "cpmove-u/mysql/one.sql", b"SELECT 1;")
        add_tar_file(tar, "cpmove-u/mysql/two.sql", b"SELECT 2;")
    try:
        normalize_import(ambiguous, out, target_domain="ambiguous.example", target_db="target_db")
    except ValueError as exc:
        assert str(exc) == "migration-database-selection-required"
    else:
        raise AssertionError("ambiguous database selection must fail closed")

    unsafe = root / "unsafe.tar.gz"
    with tarfile.open(unsafe, "w:gz") as tar:
        add_tar_file(tar, "cpmove-u/homedir/public_html/index.html", b"ok")
        add_tar_file(tar, "../../etc/shadow", b"never")
    try:
        inspect_import(unsafe)
    except ValueError as exc:
        assert str(exc) == "unsafe-migration-archive"
    else:
        raise AssertionError("path traversal must be rejected")

    symlink = root / "symlink.tar.gz"
    with tarfile.open(symlink, "w:gz") as tar:
        add_tar_file(tar, "cpmove-u/homedir/public_html/index.html", b"ok")
        info = tarfile.TarInfo("cpmove-u/homedir/public_html/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    try:
        inspect_import(symlink)
    except ValueError as exc:
        assert str(exc) == "unsafe-migration-archive-entry"
    else:
        raise AssertionError("symlink entries must be rejected")

print("Nexvary Panel multi-panel migration adapter/safety gate: PASS")
