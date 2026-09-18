from __future__ import annotations

import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory(prefix="nvp-security-headers-") as tmp:
    os.environ["NVP_DATA_DIR"] = tmp
    os.environ["NVP_DB_PATH"] = str(pathlib.Path(tmp) / "panel.db")
    os.environ["NVP_COOKIE_SECURE"] = "1"

    from panel import create_app

    app = create_app()
    app.testing = True
    client = app.test_client()

    response = client.get("/login")
    assert response.status_code == 200, response.data
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "no-referrer"
    assert response.headers.get("Strict-Transport-Security") == "max-age=31536000; includeSubDomains"

    permissions = response.headers.get("Permissions-Policy", "")
    for directive in ("camera=()", "microphone=()", "geolocation=()", "payment=()", "usb=()"):
        assert directive in permissions, permissions

    csp = response.headers.get("Content-Security-Policy", "")
    for directive in (
        "default-src 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "connect-src 'self'",
    ):
        assert directive in csp, csp

print("NEXVARY browser security headers gate: PASS")
