from __future__ import annotations
import base64, json, tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import panel.licensing as licensing

def _write_license(tmp: Path, payload: dict, key):
    sig=key.sign(licensing._canonical(payload))
    (tmp/"license.json").write_text(json.dumps({"payload":payload,"signature":base64.b64encode(sig).decode()}),encoding="utf-8")

def test_signed_license_and_tamper_detection():
    key=Ed25519PrivateKey.generate()
    with tempfile.TemporaryDirectory() as td:
        p=Path(td)
        (p/"public.pem").write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        licensing.PUBLIC_KEY_FILE=p/"public.pem"; licensing.LICENSE_FILE=p/"license.json"
        now=datetime.now(timezone.utc)
        payload={"license_id":"test","server_id":licensing.server_fingerprint(),"expires_at":(now+timedelta(days=1)).isoformat(),"features":["white_label"],"grace_days":7}
        _write_license(p,payload,key)
        state=licensing.verify_license(now)
        assert state.status=="VALID" and state.feature("white_label")
        envelope=json.loads((p/"license.json").read_text()); envelope["payload"]["features"]=[]
        (p/"license.json").write_text(json.dumps(envelope))
        assert licensing.verify_license(now).status=="LOCKED"

if __name__=="__main__":
    test_signed_license_and_tamper_detection()
    print("licensing_test: ok")
