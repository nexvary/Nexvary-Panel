from __future__ import annotations

import json
import os
import socket

OPS_SOCK=os.environ.get('NVP_OPS_SOCK','/run/nexvary-panel/ops.sock')
MAX_RESPONSE=512*1024


def ops_call(payload:dict,timeout:int=25)->dict:
    raw=(json.dumps(payload,separators=(',',':'))+'\n').encode()
    if len(raw)>64*1024:
        return {'ok':False,'error':'ops request too large'}
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(timeout);s.connect(OPS_SOCK);s.sendall(raw)
            data=b''
            while not data.endswith(b'\n') and len(data)<=MAX_RESPONSE:
                chunk=s.recv(8192)
                if not chunk:break
                data+=chunk
    except (OSError,TimeoutError) as exc:
        return {'ok':False,'error':f'ops provider unavailable: {exc}'}
    if not data or len(data)>MAX_RESPONSE:
        return {'ok':False,'error':'invalid ops response'}
    try:
        body=json.loads(data.decode())
        return body if isinstance(body,dict) else {'ok':False,'error':'invalid ops response'}
    except Exception:
        return {'ok':False,'error':'invalid ops response'}
