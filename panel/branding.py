from __future__ import annotations
import json
from pathlib import Path
from .config import APP_DIR

BRAND_FILE=APP_DIR/"branding.json"
DEFAULTS={
 "company_name":"NEXVARY","product_name":"Nexvary Panel","logo_url":"/static/brand/nexvary-panel-primary.jpg",
 "favicon_url":"/static/brand/nexvary-panel-primary.jpg","hero_url":"",
 "website":"https://nexvary.com/","email":"info@nexvary.com",
 "facebook":"https://www.facebook.com/share/14p9krEn5ij/","youtube":"https://www.youtube.com/@NexvaryInc","x":"https://x.com/Nexvary"
}
def get_branding():
    try:
        raw=json.loads(BRAND_FILE.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError):
        raw={}
    return {**DEFAULTS,**{k:v for k,v in raw.items() if k in DEFAULTS and isinstance(v,str)}}

def save_branding(values: dict):
    APP_DIR.mkdir(parents=True,exist_ok=True)
    clean={k:str(values.get(k,DEFAULTS[k])).strip()[:500] for k in DEFAULTS}
    tmp=BRAND_FILE.with_suffix(".tmp"); tmp.write_text(json.dumps(clean,ensure_ascii=False,indent=2),encoding="utf-8"); tmp.replace(BRAND_FILE)
    return clean
