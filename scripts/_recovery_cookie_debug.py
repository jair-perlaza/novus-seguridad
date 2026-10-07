"""Debug Set-Cookie and session round-trip on live server."""
import json
import re
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

BASE = "http://127.0.0.1:5000"

s = requests.Session()
r = s.get(BASE + "/login", timeout=30)
html_csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
html_csrf = html_csrf.group(1) if html_csrf else None

print(
    json.dumps(
        {
            "get_status": r.status_code,
            "set_cookie_headers": r.headers.get("Set-Cookie"),
            "session_cookie_after_get": s.cookies.get("session"),
            "html_csrf_prefix": (html_csrf or "")[:16],
            "all_cookies": dict(s.cookies),
        },
        indent=2,
    )
)
