"""Debug live login CSRF/session mismatch."""
import json
import re
import sys
from pathlib import Path

import requests
from itsdangerous import URLSafeTimedSerializer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.flask_secret_service import resolve_flask_secret_key

BASE = "http://127.0.0.1:5000"
QA_EMAIL = "novus.qa.jul2026@example.com"
QA_PASS = "NovusQA2026!"

secret, secret_source = resolve_flask_secret_key()
ser = URLSafeTimedSerializer(secret, salt="cookie-session")

s = requests.Session()
r = s.get(BASE + "/login", timeout=30)
html_csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
html_csrf = html_csrf.group(1) if html_csrf else None
cookie = s.cookies.get("session", "")

sess_csrf = None
sess_err = None
try:
    data = ser.loads(cookie)
    sess_csrf = data.get("_csrf_token")
except Exception as exc:
    sess_err = str(exc)

r2 = s.post(
    BASE + "/login",
    data={"email": QA_EMAIL, "password": QA_PASS, "csrf_token": html_csrf or ""},
    allow_redirects=False,
    timeout=30,
)

err = None
for pat in [
    r"Solicitud rechazada[^<]*",
    r"incorrectos",
    r"class=\"error\"[^>]*>([^<]+)",
]:
    m = re.search(pat, r2.text, re.I)
    if m:
        err = m.group(0) if m.lastindex is None else m.group(1)
        break

print(
    json.dumps(
        {
            "get_status": r.status_code,
            "post_status": r2.status_code,
            "html_csrf_prefix": (html_csrf or "")[:12],
            "session_csrf_prefix": (sess_csrf or "")[:12] if sess_csrf else None,
            "csrf_match": html_csrf == sess_csrf,
            "secret_source": secret_source,
            "session_decode_err": sess_err,
            "error_in_body": err,
            "location": r2.headers.get("Location"),
            "cookie_on_post": bool(s.cookies.get("session")),
        },
        indent=2,
    )
)
