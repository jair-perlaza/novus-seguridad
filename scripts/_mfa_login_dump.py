import re
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

BASE = "http://127.0.0.1:5000"

s = requests.Session()
g = s.get(BASE + "/login", timeout=15)
print("GET status", g.status_code, "cookies", dict(s.cookies))
t = re.search(r'name="csrf_token" value="([^"]+)"', g.text)
print("csrf found", bool(t))
if not t:
    print(g.text[:500])
    raise SystemExit(1)
token = t.group(1)
p = s.post(
    BASE + "/login",
    data={"email": "novus.qa.jul2026@example.com", "password": "NovusQA2026!", "csrf_token": token},
    allow_redirects=False,
    timeout=15,
)
print("POST status", p.status_code)
print("headers", {k: p.headers.get(k) for k in ("Location", "Content-Type", "Set-Cookie", "X-Novus-Recovery")})
low = p.text.lower()
for needle in ("csrf", "incorrectos", "error", "mfa", "recuperando", "bloqueado", "rate", "demasiados"):
    if needle in low:
        idx = low.index(needle)
        print("found", needle, "...", p.text[max(0, idx - 40) : idx + 80].replace("\n", " "))
