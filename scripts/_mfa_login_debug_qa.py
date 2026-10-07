import re
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

BASE = "http://127.0.0.1:5000"
email = "novus.qa.jul2026@example.com"
pwd = "NovusQA2026!"

s = requests.Session()
g = s.get(BASE + "/login", timeout=15)
t = re.search(r'name="csrf_token" value="([^"]+)"', g.text).group(1)
p = s.post(
    BASE + "/login",
    data={"email": email, "password": pwd, "csrf_token": t},
    allow_redirects=False,
    timeout=15,
)
print("status", p.status_code, "loc", p.headers.get("Location"))
print("recovery", p.headers.get("X-Novus-Recovery"))
print("mfa", "mfa" in p.text.lower(), "panel", "novus-estado-general-panel" in p.text)
