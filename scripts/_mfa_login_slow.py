import re
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.mfa_admin_http_e2e_final import clear_localhost_auth_blocks

print("cleared", clear_localhost_auth_blocks())
BASE = "http://127.0.0.1:5000"
s = requests.Session()
g = s.get(BASE + "/login", timeout=30)
t = re.search(r'name="csrf_token" value="([^"]+)"', g.text).group(1)
t0 = time.time()
p = s.post(
    BASE + "/login",
    data={"email": "novus.qa.jul2026@example.com", "password": "NovusQA2026!", "csrf_token": t},
    allow_redirects=False,
    timeout=90,
)
print("elapsed", round(time.time() - t0, 1), "status", p.status_code, "loc", p.headers.get("Location"))
print("mfa", "mfa" in p.text.lower(), "bloqueado", "bloqueado" in p.text.lower())
