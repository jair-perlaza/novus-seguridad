import re
import time
import requests

BASE = "http://127.0.0.1:5000"
EMAIL = "operaciones@novapay-fintech.co"
PASS = "NovaPay#Fintech2026"

s = requests.Session()
s.headers["User-Agent"] = "NOVUS-Phase1-Probe/1.0"
r0 = s.get(BASE + "/login", timeout=60)
csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', r0.text)
s.post(
    BASE + "/login",
    data={"email": EMAIL, "password": PASS, "csrf_token": csrf.group(1) if csrf else ""},
    timeout=120,
)

paths = [
    "/api/notifications",
    "/api/manual-defense/summary",
    "/api/notifications",
    "/api/manual-defense/summary",
]
for path in paths:
    t0 = time.perf_counter()
    r = s.get(BASE + path, timeout=120)
    ms = round((time.perf_counter() - t0) * 1000, 1)
    cache = r.json().get("http_cache") if r.headers.get("content-type", "").startswith("application/json") else None
    print(path, r.status_code, ms, "ms", cache or "")
