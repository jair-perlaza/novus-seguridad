import os
import re
import requests

BASE = "http://127.0.0.1:5000"
s = requests.Session()
g = s.get(BASE + "/login", timeout=30)
print("cookies_after_get", list(s.cookies.keys()))
print("set_cookie", g.headers.get("Set-Cookie", "")[:120])
t = re.search(r'name="csrf_token" value="([^"]+)"', g.text)
token = t.group(1) if t else ""
print("html_token_len", len(token))
pwd = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")
p = s.post(
    BASE + "/login",
    data={"email": "novus.qa.jul2026@example.com", "password": pwd, "csrf_token": token},
    timeout=30,
    allow_redirects=False,
)
print("post_status", p.status_code, "location", p.headers.get("Location"))
print("orig_status", p.headers.get("X-Novus-Original-Status"))
print("recovery", p.headers.get("X-Novus-Recovery"))
print("panel", "novus-estado-general-panel" in p.text)
if p.status_code in (301, 302, 303, 307, 308):
    p2 = s.get(BASE + (p.headers.get("Location") or "/"), timeout=30)
    print("after_redirect panel", "novus-estado-general-panel" in p2.text)
