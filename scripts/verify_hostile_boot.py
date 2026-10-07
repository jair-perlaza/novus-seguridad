#!/usr/bin/env python3
import json
import os
import re
import sys

import requests

BASE = os.environ.get("NOVUS_VERIFY_BASE", "").strip()
if not BASE:
    try:
        with open(
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "ngrok", "manager_status.json"),
            encoding="utf-8",
        ) as fh:
            pub = json.load(fh).get("public_url")
            if pub:
                BASE = pub.rstrip("/")
    except Exception:
        pass
if not BASE:
    BASE = "http://127.0.0.1:5000"
EMAIL = "novus.qa.jul2026@example.com"
PASSWORD = "NovusQA2026!"


def main() -> int:
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=30)
    print("login", r.status_code, bool(r.headers.get("Content-Security-Policy")))
    print("session_cookie", bool(s.cookies.get("session")))
    m = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    tok = m.group(1) if m else None
    print("csrf_token", bool(tok))
    if not tok:
        return 1
    r2 = s.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PASSWORD, "csrf_token": tok},
        allow_redirects=True,
        timeout=60,
    )
    print("post_login", r2.status_code, r2.url)
    if r2.status_code != 200 and "dashboard" not in r2.url:
        snippet = r2.text.replace("\n", " ")[:400]
        print("post_body_snip", snippet)
        print("csrf_reject", "CSRF" in r2.text, "rechazada" in r2.text.lower())
        print("blocked_msg", "bloqueado" in r2.text.lower())
    r3 = s.get(f"{BASE}/api/system/hostile-environment/status", timeout=30)
    print("hostile", r3.status_code)
    if r3.ok:
        print("mechanisms", r3.json().get("mechanisms_active"))
    try:
        with open("data/ngrok/manager_status.json", encoding="utf-8") as fh:
            ng = json.load(fh)
        print("ngrok", ng.get("connection_status"), ng.get("public_url"))
    except Exception as exc:
        print("ngrok_read", exc)
    return 0 if r3.ok else 2


if __name__ == "__main__":
    sys.exit(main())
