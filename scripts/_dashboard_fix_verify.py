#!/usr/bin/env python3
import json
import re
import sys
import time

import requests

BASE = "http://127.0.0.1:5000"
EMAIL, PASS = "operaciones@novapay-fintech.co", "NovaPay#Fintech2026"


def main():
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=30)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    if not m:
        print("csrf missing", file=sys.stderr)
        sys.exit(1)
    s.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PASS, "csrf_token": m.group(1)},
        allow_redirects=True,
        timeout=60,
    )
    paths = [
        "/api/dashboard/priority",
        "/api/dashboard/live",
        "/api/monitoring/status",
        "/api/notifications?kind=security",
        "/api/security/threats",
        "/api/security/vulnerabilities",
    ]
    out = {}
    for path in paths:
        t0 = time.perf_counter()
        ar = s.get(f"{BASE}{path}", timeout=90)
        body = ar.json() if "application/json" in ar.headers.get("content-type", "") else {}
        out[path] = {"http": ar.status_code, "ms": round((time.perf_counter() - t0) * 1000, 1), "body": body}
    with open("data/novus_release_candidate/DASHBOARD_FIX_VERIFY.json", "w", encoding="utf-8") as handle:
        json.dump(out, handle, indent=2, ensure_ascii=False)
    print(json.dumps(out, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
