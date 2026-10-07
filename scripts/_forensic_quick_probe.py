#!/usr/bin/env python3
"""Quick latency probe — read-only, diagnostic only."""
import re
import time
import requests

BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")


def main():
    s = requests.Session()
    t0 = time.perf_counter()
    r = s.get(f"{BASE}/login", timeout=60)
    print("login_get", round((time.perf_counter() - t0) * 1000, 1), "ms", r.status_code)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    csrf = csrf.group(1) if csrf else ""
    t1 = time.perf_counter()
    r2 = s.post(
        f"{BASE}/login",
        data={"email": QA[0], "password": QA[1], "csrf_token": csrf},
        allow_redirects=True,
        timeout=120,
    )
    print("login_post", round((time.perf_counter() - t1) * 1000, 1), "ms", r2.status_code)

    paths = [
        "/dashboard",
        "/security-operations-center",
        "/network",
        "/endpoints",
        "/threat-intelligence-center",
        "/playbook-center",
        "/incident-management",
        "/api/tie/dashboard",
        "/api/sope/dashboard",
        "/api/imcm/timeline?limit=50",
        "/api/network/info",
        "/api/network/nodes",
        "/api/network/refresh",
    ]
    for p in paths:
        t = time.perf_counter()
        try:
            rr = s.get(BASE + p, timeout=45)
            print(p, round((time.perf_counter() - t) * 1000, 1), "ms", rr.status_code, len(rr.content))
        except Exception as exc:
            print(p, "ERR", str(exc)[:100])


if __name__ == "__main__":
    main()
