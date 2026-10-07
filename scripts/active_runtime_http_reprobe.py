#!/usr/bin/env python3
"""Re-probe APIs after boot grace — sequential, with optional login."""
import json
import re
import sys
import time

import requests

BASE = "http://127.0.0.1:5000"
ENDPOINTS = [
    "/api/dashboard/live",
    "/api/health/status",
    "/api/network/nodes",
    "/api/search",
    "/api/security/vulnerabilities",
    "/api/security/threats",
    "/api/reports",
    "/api/system/runtime-info",
]


def main():
    s = requests.Session()
    lp = s.get(BASE + "/login", timeout=30)
    csrf = None
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', lp.text or "")
    if m:
        csrf = m.group(1)
    login_note = "no_csrf"
    if csrf:
        rlogin = s.post(
            BASE + "/login",
            data={
                "email": "novus.qa.jul2026@example.com",
                "password": "NovusQA2026!",
                "csrf_token": csrf,
            },
            timeout=45,
            allow_redirects=True,
        )
        login_note = f"login_status={rlogin.status_code} url={rlogin.url[:80]}"
    out = {"login": login_note, "probes": []}
    for ep in ENDPOINTS:
        t0 = time.time()
        r = s.get(BASE + ep, timeout=90)
        ms = round((time.time() - t0) * 1000, 1)
        rec = False
        body = None
        try:
            body = r.json()
            rec = bool(body.get("_novusRecovery"))
        except Exception:
            pass
        entry = {
            "endpoint": ep,
            "status": r.status_code,
            "latency_ms": ms,
            "recovery": rec,
            "result": "FAILED" if rec else ("VERIFIED" if r.status_code == 200 else "NOT VERIFIED"),
        }
        if ep.endswith("runtime-info") and body and body.get("status") == "success":
            entry["result"] = "VERIFIED"
            entry["runtime"] = body.get("runtime")
        out["probes"].append(entry)
        time.sleep(4)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
