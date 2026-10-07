#!/usr/bin/env python3
import json, re, time, requests
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")
paths = [
    "/api/dashboard/live",
    "/api/security/summary",
    "/api/network/nodes?trigger_discovery=false",
    "/api/network/info",
    "/api/network/ndr",
    "/api/network/topology",
]
s = requests.Session()
r = s.get(BASE + "/login", timeout=15)
csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
s.post(BASE + "/login", data={"email": QA[0], "password": QA[1], "csrf_token": csrf.group(1) if csrf else ""}, timeout=20)
for p in paths:
    s.get(BASE + p, timeout=15)
time.sleep(1)
rows = []
for p in paths:
    t0 = time.perf_counter()
    r = s.get(BASE + p, timeout=15)
    rows.append({"path": p, "ms": round((time.perf_counter() - t0) * 1000, 1), "http": r.status_code})
print(json.dumps(rows, indent=2))
