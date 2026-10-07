#!/usr/bin/env python3
import json, re, sys, time
from pathlib import Path
import requests
ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:5000"
EMAIL, PASS = "operaciones@novapay-fintech.co", "NovaPay#Fintech2026"
s = requests.Session()
r = s.get(f"{BASE}/login", timeout=30)
csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text).group(1)
s.post(f"{BASE}/login", data={"email": EMAIL, "password": PASS, "csrf_token": csrf}, allow_redirects=True, timeout=60)
out = {}
for path in ["/dashboard", "/api/dashboard/live", "/api/security/summary", "/api/monitoring/network-config",
             "/api/network/nodes?trigger_discovery=false", "/api/security/vulnerabilities", "/api/security/threats",
             "/api/notifications?kind=security", "/api/notifications?kind=system", "/api/ai/status"]:
    t0 = time.perf_counter()
    try:
        ar = s.get(f"{BASE}{path}", timeout=120)
        body = ar.json() if "application/json" in ar.headers.get("content-type","") else {}
        out[path] = {"http": ar.status_code, "ms": round((time.perf_counter()-t0)*1000,1),
                     "analysis_state": body.get("analysis_state"), "last_scan": body.get("last_scan"),
                     "monitoring_enabled": body.get("monitoring_enabled"), "status": body.get("status"),
                     "kernel_status": body.get("kernel_status") or body.get("state"), "last_execution_at": body.get("last_execution_at")}
    except Exception as e:
        out[path] = {"error": str(e)[:200]}
p = ROOT / "data/novus_release_candidate/FINAL_API_PROBE.json"
p.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
print(json.dumps(out, indent=2, ensure_ascii=False))
