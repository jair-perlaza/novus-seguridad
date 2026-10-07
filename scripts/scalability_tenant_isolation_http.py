#!/usr/bin/env python3
"""HTTP E2E tenant isolation — LOADTEST tenants A/B/C no pueden leer datos cruzados."""
from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "production_closure" / "tenant_isolation_http.json"
SESSIONS = ROOT / "data" / "production_closure" / "loadtest_sessions.pkl"
BASE = "http://127.0.0.1:5000"
PATHS = ["/api/dashboard/live", "/api/security/summary", "/api/tenant/scope"]


def main() -> int:
    import requests

    from services.loadtest_runtime import apply_loadtest_client_headers

    if not SESSIONS.is_file():
        print("Missing sessions", file=sys.stderr)
        return 2

    sessions = pickle.loads(SESSIONS.read_bytes())
    if len(sessions) < 3:
        return 2

    picks = [sessions[0], sessions[1], sessions[2]]
    tenant_ids = []
    leaks = []

    for rec in picks:
        s = requests.Session()
        apply_loadtest_client_headers(s, rec["email"])
        s.cookies.update(rec["cookies"])
        scope = s.get(BASE + "/api/tenant/scope", timeout=30)
        if scope.status_code != 200:
            leaks.append({"email": rec["email"], "error": f"scope {scope.status_code}"})
            continue
        body = scope.json()
        tid = body.get("tenant_id") or body.get("company_id") or body.get("nit_pyme")
        tenant_ids.append({"email": rec["email"], "tenant_id": tid})

    for i, rec_a in enumerate(picks):
        for j, rec_b in enumerate(picks):
            if i == j:
                continue
            sa = requests.Session()
            apply_loadtest_client_headers(sa, rec_a["email"])
            sa.cookies.update(rec_a["cookies"])
            for path in PATHS:
                r = sa.get(BASE + path, timeout=30)
                if r.status_code != 200:
                    continue
                text = r.text
                other_tid = tenant_ids[j]["tenant_id"]
                other_email = picks[j]["email"]
                if other_tid and str(other_tid) in text and str(other_tid) != str(tenant_ids[i]["tenant_id"]):
                    leaks.append({"viewer": rec_a["email"], "path": path, "leaked_tenant": other_tid})
                if other_email in text and other_email != rec_a["email"]:
                    leaks.append({"viewer": rec_a["email"], "path": path, "leaked_email": other_email})

    report = {
        "tenants_checked": tenant_ids,
        "cross_leaks": leaks,
        "verdict": "PASS" if not leaks and len(tenant_ids) >= 3 else "FAIL",
        "checks": len(tenant_ids) * (len(picks) - 1) * len(PATHS),
    }
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"verdict": report["verdict"], "leaks": len(leaks), "out": str(OUT)}, indent=2))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
