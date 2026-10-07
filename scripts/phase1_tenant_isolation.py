#!/usr/bin/env python3
"""Phase 1 cross-tenant isolation — 10 / 100 / 600 sessions on critical APIs."""
from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SESSIONS = ROOT / "data" / "production_closure" / "loadtest_sessions.pkl"
OUT = ROOT / "data" / "production_closure" / "phase1_tenant_isolation.json"
BASE = "http://127.0.0.1:5000"
PATHS = [
    "/api/dashboard/live",
    "/api/security/summary",
    "/api/tenant/scope",
    "/api/notifications",
    "/api/security/threats",
    "/api/security/vulnerabilities",
    "/api/network/nodes?trigger_discovery=false",
    "/api/manual-defense/summary",
]
LEVELS = [10, 100, 600]


def check_level(sessions: list, n: int) -> dict:
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers

    subset = sessions[:n]
    scopes = []
    leaks = []
    errors = []

    for rec in subset:
        s = requests.Session()
        apply_loadtest_client_headers(s, rec["email"])
        s.cookies.update(rec["cookies"])
        r = s.get(BASE + "/api/tenant/scope", timeout=20)
        if r.status_code != 200:
            errors.append({"email": rec["email"], "scope_http": r.status_code})
            continue
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        tid = body.get("tenant_id") or body.get("company_id") or body.get("nit_pyme")
        scopes.append({"email": rec["email"], "tenant_id": tid, "cookies": rec["cookies"]})

    # Sample pairwise: each of first min(20,n) vs next distinct tenants
    sample = scopes[: min(20, len(scopes))]
    for i, a in enumerate(sample):
        sa = requests.Session()
        apply_loadtest_client_headers(sa, a["email"])
        sa.cookies.update(a["cookies"])
        others = [b for j, b in enumerate(scopes) if b["email"] != a["email"]][:5]
        for path in PATHS:
            r = sa.get(BASE + path, timeout=20)
            if r.status_code != 200:
                errors.append({"viewer": a["email"], "path": path, "http": r.status_code})
                continue
            text = r.text
            for b in others:
                if b.get("tenant_id") and str(b["tenant_id"]) in text and str(b["tenant_id"]) != str(a.get("tenant_id")):
                    leaks.append({"viewer": a["email"], "path": path, "leaked_tenant": b["tenant_id"]})
                if b["email"] in text:
                    leaks.append({"viewer": a["email"], "path": path, "leaked_email": b["email"]})

    return {
        "n": n,
        "scopes_ok": len(scopes),
        "leaks": leaks,
        "errors": errors[:20],
        "error_count": len(errors),
        "pass": len(leaks) == 0 and len(scopes) >= min(n, 3),
    }


def main() -> int:
    sessions = pickle.loads(SESSIONS.read_bytes())
    report = {"levels": [], "verdict": "PASS"}
    for n in LEVELS:
        if len(sessions) < n:
            report["levels"].append({"n": n, "pass": False, "error": "insufficient_sessions"})
            report["verdict"] = "FAIL"
            continue
        print(f"Isolation level {n}...", flush=True)
        rec = check_level(sessions, n)
        report["levels"].append(rec)
        print(f"  n={n} pass={rec['pass']} leaks={len(rec['leaks'])} errors={rec['error_count']}", flush=True)
        if not rec["pass"]:
            report["verdict"] = "FAIL"
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"verdict": report["verdict"], "out": str(OUT)}, indent=2))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
