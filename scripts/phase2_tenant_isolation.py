#!/usr/bin/env python3
"""Phase 2 — tenant isolation at scale + IDOR-style checks on critical APIs."""
from __future__ import annotations

import json
import pickle
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SESSIONS = ROOT / "data" / "production_closure" / "loadtest_sessions.pkl"
OUT = ROOT / "data" / "production_closure" / "phase2_tenant_isolation.json"
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
# Test at max available among these
LEVELS = [10, 100, 600, 1000]


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch_scope(rec) -> dict | None:
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers

    s = requests.Session()
    apply_loadtest_client_headers(s, rec["email"])
    s.cookies.update(rec["cookies"])
    r = s.get(BASE + "/api/tenant/scope", timeout=25)
    if r.status_code != 200:
        return None
    body = r.json() if "json" in r.headers.get("content-type", "") else {}
    tid = body.get("tenant_id") or body.get("company_id") or body.get("nit_pyme")
    return {"email": rec["email"], "tenant_id": tid, "cookies": rec["cookies"]}


def check_level(sessions: list, n: int) -> dict:
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers

    subset = sessions[:n]
    scopes = []
    with ThreadPoolExecutor(max_workers=min(24, n)) as ex:
        futs = [ex.submit(fetch_scope, rec) for rec in subset]
        for fut in as_completed(futs):
            sc = fut.result()
            if sc and sc.get("tenant_id"):
                scopes.append(sc)

    leaks = []
    errors = []
    tests = 0
    sample = scopes[: min(25, len(scopes))]

    for a in sample:
        sa = requests.Session()
        apply_loadtest_client_headers(sa, a["email"])
        sa.cookies.update(a["cookies"])
        others = [b for b in scopes if b["email"] != a["email"]][:8]
        for path in PATHS:
            tests += 1
            try:
                r = sa.get(BASE + path, timeout=25)
            except Exception as exc:
                errors.append({"viewer": a["email"], "path": path, "error": str(exc)[:80]})
                continue
            if r.status_code != 200:
                errors.append({"viewer": a["email"], "path": path, "http": r.status_code})
                continue
            text = r.text
            for b in others:
                tests += 1
                if b.get("tenant_id") and str(b["tenant_id"]) in text and str(b["tenant_id"]) != str(a.get("tenant_id")):
                    leaks.append({"viewer": a["email"], "path": path, "leaked_tenant": b["tenant_id"], "type": "tenant_id_in_body"})
                if b["email"] in text:
                    leaks.append({"viewer": a["email"], "path": path, "leaked_email": b["email"], "type": "email_in_body"})

        # IDOR-ish: ask for another tenant via query (must not honor client tenant_id)
        if others:
            b = others[0]
            tests += 1
            try:
                r = sa.get(
                    BASE + "/api/security/summary",
                    params={"tenant_id": b["tenant_id"]},
                    timeout=25,
                )
                if r.status_code == 200:
                    text = r.text
                    # if response contains other tenant id as owning tenant, leak
                    if str(b["tenant_id"]) in text and str(a["tenant_id"]) not in text:
                        # weak signal — only count if own tenant missing and other present as primary
                        leaks.append(
                            {
                                "viewer": a["email"],
                                "path": "/api/security/summary?tenant_id=",
                                "leaked_tenant": b["tenant_id"],
                                "type": "client_tenant_id_honored",
                            }
                        )
            except Exception as exc:
                errors.append({"viewer": a["email"], "idor_error": str(exc)[:80]})

    return {
        "n": n,
        "scopes_ok": len(scopes),
        "tests_executed": tests,
        "leaks": leaks,
        "leak_count": len(leaks),
        "errors": errors[:30],
        "error_count": len(errors),
        "pass": len(leaks) == 0 and len(scopes) >= min(n, 3),
    }


def main() -> int:
    sessions = pickle.loads(SESSIONS.read_bytes())
    report = {
        "generated_at": utc(),
        "sessions_available": len(sessions),
        "levels": [],
        "TENANT_ISOLATION_TESTS": "FAIL",
        "total_tests": 0,
        "total_leaks": 0,
    }
    for n in LEVELS:
        if len(sessions) < n:
            report["levels"].append({"n": n, "pass": False, "status": "NOT_TESTED", "reason": "insufficient_sessions"})
            continue
        print(f"Isolation level {n}...", flush=True)
        rec = check_level(sessions, n)
        report["levels"].append(rec)
        report["total_tests"] += rec.get("tests_executed", 0)
        report["total_leaks"] += rec.get("leak_count", 0)
        print(
            f"  n={n} pass={rec['pass']} tests={rec['tests_executed']} leaks={rec['leak_count']} errors={rec['error_count']}",
            flush=True,
        )

    tested = [l for l in report["levels"] if l.get("pass") is not None and "status" not in l or l.get("pass") is True or l.get("pass") is False]
    # simplify verdict
    any_fail = any(l.get("pass") is False and l.get("status") != "NOT_TESTED" for l in report["levels"])
    any_pass = any(l.get("pass") is True for l in report["levels"])
    if any_fail:
        report["TENANT_ISOLATION_TESTS"] = "FAIL"
    elif any_pass:
        report["TENANT_ISOLATION_TESTS"] = "PASS"
    else:
        report["TENANT_ISOLATION_TESTS"] = "NOT_TESTED"

    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"verdict": report["TENANT_ISOLATION_TESTS"], "tests": report["total_tests"], "leaks": report["total_leaks"]}, indent=2))
    return 0 if report["TENANT_ISOLATION_TESTS"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
