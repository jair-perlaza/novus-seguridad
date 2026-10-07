#!/usr/bin/env python3
"""Phase 3 isolation under concurrent activity + security regression + recovery spot."""
from __future__ import annotations

import json
import os
import pickle
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

SESSIONS = ROOT / "data" / "production_closure" / "loadtest_sessions.pkl"
OUT = ROOT / "data" / "production_closure" / "phase3_isolation_security.json"
BASE = os.environ.get("NOVUS_LOAD_BASE", "http://127.0.0.1:5000")
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


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch_scope(rec):
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


def isolation_under_load(sessions, n: int) -> dict:
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers

    # concurrent background noise from n tenants
    stop = {"v": False}
    noise_ok = 0

    def noise(rec):
        nonlocal noise_ok
        s = requests.Session()
        apply_loadtest_client_headers(s, rec["email"])
        s.cookies.update(rec["cookies"])
        while not stop["v"]:
            try:
                r = s.get(BASE + "/api/notifications", timeout=15)
                if r.status_code == 200:
                    noise_ok += 1
            except Exception:
                pass
            time.sleep(1.5)

    noise_n = min(n, 200)
    pool = ThreadPoolExecutor(max_workers=min(48, noise_n))
    for i in range(noise_n):
        pool.submit(noise, sessions[i])

    time.sleep(2)
    scopes = []
    with ThreadPoolExecutor(max_workers=24) as ex:
        futs = [ex.submit(fetch_scope, sessions[i]) for i in range(min(n, 100))]
        for fut in as_completed(futs):
            sc = fut.result()
            if sc and sc.get("tenant_id"):
                scopes.append(sc)

    leaks = []
    tests = 0
    errors = 0
    sample = scopes[:25]
    for a in sample:
        sa = requests.Session()
        apply_loadtest_client_headers(sa, a["email"])
        sa.cookies.update(a["cookies"])
        others = [b for b in scopes if b["email"] != a["email"]][:6]
        for path in PATHS:
            tests += 1
            try:
                r = sa.get(BASE + path, timeout=20)
            except Exception:
                errors += 1
                continue
            if r.status_code != 200:
                errors += 1
                continue
            text = r.text
            for b in others:
                tests += 1
                if b.get("tenant_id") and str(b["tenant_id"]) in text and str(b["tenant_id"]) != str(a.get("tenant_id")):
                    leaks.append({"viewer": a["email"], "path": path, "leaked": b["tenant_id"]})
                if b["email"] in text:
                    leaks.append({"viewer": a["email"], "path": path, "leaked_email": b["email"]})

    stop["v"] = True
    pool.shutdown(wait=False, cancel_futures=True)
    return {
        "n_target": n,
        "noise_tenants": noise_n,
        "scopes_ok": len(scopes),
        "tests_executed": tests,
        "leaks": len(leaks),
        "leak_samples": leaks[:10],
        "errors": errors,
        "TENANT_ISOLATION": "PASS" if len(leaks) == 0 and len(scopes) >= 3 else "FAIL",
        "noise_ok_hits": noise_ok,
    }


def security_regression() -> dict:
    # reuse phase1 script logic via import
    import runpy

    # run and load output
    ns = runpy.run_path(str(ROOT / "scripts" / "phase1_security_regression.py"))
    # script writes phase1_security_regression.json
    p = ROOT / "data" / "production_closure" / "phase1_security_regression.json"
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return {"verdict": "NOT_AVAILABLE"}


def main() -> int:
    sessions = pickle.loads(SESSIONS.read_bytes())
    n = min(1500, len(sessions))
    print(f"Isolation under load n={n}...", flush=True)
    isol = isolation_under_load(sessions, n)
    print(json.dumps({"isolation": isol["TENANT_ISOLATION"], "leaks": isol["leaks"], "tests": isol["tests_executed"]}, indent=2), flush=True)
    print("Security regression...", flush=True)
    try:
        sec = security_regression()
    except SystemExit:
        p = ROOT / "data" / "production_closure" / "phase1_security_regression.json"
        sec = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {"verdict": "FAIL"}
    except Exception as exc:
        # call subprocess style
        import subprocess

        subprocess.run([sys.executable, str(ROOT / "scripts" / "phase1_security_regression.py")], cwd=str(ROOT), check=False)
        p = ROOT / "data" / "production_closure" / "phase1_security_regression.json"
        sec = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {"verdict": "FAIL", "error": str(exc)[:100]}

    out = {
        "generated_at": utc(),
        "tenant_isolation": isol,
        "security_regression": sec,
        "TENANT_ISOLATION": isol["TENANT_ISOLATION"],
        "TENANT_LEAKS": isol["leaks"],
        "SECURITY_REGRESSION": sec.get("verdict"),
    }
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"out": str(OUT), "TENANT_ISOLATION": out["TENANT_ISOLATION"], "SECURITY": out["SECURITY_REGRESSION"]}, indent=2))
    return 0 if isol["TENANT_ISOLATION"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
