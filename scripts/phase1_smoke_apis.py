#!/usr/bin/env python3
"""Quick smoke after Phase1 fixes — sequential critical APIs."""
from __future__ import annotations

import pickle
import sys
import time
from pathlib import Path

ROOT = Path(r"C:\NOVUS")
sys.path.insert(0, str(ROOT))
SESS = ROOT / "data" / "production_closure" / "loadtest_sessions.pkl"
BASE = "http://127.0.0.1:5000"
PATHS = [
    "/api/dashboard/live",
    "/api/security/summary",
    "/api/tenant/scope",
    "/api/network/nodes?trigger_discovery=false",
    "/api/security/threats",
    "/api/security/vulnerabilities",
    "/api/notifications",
    "/api/manual-defense/summary",
]


def main() -> int:
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers

    sessions = pickle.loads(SESS.read_bytes())
    rec = sessions[0]
    try:
        requests.post(BASE + "/api/system/internal/benchmark/reset-abuse-guard", timeout=5)
    except Exception:
        pass
    for path in PATHS:
        times = []
        codes = []
        for _ in range(3):
            s = requests.Session()
            apply_loadtest_client_headers(s, rec["email"])
            s.cookies.update(rec["cookies"])
            t0 = time.perf_counter()
            try:
                r = s.get(BASE + path, timeout=30)
                ms = round((time.perf_counter() - t0) * 1000, 1)
                times.append(ms)
                codes.append(r.status_code)
            except Exception as exc:
                times.append(round((time.perf_counter() - t0) * 1000, 1))
                codes.append(str(exc)[:40])
        print(f"{path} codes={codes} ms={times} max={max(t for t in times if isinstance(t, (int,float)))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
