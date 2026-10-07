#!/usr/bin/env python3
"""Smoke latency probe for Phase 1 — sequential, single session."""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

import requests

from services.loadtest_runtime import apply_loadtest_client_headers, loadtest_password

BASE = os.environ.get("NOVUS_LOAD_BASE", "http://127.0.0.1:5000")
APIS = [
    "/api/dashboard/live",
    "/api/security/summary",
    "/api/tenant/scope",
    "/api/network/nodes",
    "/api/security/threats",
    "/api/security/vulnerabilities",
    "/api/notifications",
    "/api/manual-defense/summary",
]


def main() -> int:
    try:
        import psutil

        vm = psutil.virtual_memory()
        print(f"HOST_RAM_PCT={vm.percent} AVAIL_MB={round(vm.available / 1e6, 1)}", flush=True)
        for proc in psutil.process_iter(["pid", "cmdline", "memory_info", "num_threads"]):
            cl = " ".join(proc.info.get("cmdline") or [])
            if "main.py" in cl:
                print(
                    f"NOVUS_PID={proc.pid} RSS_MB={round(proc.memory_info().rss / 1e6, 1)} "
                    f"THREADS={proc.num_threads()}",
                    flush=True,
                )
                break
    except Exception as exc:
        print(f"psutil_skip={exc}", flush=True)

    manifest_path = ROOT / "data" / "production_closure" / "loadtest_users_manifest.json"
    users = json.loads(manifest_path.read_text(encoding="utf-8"))["users"]
    email = users[0]["email"]
    pw = loadtest_password()
    s = requests.Session()
    apply_loadtest_client_headers(s, email)

    t0 = time.perf_counter()
    r0 = s.get(BASE + "/login", timeout=30)
    print(f"LOGIN_GET_MS={round((time.perf_counter() - t0) * 1000, 1)} status={r0.status_code}", flush=True)
    csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', r0.text)
    t1 = time.perf_counter()
    r1 = s.post(
        BASE + "/login",
        data={"email": email, "password": pw, "csrf_token": csrf.group(1) if csrf else ""},
        timeout=60,
        allow_redirects=False,
    )
    print(
        f"LOGIN_POST_MS={round((time.perf_counter() - t1) * 1000, 1)} status={r1.status_code} "
        f"loc={r1.headers.get('Location', '')[:80]}",
        flush=True,
    )
    if r1.status_code not in (200, 302):
        print("LOGIN_FAIL", flush=True)
        return 1

    results = {}
    for path in APIS:
        times = []
        codes = []
        for _ in range(5):
            t = time.perf_counter()
            try:
                r = s.get(BASE + path, timeout=30)
                times.append(round((time.perf_counter() - t) * 1000, 1))
                codes.append(r.status_code)
            except Exception as exc:
                times.append(30000.0)
                codes.append(type(exc).__name__)
        times_sorted = sorted(times)
        row = {
            "codes": codes,
            "p50": times_sorted[2],
            "p95_approx": times_sorted[4],
            "min": times_sorted[0],
            "max": times_sorted[-1],
        }
        results[path] = row
        print(f"{path} {row}", flush=True)

    out = ROOT / "data" / "production_closure" / "phase1_probe_apis.json"
    out.write_text(json.dumps({"email": email, "apis": results}, indent=2), encoding="utf-8")
    print(f"WROTE {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
