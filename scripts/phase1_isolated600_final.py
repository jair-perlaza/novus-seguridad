#!/usr/bin/env python3
"""Clean isolated-600 for all critical APIs — Phase 1 closure evidence."""
from __future__ import annotations

import json
import os
import pickle
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
os.environ.setdefault("NOVUS_WAITRESS_THREADS", "48")

from scripts.phase1_performance_bench import (  # noqa: E402
    host_snapshot,
    reset_guard,
    run_level,
    sequential_probe,
)

OUT = ROOT / "data" / "production_closure" / "phase1_isolated600_final.json"
BENCH = ROOT / "data" / "production_closure" / "phase1_perf_bench.json"
SESSIONS = ROOT / "data" / "production_closure" / "loadtest_sessions.pkl"

PATHS = [
    "/api/dashboard/live",
    "/api/security/summary",
    "/api/tenant/scope",
    "/api/notifications",
    "/api/manual-defense/summary",
    "/api/network/nodes?trigger_discovery=false",
    "/api/security/threats",
    "/api/security/vulnerabilities",
]


def main() -> int:
    sessions = pickle.loads(SESSIONS.read_bytes())
    if len(sessions) < 600:
        print(f"Need 600 sessions, have {len(sessions)}", file=sys.stderr)
        return 2

    reset_guard()
    time.sleep(3)
    seq = sequential_probe(sessions)
    print("SEQ_OK", all(s["ok"] for s in seq), flush=True)
    if not all(s["ok"] for s in seq):
        print("Sequential probe failed — abort", flush=True)
        return 1

    # Precargar user/tenant caches (600 identidades) antes del stampede
    print("Warming 600 user sessions (tenant/scope)...", flush=True)
    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers

    warm_ok = 0
    warm_lock = threading.Lock()

    def _warm(rec):
        nonlocal warm_ok
        s = requests.Session()
        apply_loadtest_client_headers(s, rec["email"])
        s.cookies.update(rec["cookies"])
        try:
            r = s.get("http://127.0.0.1:5000/api/tenant/scope", timeout=20)
            if r.status_code == 200:
                with warm_lock:
                    warm_ok += 1
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=24) as ex:
        futs = [ex.submit(_warm, sessions[i]) for i in range(600)]
        for fut in as_completed(futs):
            fut.result()
    print(f"Warm user cache ok={warm_ok}/600", flush=True)

    # Segunda pasada de warm (caches / probes) antes del 600
    time.sleep(5)
    seq2 = sequential_probe(sessions)
    print("SEQ2_OK", all(s["ok"] for s in seq2), {s["path"]: s["p95"] for s in seq2}, flush=True)
    time.sleep(12)
    out = []
    for path in PATHS:
        reset_guard()
        time.sleep(5)
        rec = run_level(sessions, path, 600)
        out.append(rec)
        tag = "PASS" if rec["all_ok"] and rec["p95_pass"] else "FAIL"
        print(
            f"[{tag}] {path.split('?')[0]} ok={rec['ok']}/600 p95={rec['p95']} "
            f"tout={rec['timeouts']} 5xx={rec['http_5xx']} 401={rec['http_401']} 429={rec['http_429']}",
            flush=True,
        )
        time.sleep(20)

    all_pass = all(r["all_ok"] and r["p95_pass"] for r in out)
    rep = {
        "sequential": seq,
        "levels": out,
        "host_end": host_snapshot(),
        "all_pass": all_pass,
        "600_CONCURRENT": "PASS" if all_pass else "FAIL",
    }
    OUT.write_text(json.dumps(rep, indent=2), encoding="utf-8")

    bench = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host_start": host_snapshot(),
        "sessions": len(sessions),
        "waitress_threads": 48,
        "sequential": seq,
        "levels": [{**r, "n": 600} for r in out],
        "600_CONCURRENT": rep["600_CONCURRENT"],
        "notifications_seq_p95": next(s["p95"] for s in seq if s["path"] == "/api/notifications"),
        "manual_defense_seq_p95": next(
            s["p95"] for s in seq if s["path"] == "/api/manual-defense/summary"
        ),
        "notifications_target_pass": next(
            s["p95"] for s in seq if s["path"] == "/api/notifications"
        )
        <= 1000,
        "manual_defense_target_pass": next(
            s["p95"] for s in seq if s["path"] == "/api/manual-defense/summary"
        )
        <= 1000,
        "host_end": host_snapshot(),
        "sustained_ref": "phase1_sustained_600_PASS.json",
    }
    BENCH.write_text(json.dumps(bench, indent=2), encoding="utf-8")
    print("ALL_PASS", all_pass, flush=True)
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
