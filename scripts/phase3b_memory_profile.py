#!/usr/bin/env python3
"""Phase 3B memory profile — samples HOST vs NOVUS vs loadtest client during sustained waves."""
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

OUT = ROOT / "data" / "production_closure" / "phase3b_memory_profile.json"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> int:
    # Reuse phase3 sustained for a short profile run
    n = int(os.environ.get("NOVUS_PHASE3B_PROFILE_N", "600"))
    duration = int(os.environ.get("NOVUS_PHASE3B_PROFILE_SEC", "600"))  # 10 min default
    os.environ["NOVUS_PHASE3_N"] = str(n)
    os.environ["NOVUS_PHASE3_DURATION_SEC"] = str(duration)
    os.environ["NOVUS_PHASE3_LABEL"] = f"profile_n{n}_{duration}s"
    os.environ["NOVUS_PHASE3_WAVE_GAP_SEC"] = os.environ.get("NOVUS_PHASE3_WAVE_GAP_SEC", "12")
    os.environ["NOVUS_PHASE3_DIAGNOSE"] = "0"

    from scripts.phase3_sustained import run_sustained, host_snapshot, reset_guard_diagnostic

    sessions = pickle.loads((ROOT / "data/production_closure/loadtest_sessions.pkl").read_bytes())
    if len(sessions) < n:
        print(f"need {n} sessions", file=sys.stderr)
        return 2

    t0 = time.time()
    marks = {}
    samples = []

    def mark(name):
        h = host_snapshot()
        marks[name] = {"t": utc(), "elapsed_sec": round(time.time() - t0, 1), **h}
        samples.append(marks[name])
        print(f"MARK {name} host={h['ram_pct']}% novus={(h.get('server') or {}).get('rss_mb')} client={(h.get('loadtest_client') or {}).get('rss_mb')}", flush=True)

    reset_guard_diagnostic()
    time.sleep(2)
    mark("RAM_START")

    # run sustained in-process so we share client process for attribution
    result = run_sustained(sessions, n, duration, os.environ["NOVUS_PHASE3_LABEL"])
    mark("RAM_FINAL")

    # derive interval marks from host_samples inside result
    for s in result.get("host_samples") or []:
        samples.append(s)

    novus_rss = [s.get("server", {}).get("rss_mb") for s in samples if s.get("server")]
    host_pct = [s.get("ram_pct") for s in samples if s.get("ram_pct") is not None]
    client_rss = [
        (s.get("loadtest_client") or {}).get("rss_mb")
        for s in samples
        if (s.get("loadtest_client") or {}).get("rss_mb") is not None
    ]

    profile = {
        "generated_at": utc(),
        "n": n,
        "duration_sec": duration,
        "marks": marks,
        "samples": samples,
        "novus_rss_mb": {
            "start": novus_rss[0] if novus_rss else None,
            "final": novus_rss[-1] if novus_rss else None,
            "min": min(novus_rss) if novus_rss else None,
            "max": max(novus_rss) if novus_rss else None,
            "growth": round(novus_rss[-1] - novus_rss[0], 1) if len(novus_rss) >= 2 else None,
        },
        "host_ram_pct": {
            "start": host_pct[0] if host_pct else None,
            "final": host_pct[-1] if host_pct else None,
            "min": min(host_pct) if host_pct else None,
            "max": max(host_pct) if host_pct else None,
            "avg": round(sum(host_pct) / len(host_pct), 1) if host_pct else None,
        },
        "loadtest_client_rss_mb": {
            "start": client_rss[0] if client_rss else None,
            "final": client_rss[-1] if client_rss else None,
            "max": max(client_rss) if client_rss else None,
            "growth": round(client_rss[-1] - client_rss[0], 1) if len(client_rss) >= 2 else None,
        },
        "sustained_verdict": result.get("verdict"),
        "sustained_metrics": {
            "p95": result.get("p95"),
            "timeouts": result.get("timeouts"),
            "http_429": result.get("http_429"),
            "http_5xx": result.get("http_5xx"),
            "TOTAL_CRITICAL_FAILURES": result.get("TOTAL_CRITICAL_FAILURES"),
            "ram_max": result.get("ram_max"),
        },
        "component_table": {
            "novus_core_waitress": "measured via server RSS",
            "db": "NOT_VERIFIABLE_SEPARATE (in-process SQLite in server RSS)",
            "caches": "bounded + TTL purge (see remediations)",
            "sessions_auth_cache": "bounded (NOVUS_USER_CACHE_MAX)",
            "event_bus": "pending_cap env",
            "engines": "LOADTEST paused heavy — NOT_VERIFIABLE growth isolate",
            "loadtest_client": "measured via client RSS",
            "cursor_ide": "HOST_EXTERNAL — see baseline by_category_mb",
            "otros": "HOST_EXTERNAL",
        },
        "root_cause_hypothesis": [
            "Host ~8GB with Cursor (~1.5GB+) + browser leaves <1GB free before load",
            "NOVUS RSS grows under concurrent identity warm (auth/user cache) then should plateau if bounded",
            "Timeouts at host 96–97% are HOST memory pressure / thrashing more than HTTP 5xx application faults",
        ],
    }
    OUT.write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")
    # also save sustained artifact
    sust = ROOT / "data" / "production_closure" / f"phase3_sustained_{os.environ['NOVUS_PHASE3_LABEL']}.json"
    sust.write_text(
        json.dumps({"generated_at": utc(), "result": result}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(json.dumps({"out": str(OUT), "verdict": result.get("verdict"), "novus": profile["novus_rss_mb"], "host": profile["host_ram_pct"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
