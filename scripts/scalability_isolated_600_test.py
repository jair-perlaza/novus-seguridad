#!/usr/bin/env python3
"""Prueba aislada 600 concurrent — sin niveles previos que agoten RAM."""
from __future__ import annotations

import json
import os
import pickle
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from scripts.scalability_multiuser_load_test import (  # noqa: E402
    BASE,
    CRITICAL,
    OUT,
    SESSION_CACHE,
    run_level,
    utc,
    host_snapshot,
)

OUT_ISO = ROOT / "data" / "production_closure" / "isolated_600_report.json"


def main() -> int:
    import requests

    sessions = pickle.loads(SESSION_CACHE.read_bytes())
    if len(sessions) < 600:
        print("Need 600+ sessions", file=sys.stderr)
        return 2

    for _ in range(12):
        snap = host_snapshot()
        if snap.get("ram_pct", 100) < 88:
            break
        time.sleep(10)

    try:
        requests.post(BASE + "/api/system/internal/benchmark/reset-abuse-guard", timeout=10)
    except Exception:
        pass
    time.sleep(5)

    report = {
        "generated_at": utc(),
        "mode": "isolated_600",
        "host_start": host_snapshot(),
        "levels": [],
    }
    n = 600
    for path in CRITICAL:
        try:
            requests.post(BASE + "/api/system/internal/benchmark/reset-abuse-guard", timeout=10)
        except Exception:
            pass
        time.sleep(3)
        rec = run_level(sessions, path, n)
        report["levels"].append(rec)
        print(
            f"[{'PASS' if rec.get('all_ok') and rec.get('p95_pass') else 'FAIL'}] "
            f"n=600 path={path} ok={rec.get('ok')}/600 p95={rec.get('p95')} "
            f"status={rec.get('http_status')} 429={rec.get('http_429')} tout={rec.get('timeouts')}",
            flush=True,
        )

    report["host_end"] = host_snapshot()
    crit = report["levels"]
    report["600_CONCURRENT"] = (
        "PASS"
        if crit
        and all(r.get("all_ok") and r.get("p95_pass") and r.get("db_locks", 0) == 0 for r in crit)
        else "FAIL"
    )
    OUT_ISO.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"600": report["600_CONCURRENT"], "out": str(OUT_ISO)}, indent=2))
    return 0 if report["600_CONCURRENT"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
