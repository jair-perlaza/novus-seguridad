#!/usr/bin/env python3
"""Phase1 isolated concurrent levels — fast host gate, single NOVUS check."""
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

from scripts.phase1_perf_bench import (  # noqa: E402
    CRITICAL,
    host,
    reset_guard,
    run_level,
    run_one,
    sequential,
    utc,
)

OUT = ROOT / "data" / "production_closure" / "phase1_perf_bench.json"
SESS = ROOT / "data" / "production_closure" / "loadtest_sessions.pkl"
PATHS = [
    "/api/dashboard/live",
    "/api/security/summary",
    "/api/tenant/scope",
    "/api/notifications",
]
LEVELS = [10, 25, 50, 100, 250, 400, 600]


def count_novus() -> int:
    import psutil

    n = 0
    root = str(ROOT).replace("\\", "/").lower()
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or []).replace("\\", "/").lower()
            if "main.py" in cmd and root in cmd:
                n += 1
        except (psutil.Error, OSError, TypeError):
            continue
    return n


def main() -> int:
    sessions = pickle.loads(SESS.read_bytes())
    if len(sessions) < 600:
        print("need 600 sessions", file=sys.stderr)
        return 2
    n_proc = count_novus()
    print(f"novus_processes={n_proc}", flush=True)
    if n_proc < 1:
        print("REFUSE: no NOVUS process", file=sys.stderr)
        return 3
    if n_proc > 1:
        print(f"REFUSE: duplicate NOVUS ({n_proc})", file=sys.stderr)
        return 3

    report = {
        "generated_at": utc(),
        "host_start": host(),
        "novus_processes": n_proc,
        "sessions": len(sessions),
        "sequential": [],
        "levels": [],
    }

    print("Warmup (light)...", flush=True)
    reset_guard()
    for rec in sessions[:5]:
        for path in CRITICAL:
            try:
                run_one(rec, path)
            except Exception:
                pass
    time.sleep(2)
    report["sequential"] = sequential(sessions)

    for n in LEVELS:
        print(f"Level n={n} host={host()}", flush=True)
        if count_novus() > 1:
            print("ABORT duplicate", file=sys.stderr)
            break
        reset_guard()
        time.sleep(2)
        for path in PATHS:
            reset_guard()
            for rec in sessions[:3]:
                try:
                    run_one(rec, path)
                except Exception:
                    pass
            rec = run_level(sessions, path, n)
            report["levels"].append(rec)
            tag = (
                "PASS"
                if rec["all_ok"] and rec["p95_pass"] and rec["timeouts"] == 0 and rec["http_5xx"] == 0
                else "FAIL"
            )
            print(
                f"[{tag}] n={n} {path} ok={rec['ok']}/{n} p95={rec['p95']} "
                f"429={rec['http_429']} tout={rec['timeouts']} ram={rec.get('host_after',{}).get('ram_pct')}",
                flush=True,
            )
        time.sleep(10 if n < 250 else 30)

    report["host_end"] = host()
    crit600 = [r for r in report["levels"] if r.get("n") == 600]
    report["600_ok"] = bool(crit600) and all(
        r.get("all_ok") and r.get("p95_pass") and r.get("timeouts", 0) == 0 and r.get("http_5xx", 0) == 0
        for r in crit600
    )
    notif = next((s for s in report["sequential"] if "notifications" in s["path"]), {})
    report["notifications_p95_seq"] = notif.get("p95")
    report["notifications_target_met"] = (notif.get("p95") or 99999) <= 1000
    md = next((s for s in report["sequential"] if "manual-defense" in s["path"]), {})
    report["manual_defense_p95_seq"] = md.get("p95")
    report["verdict"] = (
        "CLOSED" if report["600_ok"] and report["notifications_target_met"] else "NOT_CLOSED"
    )
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(
        json.dumps(
            {
                "verdict": report["verdict"],
                "600_ok": report["600_ok"],
                "notif": report["notifications_p95_seq"],
                "manual": report["manual_defense_p95_seq"],
            },
            indent=2,
        )
    )
    return 0 if report["verdict"] == "CLOSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
