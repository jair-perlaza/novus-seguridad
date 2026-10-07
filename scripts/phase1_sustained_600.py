#!/usr/bin/env python3
"""Sustained 600-concurrent Phase 1 stability run (default 30 minutes)."""
from __future__ import annotations

import json
import os
import pickle
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

SESSION_CACHE = ROOT / "data" / "production_closure" / "loadtest_sessions.pkl"
OUT = ROOT / "data" / "production_closure" / "phase1_sustained_600.json"
BASE = os.environ.get("NOVUS_LOAD_BASE", "http://127.0.0.1:5000")
N = int(os.environ.get("NOVUS_SUSTAINED_N", "600"))
DURATION_MIN = int(os.environ.get("NOVUS_SUSTAINED_MINUTES", "30"))
PATH = os.environ.get("NOVUS_SUSTAINED_PATH", "/api/notifications")
TIMEOUT = float(os.environ.get("NOVUS_SUSTAINED_TIMEOUT", "15"))
WAVE_PAUSE = float(os.environ.get("NOVUS_SUSTAINED_WAVE_PAUSE", "5"))


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def pct(values, p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return round(s[f], 2)
    return round(s[f] + (s[c] - s[f]) * (k - f), 2)


def host_snap() -> dict:
    import psutil

    vm = psutil.virtual_memory()
    novus = None
    for proc in psutil.process_iter(["pid", "cmdline", "memory_info", "num_threads"]):
        cl = " ".join(proc.info.get("cmdline") or [])
        if "main.py" in cl and "NOVUS" in cl.replace("\\", "/"):
            novus = {
                "pid": proc.pid,
                "rss_mb": round(proc.memory_info().rss / 1e6, 1),
                "threads": proc.num_threads(),
            }
            break
    if novus is None:
        for proc in psutil.process_iter(["pid", "cmdline", "memory_info", "num_threads"]):
            cl = " ".join(proc.info.get("cmdline") or [])
            if cl.endswith("main.py") or " main.py" in cl:
                novus = {
                    "pid": proc.pid,
                    "rss_mb": round(proc.memory_info().rss / 1e6, 1),
                    "threads": proc.num_threads(),
                }
                break
    return {
        "ts": utc(),
        "ram_pct": round(vm.percent, 1),
        "ram_avail_gb": round(vm.available / (1024**3), 2),
        "cpu_pct": round(psutil.cpu_percent(interval=0.1), 1),
        "novus": novus,
    }


def wave(sessions: list, path: str, n: int) -> dict:
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers

    subset = sessions[:n]
    results = []
    counts = {"429": 0, "5xx": 0, "timeout": 0, "401": 0, "ok": 0}
    lock = threading.Lock()

    def one(rec):
        t0 = time.perf_counter()
        s = requests.Session()
        apply_loadtest_client_headers(s, rec["email"])
        s.cookies.update(rec["cookies"])
        try:
            r = s.get(BASE + path, timeout=TIMEOUT)
            ms = round((time.perf_counter() - t0) * 1000, 2)
            with lock:
                if r.status_code == 200:
                    counts["ok"] += 1
                elif r.status_code == 429:
                    counts["429"] += 1
                elif r.status_code == 401:
                    counts["401"] += 1
                elif r.status_code >= 500:
                    counts["5xx"] += 1
            return {"ok": r.status_code == 200, "ms": ms, "http": r.status_code}
        except Exception as exc:
            with lock:
                if "timeout" in str(exc).lower():
                    counts["timeout"] += 1
            return {"ok": False, "ms": round((time.perf_counter() - t0) * 1000, 2), "error": str(exc)[:80]}

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=min(n, 64)) as ex:
        futs = [ex.submit(one, subset[i]) for i in range(n)]
        for fut in as_completed(futs):
            results.append(fut.result())
    elapsed = time.perf_counter() - t0
    lat = [r["ms"] for r in results]
    return {
        "ok": counts["ok"],
        "n": n,
        "p50": pct(lat, 50),
        "p95": pct(lat, 95),
        "p99": pct(lat, 99),
        "max": max(lat) if lat else 0,
        "rps": round(n / elapsed, 2) if elapsed else 0,
        "http_429": counts["429"],
        "http_5xx": counts["5xx"],
        "http_401": counts["401"],
        "timeouts": counts["timeout"],
        "elapsed_ms": round(elapsed * 1000, 1),
        "host": host_snap(),
    }


def main() -> int:
    sessions = pickle.loads(SESSION_CACHE.read_bytes())
    if len(sessions) < N:
        print(f"Need {N} sessions, have {len(sessions)}", file=sys.stderr)
        return 2

    end_waves = DURATION_MIN  # una oleada por minuto nominal
    report = {
        "generated_at": utc(),
        "n": N,
        "path": PATH,
        "duration_min": DURATION_MIN,
        "target_waves": end_waves,
        "minutes": [],
        "host_start": host_snap(),
    }
    print(f"Sustained {N}x {PATH} for {end_waves} waves (~{DURATION_MIN} min)...", flush=True)
    # Warm-up: oleada completa (excluida del veredicto) para llenar caches sin sesgo de cold-start
    warm = wave(sessions, PATH, N)
    report["warmup"] = {k: warm[k] for k in ("ok", "p95", "timeouts", "http_5xx")}
    print(f"warmup ok={warm['ok']}/{N} p95={warm['p95']} tout={warm['timeouts']}", flush=True)
    time.sleep(max(5.0, WAVE_PAUSE))
    for minute in range(1, end_waves + 1):
        rec = wave(sessions, PATH, N)
        rec["minute"] = minute
        report["minutes"].append(rec)
        print(
            f"min={minute} ok={rec['ok']}/{N} p95={rec['p95']} "
            f"tout={rec['timeouts']} 5xx={rec['http_5xx']} 429={rec['http_429']} "
            f"ram={rec['host']['ram_pct']}% thr={((rec['host'].get('novus') or {}).get('threads'))}",
            flush=True,
        )
        OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
        time.sleep(WAVE_PAUSE)

    report["host_end"] = host_snap()
    oks = all(m["ok"] == N and m["timeouts"] == 0 and m["http_5xx"] == 0 for m in report["minutes"])
    p95s = [m["p95"] for m in report["minutes"]]
    report["verdict"] = "PASS" if oks and (max(p95s) if p95s else 99999) <= 3000 else "FAIL"
    report["p95_max"] = max(p95s) if p95s else None
    report["p95_mean"] = round(statistics.mean(p95s), 2) if p95s else None
    thr = [((m.get("host") or {}).get("novus") or {}).get("threads") for m in report["minutes"]]
    thr = [t for t in thr if t is not None]
    report["threads_start"] = thr[0] if thr else None
    report["threads_end"] = thr[-1] if thr else None
    report["thread_growth"] = (thr[-1] - thr[0]) if len(thr) >= 2 else None
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"verdict": report["verdict"], "p95_max": report["p95_max"], "out": str(OUT)}, indent=2))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
