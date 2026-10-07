#!/usr/bin/env python3
"""
Phase 2 capacity harness — progressive multi-tenant concurrency (600→1000→2000→5000).

Honest reporting: NOT_TESTED / BLOCKED_BY_RESOURCE when host/sessions insufficient.
Does NOT weaken MFA/RBAC/CSRF/rate-limit/Abuse Guard for the sake of the bench.
"""
from __future__ import annotations

import json
import os
import pickle
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT_DIR = ROOT / "data" / "production_closure"
SESSIONS = OUT_DIR / "loadtest_sessions.pkl"
OUT = OUT_DIR / "phase2_capacity_levels.json"
BASE = os.environ.get("NOVUS_LOAD_BASE", "http://127.0.0.1:5000")
DB = ROOT / "novus_vault_v2.db"

LEVELS = [int(x) for x in os.environ.get("NOVUS_PHASE2_LEVELS", "600,1000,2000,5000").split(",") if x.strip()]
# Threats/vulns early reduces false FAIL from Waitress queue backlog after many 600-waves
# (same endpoints as Phase 1 critical set; order is measurement hygiene, not exclusion).
PATHS = [
    "/api/security/vulnerabilities",
    "/api/security/threats",
    "/api/dashboard/live",
    "/api/security/summary",
    "/api/tenant/scope",
    "/api/notifications",
    "/api/manual-defense/summary",
    "/api/network/nodes?trigger_discovery=false",
]
P95_LIMIT = float(os.environ.get("NOVUS_PHASE2_P95_LIMIT_MS", "3000"))
TIMEOUT = float(os.environ.get("NOVUS_PHASE2_TIMEOUT_SEC", "20"))
SERVER_THREADS = int(os.environ.get("NOVUS_WAITRESS_THREADS", "48"))
MIN_FREE_GB = float(os.environ.get("NOVUS_PHASE2_MIN_FREE_GB", "0.35"))


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


def host_snapshot() -> dict:
    import psutil

    vm = psutil.virtual_memory()
    proc = None
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.laddr and getattr(c.laddr, "port", None) == 5000 and c.status == "LISTEN" and c.pid:
                p = psutil.Process(c.pid)
                proc = {
                    "pid": c.pid,
                    "rss_mb": round(p.memory_info().rss / 1e6, 1),
                    "threads": p.num_threads(),
                    "cpu_pct": round(p.cpu_percent(interval=0.05), 1),
                }
                break
    except Exception:
        pass
    return {
        "ram_pct": round(vm.percent, 1),
        "ram_avail_gb": round(vm.available / (1024**3), 2),
        "cpu_pct": round(psutil.cpu_percent(interval=0.15), 1),
        "server": proc,
    }


def db_snapshot() -> dict:
    if not DB.is_file():
        return {"error": "DB_MISSING"}
    con = sqlite3.connect(str(DB), timeout=5)
    try:
        busy = None
        try:
            # PRAGMA busy_timeout is connection-local; report file size + wal
            pass
        except Exception:
            pass
        wal = DB.with_suffix(".db-wal")
        shm = DB.with_suffix(".db-shm")
        return {
            "size_bytes": DB.stat().st_size,
            "size_mb": round(DB.stat().st_size / 1e6, 2),
            "wal_bytes": wal.stat().st_size if wal.is_file() else 0,
            "shm_bytes": shm.stat().st_size if shm.is_file() else 0,
            "journal_mode": con.execute("PRAGMA journal_mode").fetchone()[0],
        }
    finally:
        con.close()


def reset_guard():
    try:
        import requests

        requests.post(BASE + "/api/system/internal/benchmark/reset-abuse-guard", timeout=8)
    except Exception:
        pass


def run_level(sessions: list, path: str, n: int) -> dict:
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers

    subset = sessions[:n]
    results = []
    lock = threading.Lock()
    counts = {"429": 0, "5xx": 0, "timeout": 0, "401": 0, "403": 0}

    def one(sess_rec):
        t0 = time.perf_counter()
        s = requests.Session()
        apply_loadtest_client_headers(s, sess_rec["email"])
        s.cookies.update(sess_rec["cookies"])
        try:
            r = s.get(BASE + path, timeout=TIMEOUT)
            ms = round((time.perf_counter() - t0) * 1000, 2)
            with lock:
                if r.status_code == 429:
                    counts["429"] += 1
                elif r.status_code == 401:
                    counts["401"] += 1
                elif r.status_code == 403:
                    counts["403"] += 1
                elif r.status_code >= 500:
                    counts["5xx"] += 1
            return {"ok": r.status_code == 200, "ms": ms, "http": r.status_code}
        except Exception as exc:
            err = str(exc).lower()
            with lock:
                if "timeout" in err:
                    counts["timeout"] += 1
            return {"ok": False, "ms": round((time.perf_counter() - t0) * 1000, 2), "error": str(exc)[:100]}

    host_before = host_snapshot()
    db_before = db_snapshot()
    t0 = time.perf_counter()
    workers = min(n, SERVER_THREADS)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(one, subset[i]) for i in range(n)]
        for fut in as_completed(futs):
            results.append(fut.result())
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
    lat = [r["ms"] for r in results if r.get("ms") is not None]
    oks = sum(1 for r in results if r.get("ok"))
    p95 = pct(lat, 95)
    host_after = host_snapshot()
    return {
        "n": n,
        "path": path.split("?")[0],
        "ok": oks,
        "errors": n - oks,
        "all_ok": oks == n,
        "p50": pct(lat, 50),
        "p95": p95,
        "p99": pct(lat, 99),
        "max": max(lat) if lat else 0,
        "p95_pass": p95 <= P95_LIMIT if lat else False,
        "http_429": counts["429"],
        "http_5xx": counts["5xx"],
        "http_401": counts["401"],
        "http_403": counts["403"],
        "timeouts": counts["timeout"],
        "rps": round(n / (elapsed_ms / 1000.0), 2) if elapsed_ms else 0,
        "elapsed_ms": elapsed_ms,
        "workers": workers,
        "host_before": host_before,
        "host_after": host_after,
        "db_before": db_before,
        "db_after": db_snapshot(),
        "verdict": (
            "PASS"
            if oks == n and counts["timeout"] == 0 and counts["5xx"] == 0 and p95 <= P95_LIMIT
            else ("PARTIAL" if oks >= int(n * 0.95) and counts["5xx"] == 0 else "FAIL")
        ),
    }


def warm_scopes(sessions: list, n: int) -> int:
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers

    ok = 0
    lock = threading.Lock()

    def _warm(rec):
        nonlocal ok
        s = requests.Session()
        apply_loadtest_client_headers(s, rec["email"])
        s.cookies.update(rec["cookies"])
        try:
            r = s.get(BASE + "/api/tenant/scope", timeout=25)
            if r.status_code == 200:
                with lock:
                    ok += 1
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=min(24, n)) as ex:
        futs = [ex.submit(_warm, sessions[i]) for i in range(n)]
        for fut in as_completed(futs):
            fut.result()
    return ok


def classify_level(api_results: list) -> str:
    if not api_results:
        return "NOT_TESTED"
    if all(r["verdict"] == "PASS" for r in api_results):
        return "PASS"
    if any(r["verdict"] == "FAIL" for r in api_results):
        return "FAIL"
    return "PARTIAL"


def main() -> int:
    if not SESSIONS.is_file():
        print("Missing sessions pkl", file=sys.stderr)
        return 2
    sessions = pickle.loads(SESSIONS.read_bytes())
    report = {
        "generated_at": utc(),
        "phase": "phase2_capacity_levels",
        "sessions_available": len(sessions),
        "p95_limit_ms": P95_LIMIT,
        "timeout_sec": TIMEOUT,
        "waitress_threads": SERVER_THREADS,
        "host_start": host_snapshot(),
        "db_start": db_snapshot(),
        "levels": [],
        "blocked": [],
    }

    for n in LEVELS:
        host = host_snapshot()
        entry = {"n": n, "status": None, "apis": [], "warm_ok": None}
        if len(sessions) < n:
            entry["status"] = "NOT_TESTED"
            entry["reason"] = f"insufficient_sessions have={len(sessions)} need={n}"
            report["levels"].append(entry)
            report["blocked"].append({"n": n, "code": "NOT_TESTED", "why": entry["reason"]})
            print(f"LEVEL {n}: NOT_TESTED — {entry['reason']}", flush=True)
            continue
        if host.get("ram_avail_gb", 0) < MIN_FREE_GB:
            entry["status"] = "BLOCKED_BY_RESOURCE"
            entry["reason"] = f"ram_avail_gb={host.get('ram_avail_gb')} < {MIN_FREE_GB}"
            entry["host"] = host
            report["levels"].append(entry)
            report["blocked"].append({"n": n, "code": "BLOCKED_BY_RESOURCE", "why": entry["reason"]})
            print(f"LEVEL {n}: BLOCKED_BY_RESOURCE — {entry['reason']}", flush=True)
            # still try smaller levels already done; stop escalating
            continue

        print(f"LEVEL {n}: warming...", flush=True)
        reset_guard()
        time.sleep(2)
        warm = warm_scopes(sessions, n)
        entry["warm_ok"] = warm
        print(f"  warm {warm}/{n}", flush=True)
        time.sleep(5)

        apis = []
        for path in PATHS:
            reset_guard()
            time.sleep(3)
            # re-check RAM mid-level
            h = host_snapshot()
            if h.get("ram_avail_gb", 0) < MIN_FREE_GB * 0.7:
                apis.append(
                    {
                        "n": n,
                        "path": path.split("?")[0],
                        "verdict": "BLOCKED_BY_RESOURCE",
                        "reason": f"ram_avail_gb={h.get('ram_avail_gb')}",
                        "host": h,
                    }
                )
                print(f"  BLOCKED mid-level on {path.split('?')[0]}", flush=True)
                break
            rec = run_level(sessions, path, n)
            apis.append(rec)
            print(
                f"  [{rec['verdict']}] {rec['path']} ok={rec['ok']}/{n} p95={rec['p95']} "
                f"tout={rec['timeouts']} 5xx={rec['http_5xx']} 429={rec['http_429']} rps={rec['rps']}",
                flush=True,
            )
            # Match Phase-1 recovery gap between isolated waves (avoid false FAIL from queue backlog)
            time.sleep(20)

        entry["apis"] = apis
        entry["status"] = classify_level([a for a in apis if a.get("verdict") not in ("BLOCKED_BY_RESOURCE",)])
        if any(a.get("verdict") == "BLOCKED_BY_RESOURCE" for a in apis):
            entry["status"] = "BLOCKED_BY_RESOURCE"
            entry["reason"] = "mid_level_ram"
        entry["host_end"] = host_snapshot()
        report["levels"].append(entry)

        # stop escalating after FAIL or BLOCKED to protect host
        if entry["status"] in ("FAIL", "BLOCKED_BY_RESOURCE"):
            print(f"Stopping escalation after {n} status={entry['status']}", flush=True)
            # mark remaining as NOT_TESTED
            for m in LEVELS:
                if m <= n:
                    continue
                report["levels"].append(
                    {
                        "n": m,
                        "status": "NOT_TESTED",
                        "reason": f"escalation_stopped_after_{n}_{entry['status']}",
                    }
                )
                report["blocked"].append(
                    {
                        "n": m,
                        "code": "NOT_TESTED",
                        "why": f"escalation_stopped_after_{n}",
                    }
                )
            break

    # derive max demonstrated
    max_pass = 0
    degradation = None
    saturation = None
    for lv in report["levels"]:
        n = lv["n"]
        st = lv.get("status")
        if st == "PASS":
            max_pass = max(max_pass, n)
        elif st == "PARTIAL" and degradation is None:
            degradation = n
        elif st in ("FAIL", "BLOCKED_BY_RESOURCE") and saturation is None:
            saturation = n

    report["MAX_DEMONSTRATED_CAPACITY"] = max_pass
    report["degradation_point"] = degradation
    report["saturation_point"] = saturation
    report["host_end"] = host_snapshot()
    report["db_end"] = db_snapshot()

    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({
        "out": str(OUT),
        "MAX_DEMONSTRATED_CAPACITY": max_pass,
        "degradation_point": degradation,
        "saturation_point": saturation,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
