#!/usr/bin/env python3
"""Phase 1 performance bench — isolated levels, rebuild sessions, critical APIs."""
from __future__ import annotations

import json
import os
import pickle
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "data" / "production_closure" / "phase1_perf_bench.json"
SESSION_CACHE = ROOT / "data" / "production_closure" / "loadtest_sessions.pkl"
BASE = os.environ.get("NOVUS_LOAD_BASE", "http://127.0.0.1:5000")
LEVELS = [10, 25, 50, 100, 250, 400, 600]
CRITICAL = [
    "/api/dashboard/live",
    "/api/security/summary",
    "/api/tenant/scope",
    "/api/notifications",
    "/api/manual-defense/summary",
    "/api/network/nodes?trigger_discovery=false",
    "/api/security/threats",
    "/api/security/vulnerabilities",
]
P95_LIMIT = 3000.0
TIMEOUT = 15.0
SERVER_THREADS = int(os.environ.get("NOVUS_WAITRESS_THREADS", "64"))


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
    return {
        "ram_pct": round(vm.percent, 1),
        "ram_avail_gb": round(vm.available / (1024**3), 2),
        "cpu_pct": round(psutil.cpu_percent(interval=0.15), 1),
    }


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
            return {"ok": False, "ms": round((time.perf_counter() - t0) * 1000, 2), "error": str(exc)[:80]}

    host_before = host_snapshot()
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=min(n, SERVER_THREADS)) as ex:
        futs = [ex.submit(one, subset[i]) for i in range(n)]
        for fut in as_completed(futs):
            results.append(fut.result())
    elapsed = round((time.perf_counter() - t0) * 1000, 1)
    lat = [r["ms"] for r in results if r.get("ms") is not None]
    oks = sum(1 for r in results if r.get("ok"))
    p95 = pct(lat, 95)
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
        "rps": round(n / (elapsed / 1000.0), 2) if elapsed else 0,
        "host_before": host_before,
        "host_after": host_snapshot(),
    }


def sequential_probe(sessions: list) -> list:
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers

    rec = sessions[0]
    out = []
    for path in CRITICAL:
        samples = []
        codes = []
        for _ in range(5):
            s = requests.Session()
            apply_loadtest_client_headers(s, rec["email"])
            s.cookies.update(rec["cookies"])
            t0 = time.perf_counter()
            try:
                r = s.get(BASE + path, timeout=30)
                codes.append(r.status_code)
                samples.append(round((time.perf_counter() - t0) * 1000, 2))
            except Exception:
                codes.append(0)
                samples.append(30000.0)
        out.append({
            "path": path.split("?")[0],
            "samples": len(samples),
            "p50": pct(samples, 50),
            "p95": pct(samples, 95),
            "p99": pct(samples, 99),
            "max": max(samples),
            "http_codes": codes,
            "ok": all(c == 200 for c in codes),
        })
        print(f"SEQ {path.split('?')[0]} p95={out[-1]['p95']} ok={out[-1]['ok']}", flush=True)
    return out


def main() -> int:
    if not SESSION_CACHE.is_file():
        print("Missing sessions — run scalability_build_loadtest_sessions.py", file=sys.stderr)
        return 2
    sessions = pickle.loads(SESSION_CACHE.read_bytes())
    if len(sessions) < 600:
        print(f"Need 600 sessions, have {len(sessions)}", file=sys.stderr)
        return 2

    report = {
        "generated_at": utc(),
        "host_start": host_snapshot(),
        "sessions": len(sessions),
        "waitress_threads": SERVER_THREADS,
        "sequential": [],
        "levels": [],
    }

    print("Warm + sequential probe...", flush=True)
    reset_guard()
    time.sleep(2)
    report["sequential"] = sequential_probe(sessions)

    for n in LEVELS:
        if n > len(sessions):
            break
        # Cooldown + reset between isolated levels
        time.sleep(25 if n >= 100 else 10)
        reset_guard()
        time.sleep(2)
        for path in [
            "/api/dashboard/live",
            "/api/security/summary",
            "/api/tenant/scope",
            "/api/notifications",
            "/api/manual-defense/summary",
        ]:
            reset_guard()
            time.sleep(1)
            rec = run_level(sessions, path, n)
            report["levels"].append(rec)
            tag = "PASS" if rec["all_ok"] and rec["p95_pass"] else "FAIL"
            print(
                f"[{tag}] n={n} {path} ok={rec['ok']}/{n} p95={rec['p95']} "
                f"429={rec['http_429']} 401={rec['http_401']} tout={rec['timeouts']}",
                flush=True,
            )

    report["host_end"] = host_snapshot()
    crit600 = [r for r in report["levels"] if r.get("n") == 600]
    report["600_CONCURRENT"] = (
        "PASS"
        if crit600 and all(r.get("all_ok") and r.get("p95_pass") for r in crit600)
        else "FAIL"
    )
    seq_notif = next((s for s in report["sequential"] if s["path"] == "/api/notifications"), {})
    seq_def = next((s for s in report["sequential"] if s["path"] == "/api/manual-defense/summary"), {})
    report["notifications_seq_p95"] = seq_notif.get("p95")
    report["manual_defense_seq_p95"] = seq_def.get("p95")
    report["notifications_target_pass"] = (seq_notif.get("p95") or 99999) <= 1000
    report["manual_defense_target_pass"] = (seq_def.get("p95") or 99999) <= 1000

    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({
        "600": report["600_CONCURRENT"],
        "notif_p95": report["notifications_seq_p95"],
        "defense_p95": report["manual_defense_seq_p95"],
        "out": str(OUT),
    }, indent=2))
    return 0 if report["600_CONCURRENT"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
