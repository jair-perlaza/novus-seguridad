#!/usr/bin/env python3
"""
Phase 3 sustained multi-tenant capacity harness.

Simultaneous real sessions for N minutes, rotating critical APIs.
Abuse Guard stays ON. Between levels, only diagnostic counter reset
(existing /api/system/internal/benchmark/reset-abuse-guard) so prior
bench waves do not poison the next measurement — does not change limits.
"""
from __future__ import annotations

import json
import os
import pickle
import sqlite3
import sys
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT_DIR = ROOT / "data" / "production_closure"
SESSIONS = OUT_DIR / "loadtest_sessions.pkl"
BASE = os.environ.get("NOVUS_LOAD_BASE", "http://127.0.0.1:5000")
DB = ROOT / "novus_vault_v2.db"

CRITICAL_PATHS = [
    "/api/tenant/scope",
    "/api/dashboard/live",
    "/api/security/summary",
    "/api/notifications",
    "/api/manual-defense/summary",
    "/api/network/nodes?trigger_discovery=false",
    "/api/security/threats",
    "/api/security/vulnerabilities",
]

SERVER_THREADS = int(os.environ.get("NOVUS_WAITRESS_THREADS", "48"))
REQ_TIMEOUT = float(os.environ.get("NOVUS_PHASE3_TIMEOUT_SEC", "20"))
P95_LIMIT = float(os.environ.get("NOVUS_PHASE3_P95_LIMIT_MS", "3000"))
# Per-user think time: avoid turning every concurrent user into a flood bot
MIN_INTERVAL_SEC = float(os.environ.get("NOVUS_PHASE3_USER_INTERVAL_SEC", "2.5"))


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
    server = None
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.laddr and getattr(c.laddr, "port", None) == 5000 and c.status == "LISTEN" and c.pid:
                p = psutil.Process(c.pid)
                mi = p.memory_info()
                server = {
                    "pid": c.pid,
                    "rss_mb": round(mi.rss / 1e6, 1),
                    "vms_mb": round(getattr(mi, "vms", 0) / 1e6, 1),
                    "threads": p.num_threads(),
                }
                break
    except Exception:
        pass
    client = None
    try:
        me = psutil.Process()
        mi = me.memory_info()
        client = {
            "pid": me.pid,
            "rss_mb": round(mi.rss / 1e6, 1),
            "threads": me.num_threads(),
        }
    except Exception:
        pass
    return {
        "ram_pct": round(vm.percent, 1),
        "ram_avail_gb": round(vm.available / (1024**3), 2),
        "cpu_pct": round(psutil.cpu_percent(interval=0.2), 1),
        "server": server,
        "loadtest_client": client,
    }


def db_size() -> dict:
    if not DB.is_file():
        return {}
    wal = DB.with_suffix(DB.suffix + "-wal") if False else Path(str(DB) + "-wal")
    return {
        "size_bytes": DB.stat().st_size,
        "size_mb": round(DB.stat().st_size / 1e6, 2),
        "wal_bytes": wal.stat().st_size if wal.is_file() else 0,
    }


def reset_guard_diagnostic():
    """Clear in-memory flood windows between levels — does NOT raise configured limits."""
    try:
        import requests

        r = requests.post(BASE + "/api/system/internal/benchmark/reset-abuse-guard", timeout=8)
        return r.status_code
    except Exception as exc:
        return f"error:{exc}"


def diagnose_429_sample(sessions: list, n: int = 200) -> dict:
    """Burst probe to capture Abuse Guard bucket codes (evidence, not a pass criterion)."""
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers

    buckets = Counter()
    codes = Counter()
    samples = []

    def one(rec):
        s = requests.Session()
        apply_loadtest_client_headers(s, rec["email"])
        s.cookies.update(rec["cookies"])
        try:
            r = s.get(BASE + "/api/tenant/scope", timeout=15)
            body = {}
            try:
                body = r.json()
            except Exception:
                pass
            return {
                "http": r.status_code,
                "code": body.get("code"),
                "bucket": body.get("bucket"),
                "message": (body.get("message") or "")[:80],
            }
        except Exception as exc:
            return {"http": 0, "error": str(exc)[:80]}

    with ThreadPoolExecutor(max_workers=min(n, SERVER_THREADS)) as ex:
        futs = [ex.submit(one, sessions[i]) for i in range(min(n, len(sessions)))]
        for fut in as_completed(futs):
            rec = fut.result()
            codes[rec.get("http")] += 1
            if rec.get("bucket"):
                # normalize sess hashes
                b = str(rec["bucket"])
                if b.startswith("sess:"):
                    buckets["sess:*"] += 1
                elif b.startswith("ip-nat"):
                    buckets[b.split(":")[0] + ":*"] += 1
                else:
                    buckets[b] += 1
            if rec.get("http") == 429 and len(samples) < 8:
                samples.append(rec)
    return {"n": n, "http_codes": dict(codes), "buckets": dict(buckets), "samples_429": samples}


def run_sustained(sessions: list, n: int, duration_sec: int, label: str) -> dict:
    """
    Sustained concurrency: every WAVE_GAP seconds, fire one authenticated request
    from each of N tenant sessions (Phase-2 isolated-wave model), rotating APIs,
    for the full duration. Client concurrency capped at Waitress threads.
    """
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers

    subset = sessions[:n]
    stop_at = time.time() + duration_sec
    lock = threading.Lock()
    latencies: list = []
    by_path: dict = defaultdict(list)
    http_codes = Counter()
    codes_429_body = Counter()
    errors = Counter()
    active_users = set()
    completed = 0
    failed = 0
    samples_host = []
    threads_samples = []
    wave_summaries = []
    start_host = host_snapshot()
    start_db = db_size()
    start_threads = (start_host.get("server") or {}).get("threads")
    crash = False
    server_gone = False
    critical = []
    critical_counts = Counter()
    client_workers = min(n, SERVER_THREADS)
    wave_gap = float(os.environ.get("NOVUS_PHASE3_WAVE_GAP_SEC", str(max(MIN_INTERVAL_SEC, 8.0))))
    path_rot = 0

    mon_stop = threading.Event()

    def monitor():
        nonlocal server_gone, crash
        while not mon_stop.wait(15):
            h = host_snapshot()
            with lock:
                samples_host.append({"t": utc(), **h})
                thr = (h.get("server") or {}).get("threads")
                if thr is not None:
                    threads_samples.append(thr)
                if not h.get("server"):
                    server_gone = True
                    crash = True
                    critical_counts["server_gone"] += 1
                    if len(critical) < 50:
                        critical.append({"type": "server_gone", "t": utc()})

    mon = threading.Thread(target=monitor, daemon=True)
    mon.start()

    # Windows Waitress uses select() — keep-alive to hundreds of clients exhausts FDs.
    # Cap concurrent client connections to Waitress thread count via thread-local Session.
    _tls = threading.local()

    def get_session(rec):
        s = getattr(_tls, "session", None)
        if s is None:
            s = requests.Session()
            s.headers["Connection"] = "close"
            _tls.session = s
        apply_loadtest_client_headers(s, rec["email"])
        s.cookies.clear()
        s.cookies.update(rec["cookies"])
        return s

    def one(rec, path):
        nonlocal completed, failed, crash
        s = get_session(rec)
        t0 = time.perf_counter()
        try:
            r = s.get(BASE + path, timeout=REQ_TIMEOUT)
            ms = (time.perf_counter() - t0) * 1000
            with lock:
                latencies.append(ms)
                by_path[path.split("?")[0]].append(ms)
                http_codes[r.status_code] += 1
                active_users.add(rec["email"])
                if r.status_code == 200:
                    completed += 1
                else:
                    failed += 1
                    if r.status_code == 429:
                        try:
                            body = r.json()
                            codes_429_body[body.get("code") or "UNKNOWN"] += 1
                        except Exception:
                            codes_429_body["UNPARSEABLE"] += 1
                    if r.status_code >= 500:
                        critical_counts["http_5xx"] += 1
                        if len(critical) < 50:
                            critical.append({"type": "http_5xx", "path": path, "http": r.status_code})
            return r.status_code, ms
        except Exception as exc:
            ms = (time.perf_counter() - t0) * 1000
            err = str(exc).lower()
            with lock:
                latencies.append(ms)
                failed += 1
                active_users.add(rec["email"])
                if "timeout" in err:
                    errors["timeout"] += 1
                    critical_counts["timeout"] += 1
                    if len(critical) < 50:
                        critical.append({"type": "timeout", "path": path})
                elif "connection" in err or "max retries" in err:
                    errors["connection"] += 1
                    critical_counts["connection"] += 1
                    # Do not mark whole run crash=True for transient connection blips
                    if len(critical) < 50:
                        critical.append({"type": "connection", "error": str(exc)[:80]})
                else:
                    errors["other"] += 1
            return 0, ms

    t0 = time.perf_counter()
    wave_i = 0
    while time.time() < stop_at and not server_gone:
        path = CRITICAL_PATHS[path_rot % len(CRITICAL_PATHS)]
        path_rot += 1
        wave_i += 1
        w_ok = 0
        w_fail = 0
        w_lat = []
        wt0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=client_workers) as ex:
            futs = [ex.submit(one, subset[i], path) for i in range(n)]
            for fut in as_completed(futs):
                code, ms = fut.result()
                w_lat.append(ms)
                if code == 200:
                    w_ok += 1
                else:
                    w_fail += 1
        w_elapsed = time.perf_counter() - wt0
        wave_summaries.append(
            {
                "wave": wave_i,
                "path": path.split("?")[0],
                "ok": w_ok,
                "fail": w_fail,
                "p95": pct(w_lat, 95),
                "elapsed_sec": round(w_elapsed, 2),
            }
        )
        print(
            f"  wave {wave_i} {path.split('?')[0]} ok={w_ok}/{n} p95={pct(w_lat,95)} "
            f"fail={w_fail} elapsed={w_elapsed:.1f}s",
            flush=True,
        )
        # gap between waves (stability, not flood)
        remain = stop_at - time.time()
        if remain <= 0:
            break
        time.sleep(min(wave_gap, max(0.0, remain)))

    elapsed = time.perf_counter() - t0
    mon_stop.set()

    end_host = host_snapshot()
    end_db = db_size()
    end_threads = (end_host.get("server") or {}).get("threads")
    total_req = completed + failed
    p95 = pct(latencies, 95)
    p99 = pct(latencies, 99)
    timeouts = errors.get("timeout", 0)
    http_5xx = sum(c for code, c in http_codes.items() if isinstance(code, int) and code >= 500)
    http_429 = http_codes.get(429, 0)
    http_4xx = sum(c for code, c in http_codes.items() if isinstance(code, int) and 400 <= code < 500)

    path_stats = {}
    for p, vals in by_path.items():
        path_stats[p] = {
            "n": len(vals),
            "p50": pct(vals, 50),
            "p95": pct(vals, 95),
            "p99": pct(vals, 99),
        }

    ram_samples = [s.get("ram_pct") for s in samples_host if s.get("ram_pct") is not None]
    cpu_samples = [s.get("cpu_pct") for s in samples_host if s.get("cpu_pct") is not None]
    thr_all = threads_samples[:]
    if start_threads is not None:
        thr_all = [start_threads] + thr_all
    if end_threads is not None:
        thr_all = thr_all + [end_threads]

    total_critical = int(
        critical_counts.get("http_5xx", 0)
        + critical_counts.get("timeout", 0)
        + critical_counts.get("connection", 0)
        + critical_counts.get("server_gone", 0)
        + critical_counts.get("worker_crash", 0)
    )
    critical_trim = critical[:50]

    ok_ratio = (completed / total_req) if total_req else 0.0
    waves_all_ok = all(w["ok"] == n and w["fail"] == 0 for w in wave_summaries) if wave_summaries else False
    stable = (
        not crash
        and not server_gone
        and http_5xx == 0
        and timeouts == 0
        and http_429 == 0
        and p95 <= P95_LIMIT
        and ok_ratio >= 0.995
        and len(active_users) >= int(n * 0.98)
        and (end_threads is None or start_threads is None or end_threads <= start_threads + 40)
        and total_critical == 0
        and waves_all_ok
    )

    if http_429 > 0 and http_5xx == 0 and not server_gone and critical_counts.get("connection", 0) == 0:
        verdict = "SATURATED_OR_THROTTLED"
    elif stable:
        verdict = "STABLE"
    elif http_5xx > 0 or server_gone or total_critical > int(max(total_req, 1) * 0.01):
        verdict = "FAIL"
    else:
        verdict = "DEGRADED"

    return {
        "label": label,
        "n": n,
        "duration_sec": duration_sec,
        "elapsed_sec": round(elapsed, 1),
        "waves": len(wave_summaries),
        "wave_gap_sec": wave_gap,
        "wave_summaries": wave_summaries,
        "tenants_concurrent": n,
        "users_concurrent": n,
        "sessions_concurrent": n,
        "users_active_observed": len(active_users),
        "requests_total": total_req,
        "requests_completed_200": completed,
        "requests_failed": failed,
        "rps": round(total_req / elapsed, 2) if elapsed else 0,
        "p50": pct(latencies, 50),
        "p95": p95,
        "p99": p99,
        "max_ms": round(max(latencies), 2) if latencies else 0,
        "timeouts": timeouts,
        "http_429": http_429,
        "http_4xx": http_4xx,
        "http_5xx": http_5xx,
        "http_codes": {str(k): v for k, v in http_codes.items()},
        "codes_429_body": dict(codes_429_body),
        "path_stats": path_stats,
        "host_start": start_host,
        "host_end": end_host,
        "host_samples": samples_host[-20:],
        "cpu_avg": round(sum(cpu_samples) / len(cpu_samples), 1) if cpu_samples else None,
        "cpu_max": max(cpu_samples) if cpu_samples else None,
        "ram_avg": round(sum(ram_samples) / len(ram_samples), 1) if ram_samples else None,
        "ram_max": max(ram_samples) if ram_samples else None,
        "ram_min": min(ram_samples) if ram_samples else None,
        "threads_start": start_threads,
        "threads_end": end_threads,
        "threads_max": max(thr_all) if thr_all else None,
        "db_start": start_db,
        "db_end": end_db,
        "db_growth_bytes": (end_db.get("size_bytes") or 0) - (start_db.get("size_bytes") or 0),
        "TOTAL_CRITICAL_FAILURES": total_critical,
        "critical_counts": dict(critical_counts),
        "critical_events_sample": critical_trim,
        "client_workers": client_workers,
        "verdict": verdict,
        "stable": stable,
        "user_interval_sec": MIN_INTERVAL_SEC,
        "model_note": "Repeated N-concurrent isolated waves (max_workers=Waitress threads) for full duration; rotates critical APIs",
    }


def main() -> int:
    n = int(os.environ.get("NOVUS_PHASE3_N", "1000"))
    duration = int(os.environ.get("NOVUS_PHASE3_DURATION_SEC", "300"))
    label = os.environ.get("NOVUS_PHASE3_LABEL", f"n{n}_{duration}s")
    diagnose = os.environ.get("NOVUS_PHASE3_DIAGNOSE", "1") == "1"

    if not SESSIONS.is_file():
        print("Missing sessions", file=sys.stderr)
        return 2
    sessions = pickle.loads(SESSIONS.read_bytes())
    if len(sessions) < n:
        print(f"Need {n} sessions, have {len(sessions)}", file=sys.stderr)
        return 2

    report = {
        "generated_at": utc(),
        "phase": "phase3_sustained",
        "sessions_available": len(sessions),
        "config": {
            "n": n,
            "duration_sec": duration,
            "user_interval_sec": MIN_INTERVAL_SEC,
            "p95_limit_ms": P95_LIMIT,
            "timeout_sec": REQ_TIMEOUT,
            "waitress_threads": SERVER_THREADS,
        },
    }

    print(f"reset_guard={reset_guard_diagnostic()}", flush=True)
    time.sleep(3)
    # Warm critical paths once (platform caches / user loader) before timed waves
    print("Warming critical APIs (sequential)...", flush=True)
    try:
        import requests
        from services.loadtest_runtime import apply_loadtest_client_headers

        warm = sessions[0]
        s = requests.Session()
        apply_loadtest_client_headers(s, warm["email"])
        s.cookies.update(warm["cookies"])
        s.headers["Connection"] = "close"
        for path in CRITICAL_PATHS:
            try:
                s.get(BASE + path, timeout=30)
            except Exception:
                pass
        # light concurrent warm of tenant/scope for first N identities (cap workers)
        def _w(rec):
            ss = requests.Session()
            apply_loadtest_client_headers(ss, rec["email"])
            ss.cookies.update(rec["cookies"])
            ss.headers["Connection"] = "close"
            try:
                ss.get(BASE + "/api/tenant/scope", timeout=20)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=min(24, n)) as ex:
            list(ex.map(_w, sessions[:n]))
    except Exception as exc:
        print(f"warm_warn: {exc}", flush=True)
    reset_guard_diagnostic()
    time.sleep(5)
    if diagnose:
        print("Diagnosing 429 buckets (burst sample)...", flush=True)
        # warm-ish burst
        d = diagnose_429_sample(sessions, min(n, 400))
        report["abuse_guard_diagnosis_pre"] = d
        print(json.dumps(d, indent=2), flush=True)
        reset_guard_diagnostic()
        time.sleep(5)

    print(f"SUSTAINED n={n} duration={duration}s label={label}", flush=True)
    result = run_sustained(sessions, n, duration, label)
    report["result"] = result
    report["host_final"] = host_snapshot()

    out = OUT_DIR / f"phase3_sustained_{label}.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(
        json.dumps(
            {
                "out": str(out),
                "verdict": result["verdict"],
                "stable": result["stable"],
                "p95": result["p95"],
                "rps": result["rps"],
                "429": result["http_429"],
                "5xx": result["http_5xx"],
                "timeouts": result["timeouts"],
                "critical": result["TOTAL_CRITICAL_FAILURES"],
                "active_users": result["users_active_observed"],
            },
            indent=2,
        )
    )
    return 0 if result["verdict"] in ("STABLE", "DEGRADED", "SATURATED_OR_THROTTLED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
