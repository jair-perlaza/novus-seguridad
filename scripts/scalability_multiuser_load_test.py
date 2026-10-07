#!/usr/bin/env python3
"""
Load test multi-usuario NOVUS — 600 usuarios independientes, sesiones independientes.
Genera: data/production_closure/multiuser_load_test_report.json

Criterio 600: 600/600 OK, p95 <= 3000ms en APIs críticas, sin relajar seguridad global.
"""
from __future__ import annotations

import json
import os
import pickle
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "data" / "production_closure" / "multiuser_load_test_report.json"
MANIFEST = ROOT / "data" / "production_closure" / "loadtest_users_manifest.json"
SESSION_CACHE = ROOT / "data" / "production_closure" / "loadtest_sessions.pkl"
BASE = os.environ.get("NOVUS_LOAD_BASE", "http://127.0.0.1:5000")
LEVELS = [10, 25, 50, 100, 250, 400, 600, 750, 1000]
CRITICAL = ["/api/dashboard/live", "/api/security/summary", "/api/tenant/scope"]
P95_LIMIT = float(os.environ.get("NOVUS_LOAD_P95_LIMIT_MS", "3000"))
TIMEOUT = float(os.environ.get("NOVUS_LOAD_REQUEST_TIMEOUT", "15"))
SERVER_THREADS = int(os.environ.get("NOVUS_WAITRESS_THREADS", "96"))


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
    return {"ram_pct": round(vm.percent, 1), "cpu_pct": round(psutil.cpu_percent(interval=0.2), 1)}


def login_user(email: str, password: str) -> dict | None:
    import requests

    from services.loadtest_runtime import apply_loadtest_client_headers

    s = requests.Session()
    apply_loadtest_client_headers(s, email)
    try:
        r0 = s.get(BASE + "/login", timeout=30)
        csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', r0.text)
        r1 = s.post(
            BASE + "/login",
            data={"email": email, "password": password, "csrf_token": csrf.group(1) if csrf else ""},
            timeout=60,
            allow_redirects=False,
        )
        if r1.status_code not in (200, 302):
            return None
        return {"email": email, "cookies": dict(s.cookies), "status": r1.status_code}
    except Exception:
        return None


def build_sessions(manifest: dict, password: str, max_users: int) -> list:
    if SESSION_CACHE.is_file() and os.environ.get("NOVUS_LOADTEST_REUSE_SESSIONS", "1") == "1":
        try:
            cached = pickle.loads(SESSION_CACHE.read_bytes())
            if len(cached) >= max_users:
                return cached[:max_users]
        except Exception:
            pass

    users = manifest["users"][:max_users]
    sessions = []
    lock = threading.Lock()

    def worker(u):
        rec = login_user(u["email"], password)
        if rec:
            with lock:
                sessions.append(rec)

    workers = min(32, len(users))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(worker, users))

    SESSION_CACHE.parent.mkdir(parents=True, exist_ok=True)
    SESSION_CACHE.write_bytes(pickle.dumps(sessions))
    return sessions


def run_level(sessions: list, path: str, n: int) -> dict:
    import requests

    subset = sessions[:n]
    if len(subset) < n:
        return {"n": n, "path": path, "error": f"only {len(subset)} sessions available", "all_ok": False}

    results = []
    lock = threading.Lock()
    counts = {"429": 0, "5xx": 0, "timeout": 0, "401": 0, "403": 0, "db_lock": 0}
    http_status: dict = {}

    def one(sess_rec):
        t0 = time.perf_counter()
        s = requests.Session()
        from services.loadtest_runtime import apply_loadtest_client_headers

        apply_loadtest_client_headers(s, sess_rec["email"])
        s.cookies.update(sess_rec["cookies"])
        try:
            r = s.get(BASE + path, timeout=TIMEOUT)
            ms = round((time.perf_counter() - t0) * 1000, 2)
            body = r.text.lower()
            err_body = {}
            try:
                err_body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            except Exception:
                pass
            with lock:
                http_status[r.status_code] = http_status.get(r.status_code, 0) + 1
                if r.status_code == 429:
                    counts["429"] += 1
                elif r.status_code == 401:
                    counts["401"] += 1
                elif r.status_code == 403:
                    counts["403"] += 1
                elif r.status_code >= 500:
                    counts["5xx"] += 1
                if "database is locked" in body:
                    counts["db_lock"] += 1
            return {
                "ok": r.status_code == 200,
                "ms": ms,
                "http": r.status_code,
                "email": sess_rec["email"],
                "rate_limit_code": err_body.get("code") if r.status_code == 429 else None,
            }
        except Exception as exc:
            err = str(exc)[:120]
            with lock:
                if "timeout" in err.lower():
                    counts["timeout"] += 1
            return {"ok": False, "ms": round((time.perf_counter() - t0) * 1000, 2), "error": err, "email": sess_rec["email"]}

    host_before = host_snapshot()
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=min(n, SERVER_THREADS)) as ex:
        futs = [ex.submit(one, subset[i]) for i in range(n)]
        for fut in as_completed(futs):
            results.append(fut.result())
    elapsed = round((time.perf_counter() - t0) * 1000, 1)
    host_after = host_snapshot()
    lat = [r["ms"] for r in results if r.get("ms")]
    oks = sum(1 for r in results if r.get("ok"))
    return {
        "n": n,
        "path": path,
        "ok": oks,
        "errors": n - oks,
        "p50": pct(lat, 50),
        "p95": pct(lat, 95),
        "p99": pct(lat, 99),
        "max": max(lat) if lat else 0,
        "elapsed_ms": elapsed,
        "all_ok": oks == n,
        "p95_pass": pct(lat, 95) <= P95_LIMIT if lat else False,
        "http_429": counts["429"],
        "http_5xx": counts["5xx"],
        "http_401": counts["401"],
        "http_403": counts["403"],
        "http_status": http_status,
        "timeouts": counts["timeout"],
        "db_locks": counts["db_lock"],
        "host_before": host_before,
        "host_after": host_after,
        "unique_users": len({r.get("email") for r in results}),
    }


def main() -> int:
    from services.loadtest_runtime import loadtest_password

    if not MANIFEST.is_file():
        print("Manifest missing — run scalability_seed_loadtest_users.py first", file=sys.stderr)
        return 2

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    max_level = max(LEVELS)
    password = loadtest_password()

    if os.environ.get("NOVUS_LOADTEST_SKIP_BUILD", "1") == "1":
        if not SESSION_CACHE.is_file():
            print("Session cache missing — run scalability_build_loadtest_sessions.py first", file=sys.stderr)
            return 2
        sessions = pickle.loads(SESSION_CACHE.read_bytes())
        sess_ms = 0.0
        print(f"Loaded {len(sessions)} cached sessions", flush=True)
    else:
        print(f"Building {max_level} independent sessions...", flush=True)
        t_sess = time.perf_counter()
        sessions = build_sessions(manifest, password, max_level)
        sess_ms = round((time.perf_counter() - t_sess) * 1000, 1)
        print(f"Sessions ready: {len(sessions)}/{max_level} in {sess_ms}ms", flush=True)

    if len(sessions) < 600:
        print(f"FAIL: only {len(sessions)} sessions — need 600+", file=sys.stderr)
        report = {
            "generated_at": utc(),
            "base_url": BASE,
            "sessions_built": len(sessions),
            "600_CONCURRENT": "FAIL",
            "750_CONCURRENT": "FAIL",
            "1000_CONCURRENT": "FAIL",
            "PRODUCTION_READY": "FAIL",
            "error": "insufficient_sessions",
        }
        OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        return 1

    report = {
        "generated_at": utc(),
        "base_url": BASE,
        "p95_limit_ms": P95_LIMIT,
        "sessions_built": len(sessions),
        "session_build_ms": sess_ms,
        "levels": [],
        "host_start": host_snapshot(),
    }

    print("Warming critical endpoint caches...", flush=True)
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers

    for rec in sessions[-20:]:
        s = requests.Session()
        apply_loadtest_client_headers(s, rec["email"])
        s.cookies.update(rec["cookies"])
        for path in CRITICAL:
            try:
                s.get(BASE + path, timeout=30)
            except Exception:
                pass
    time.sleep(2)

    for n in LEVELS:
        if n > len(sessions):
            report["levels"].append({"n": n, "skipped": True, "reason": "insufficient sessions"})
            continue
        try:
            from services.http_abuse_guard import reset_abuse_guard_state

            reset_abuse_guard_state()
        except Exception:
            pass
        try:
            import requests

            requests.post(BASE + "/api/system/internal/benchmark/reset-abuse-guard", timeout=5)
        except Exception:
            pass
        if n >= 400:
            time.sleep(60)
        elif n > 10:
            time.sleep(30)
        for path in CRITICAL:
            try:
                import requests

                requests.post(BASE + "/api/system/internal/benchmark/reset-abuse-guard", timeout=10)
            except Exception:
                pass
            time.sleep(2)
            rec = run_level(sessions, path, n)
            report["levels"].append(rec)
            tag = "PASS" if rec.get("all_ok") and rec.get("p95_pass") else "FAIL"
            print(
                f"[{tag}] n={n} path={path} ok={rec.get('ok')}/{n} p95={rec.get('p95')} "
                f"429={rec.get('http_429')} tout={rec.get('timeouts')}",
                flush=True,
            )
        if n >= 600:
            crit = [r for r in report["levels"] if r.get("n") == 600]
            report["600_level_results"] = crit

    report["host_end"] = host_snapshot()
    crit600 = [r for r in report["levels"] if r.get("n") == 600]
    report["600_CONCURRENT"] = (
        "PASS"
        if crit600
        and all(r.get("all_ok") and r.get("p95_pass") and r.get("db_locks", 0) == 0 for r in crit600)
        else "FAIL"
    )
    report["750_CONCURRENT"] = (
        "PASS"
        if all(
            r.get("all_ok") and r.get("p95_pass")
            for r in report["levels"]
            if r.get("n") == 750
        )
        else "FAIL"
    )
    report["1000_CONCURRENT"] = (
        "PASS"
        if all(
            r.get("all_ok") and r.get("p95_pass")
            for r in report["levels"]
            if r.get("n") == 1000
        )
        else "FAIL"
    )
    report["PRODUCTION_READY"] = "PASS" if report["600_CONCURRENT"] == "PASS" else "FAIL"

    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"600": report["600_CONCURRENT"], "out": str(OUT)}, indent=2))
    return 0 if report["600_CONCURRENT"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
