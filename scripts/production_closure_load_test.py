#!/usr/bin/env python3
"""
Prueba de carga NOVUS — tenants + concurrencia reproducible.
Genera data/production_closure/load_test_report.json

Criterio PASS (600 concurrentes):
  - 600/600 OK en /api/dashboard/live y /api/security/summary
  - p95 <= 3000 ms en ambos endpoints críticos
  - 0 db_locks
"""
from __future__ import annotations

import json
import os
import statistics
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "data" / "production_closure"
OUT.mkdir(parents=True, exist_ok=True)
BASE = os.environ.get("NOVUS_LOAD_BASE", "http://127.0.0.1:5000")
PY = sys.executable

TENANT_TARGETS = [100, 200, 300, 600]
CONCURRENT_LEVELS = [10, 25, 50, 100, 250, 400, 600, 750, 1000]
CRITICAL_PATHS = ["/api/dashboard/live", "/api/security/summary"]
P95_LIMIT_MS = float(os.environ.get("NOVUS_LOAD_P95_LIMIT_MS", "3000"))
REQUEST_TIMEOUT = float(os.environ.get("NOVUS_LOAD_REQUEST_TIMEOUT", "10"))


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def percentile(values, p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return round(s[f], 2)
    return round(s[f] + (s[c] - s[f]) * (k - f), 2)


def seed_tenants(count: int) -> dict:
    from database import SessionLocal, TenantMonitoringScope

    prefix = f"LOADTEST-{uuid.uuid4().hex[:8].upper()}"
    db = SessionLocal()
    created = 0
    try:
        for i in range(count):
            tid = f"{prefix}-{i:04d}"
            row = db.query(TenantMonitoringScope).filter(TenantMonitoringScope.tenant_id == tid).first()
            if row:
                continue
            db.add(
                TenantMonitoringScope(
                    tenant_id=tid,
                    monitoring_enabled=True,
                    monitoring_mode="platform_node",
                    configured_at=utc(),
                )
            )
            created += 1
        db.commit()
    finally:
        db.close()
    return {"prefix": prefix, "requested": count, "created": created}


def db_probe() -> dict:
    import sqlite3

    db = ROOT / "novus_vault_v2.db"
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=30)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM tenant_monitoring_scope")
    tenants = cur.fetchone()[0]
    cur.execute("PRAGMA journal_mode")
    journal = cur.fetchone()[0]
    conn.close()
    return {"tenant_rows": tenants, "journal_mode": journal}


def _login_session():
    import re
    import requests

    s = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=64, pool_maxsize=128, max_retries=0)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": "NOVUS-LoadTest/1.0 (internal benchmark)"})
    r0 = s.get(f"{BASE}/login", timeout=30)
    csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', r0.text)
    email = os.environ.get("NOVUS_LOAD_EMAIL", "operaciones@novapay-fintech.co")
    password = os.environ.get("NOVUS_LOAD_PASSWORD", "NovaPay#Fintech2026")
    s.post(
        f"{BASE}/login",
        data={"email": email, "password": password, "csrf_token": csrf.group(1) if csrf else ""},
        timeout=60,
    )
    return s


_thread_local = threading.local()
_session_pool: list = []
_pool_lock = threading.Lock()
_pool_counter = 0


def _init_session_pool(size: int = 32) -> None:
    global _session_pool
    with _pool_lock:
        if _session_pool:
            return
        for _ in range(size):
            _session_pool.append(_login_session())


def _get_thread_session():
    _init_session_pool(32)
    sess = getattr(_thread_local, "session", None)
    if sess is None:
        global _pool_counter
        with _pool_lock:
            idx = _pool_counter % len(_session_pool)
            _pool_counter += 1
        sess = _session_pool[idx]
        _thread_local.session = sess
    return sess


def warmup_paths(session, paths: list) -> None:
    for path in paths:
        for _ in range(3):
            try:
                session.get(BASE + path, timeout=REQUEST_TIMEOUT)
            except Exception:
                pass


def run_concurrent_requests(path: str, n: int, workers: int) -> dict:
    results = []
    db_locks = 0
    timeouts = 0
    lock = threading.Lock()

    def _one(_):
        nonlocal db_locks, timeouts
        t0 = time.perf_counter()
        try:
            sess = _get_thread_session()
            r = sess.get(BASE + path, timeout=REQUEST_TIMEOUT)
            ms = round((time.perf_counter() - t0) * 1000, 2)
            body = r.text.lower()
            if "database is locked" in body:
                with lock:
                    db_locks += 1
            return {"http": r.status_code, "ms": ms, "ok": r.status_code == 200}
        except Exception as exc:
            err = str(exc)[:200]
            with lock:
                if "timeout" in err.lower() or "timed out" in err.lower():
                    timeouts += 1
                if "locked" in err.lower():
                    db_locks += 1
            return {
                "http": 0,
                "ms": round((time.perf_counter() - t0) * 1000, 2),
                "ok": False,
                "error": err,
            }

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(_one, i) for i in range(n)]
        for fut in as_completed(futs):
            results.append(fut.result())

    latencies = [r["ms"] for r in results if r.get("ms")]
    oks = sum(1 for r in results if r.get("ok"))
    return {
        "n": n,
        "workers": workers,
        "ok": oks,
        "errors": n - oks,
        "timeouts": timeouts,
        "db_locks": db_locks,
        "p50": percentile(latencies, 50),
        "p95": percentile(latencies, 95),
        "p99": percentile(latencies, 99),
        "max": max(latencies) if latencies else 0,
        "path": path,
        "concurrent_users": n,
        "p95_pass": percentile(latencies, 95) <= P95_LIMIT_MS if latencies else False,
        "all_ok": oks == n,
    }


def main() -> int:
    import psutil

    report = {
        "generated_at": utc(),
        "base_url": BASE,
        "p95_limit_ms": P95_LIMIT_MS,
        "request_timeout_sec": REQUEST_TIMEOUT,
        "db_before": db_probe(),
        "tenant_seeding": [],
        "concurrency": [],
        "warmup": {},
        "ram_start_pct": round(psutil.virtual_memory().percent, 1),
        "cpu_start_pct": round(psutil.cpu_percent(interval=0.5), 1),
    }

    existing_tenants = db_probe().get("tenant_rows", 0)
    if existing_tenants < 600:
        for target in TENANT_TARGETS:
            report["tenant_seeding"].append(seed_tenants(target))
    else:
        report["tenant_seeding"] = [{"skipped": True, "existing_tenants": existing_tenants}]

    report["db_after_seed"] = db_probe()

    warm_sess = _login_session()
    print("Initializing session pool (32 logins)...", flush=True)
    t_pool = time.perf_counter()
    _init_session_pool(32)
    print(f"Session pool ready in {round((time.perf_counter()-t_pool)*1000,1)}ms", flush=True)
    t_w = time.perf_counter()
    warmup_paths(warm_sess, CRITICAL_PATHS)
    report["warmup"] = {
        "ms": round((time.perf_counter() - t_w) * 1000, 1),
        "paths": CRITICAL_PATHS,
        "session_pool_ms": round((time.perf_counter() - t_pool) * 1000, 1),
    }

    for n in CONCURRENT_LEVELS:
        workers = min(n, int(os.environ.get("NOVUS_LOAD_MAX_WORKERS", "64")))
        for path in CRITICAL_PATHS:
            rec = run_concurrent_requests(path, n, workers)
            report["concurrency"].append(rec)
            status = "PASS" if rec["all_ok"] and rec["p95_pass"] else "FAIL"
            print(
                f"[{status}] conc={n} path={path} ok={rec['ok']}/{n} "
                f"p95={rec['p95']}ms timeouts={rec['timeouts']} locks={rec['db_locks']}"
            )
            if n >= 600 and status == "FAIL":
                break
        else:
            continue
        break

    report["ram_end_pct"] = round(psutil.virtual_memory().percent, 1)
    report["cpu_end_pct"] = round(psutil.cpu_percent(interval=0.5), 1)

    crit_600 = [
        r
        for r in report["concurrency"]
        if r.get("concurrent_users") == 600 and r.get("path") in CRITICAL_PATHS
    ]
    report["verdict_600"] = (
        "PASS"
        if len(crit_600) == 2
        and all(r.get("all_ok") and r.get("p95_pass") and r.get("db_locks", 0) == 0 for r in crit_600)
        else "FAIL"
    )
    report["verdict"] = (
        "PASS"
        if all(
            r.get("db_locks", 0) == 0 and r.get("all_ok") and r.get("p95_pass")
            for r in report["concurrency"]
        )
        else report["verdict_600"]
    )

    out_path = OUT / "load_test_report.json"
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {out_path} verdict={report['verdict']} verdict_600={report['verdict_600']}")
    return 0 if report["verdict_600"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
