#!/usr/bin/env python3
"""
Diagnóstico de rendimiento NOVUS — HTTP, DB, CPU, RAM, background.
Genera: data/production_closure/performance_diagnosis.json
NO ejecuta load test masivo — solo mediciones controladas.
"""
from __future__ import annotations

import json
import os
import sqlite3
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "data" / "production_closure" / "performance_diagnosis.json"
BASE = os.environ.get("NOVUS_DIAG_BASE", "http://127.0.0.1:5000")
PROD_EMAIL = os.environ.get("NOVUS_DIAG_EMAIL", "operaciones@novapay-fintech.co")
PROD_PASS = os.environ.get("NOVUS_DIAG_PASSWORD", "NovaPay#Fintech2026")


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


def host_metrics() -> dict:
    import psutil

    vm = psutil.virtual_memory()
    novus_pid = None
    novus_ram = None
    novus_cpu = None
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and getattr(c.laddr, "port", None) == 5000 and c.status == "LISTEN":
            novus_pid = c.pid
            break
    if novus_pid:
        try:
            p = psutil.Process(novus_pid)
            novus_ram = round(p.memory_info().rss / 1024 / 1024, 1)
            novus_cpu = round(p.cpu_percent(interval=0.2), 1)
        except Exception:
            pass
    return {
        "ram_pct": round(vm.percent, 1),
        "ram_available_gb": round(vm.available / (1024**3), 2),
        "cpu_pct": round(psutil.cpu_percent(interval=0.3), 1),
        "novus_pid": novus_pid,
        "novus_ram_mb": novus_ram,
        "novus_cpu_pct": novus_cpu,
    }


def measure_login(session_factory) -> dict:
    import re
    import requests

    times = []
    statuses = []
    for i in range(2):
        s = requests.Session()
        s.headers["User-Agent"] = "NOVUS-Diagnosis/1.0"
        t0 = time.perf_counter()
        r0 = s.get(BASE + "/login", timeout=30)
        csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', r0.text)
        r1 = s.post(
            BASE + "/login",
            data={"email": PROD_EMAIL, "password": PROD_PASS, "csrf_token": csrf.group(1) if csrf else ""},
            timeout=120,
            allow_redirects=False,
        )
        ms = round((time.perf_counter() - t0) * 1000, 2)
        times.append(ms)
        statuses.append(r1.status_code)
    return {
        "samples": len(times),
        "p50_ms": pct(times, 50),
        "p95_ms": pct(times, 95),
        "max_ms": max(times),
        "status_codes": statuses,
    }


def measure_endpoints(session) -> list:
    paths = [
        "/dashboard",
        "/api/dashboard/live",
        "/api/security/summary",
        "/api/tenant/scope",
        "/api/network/nodes?trigger_discovery=false",
        "/api/notifications",
        "/api/manual-defense/summary",
        "/api/security/threats",
        "/api/security/vulnerabilities",
    ]
    rows = []
    for path in paths:
        lat = []
        codes = []
        for _ in range(3):
            t0 = time.perf_counter()
            try:
                r = session.get(BASE + path, timeout=30, allow_redirects=True)
                lat.append(round((time.perf_counter() - t0) * 1000, 2))
                codes.append(r.status_code)
            except Exception as exc:
                lat.append(round((time.perf_counter() - t0) * 1000, 2))
                codes.append(str(exc)[:80])
        rows.append({
            "path": path,
            "p50_ms": pct(lat, 50),
            "p95_ms": pct(lat, 95),
            "p99_ms": pct(lat, 99),
            "max_ms": max(lat) if lat else 0,
            "status_codes": codes,
        })
    return rows


def measure_db() -> dict:
    db_path = ROOT / "novus_vault_v2.db"
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode")
    journal = cur.fetchone()[0]
    queries = [
        ("usuario_by_email", "SELECT id,email,nit_pyme FROM usuarios WHERE email=? LIMIT 1", (PROD_EMAIL,)),
        ("tenant_scope", "SELECT tenant_id,monitoring_enabled FROM tenant_monitoring_scope LIMIT 50", ()),
        ("tenant_count", "SELECT COUNT(*) FROM tenant_monitoring_scope", ()),
        ("evidence_count", "SELECT COUNT(*) FROM platform_evidences", ()),
        ("logs_count", "SELECT COUNT(*) FROM logs", ()),
        ("notifications_count", "SELECT COUNT(*) FROM novus_notifications", ()),
    ]
    results = []
    for label, sql, params in queries:
        lat = []
        for _ in range(20):
            t0 = time.perf_counter()
            if params:
                cur.execute(sql, params)
            else:
                cur.execute(sql)
            cur.fetchall()
            lat.append(round((time.perf_counter() - t0) * 1000, 3))
        results.append({"query": label, "p50_ms": pct(lat, 50), "p95_ms": pct(lat, 95), "max_ms": max(lat)})
    conn.close()
    return {"journal_mode": journal, "queries": results}


def measure_background() -> dict:
    import psutil

    threads = []
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or [])
            if "main.py" in cmd or (p.info.get("name") or "").lower().startswith("python"):
                proc = psutil.Process(p.info["pid"])
                if any("5000" in str(c.laddr) for c in proc.connections(kind="inet") if c.laddr):
                    for t in proc.threads():
                        threads.append({"pid": p.info["pid"], "thread_id": t.id, "user_time": t.user_time})
                    break
        except Exception:
            continue
    return {"novus_thread_count": len(threads), "sample": threads[:15]}


def measure_concurrent_light(session) -> dict:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    path = "/api/dashboard/live"
    n = 25

    def one(_):
        t0 = time.perf_counter()
        try:
            r = session.get(BASE + path, timeout=15)
            return {"ok": r.status_code == 200, "ms": round((time.perf_counter() - t0) * 1000, 2), "http": r.status_code}
        except Exception as exc:
            return {"ok": False, "ms": round((time.perf_counter() - t0) * 1000, 2), "error": str(exc)[:100]}

    before = host_metrics()
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=25) as ex:
        res = list(ex.map(one, range(n)))
    elapsed = round((time.perf_counter() - t0) * 1000, 1)
    after = host_metrics()
    lat = [r["ms"] for r in res]
    return {
        "n": n,
        "path": path,
        "ok": sum(1 for r in res if r.get("ok")),
        "p50_ms": pct(lat, 50),
        "p95_ms": pct(lat, 95),
        "max_ms": max(lat) if lat else 0,
        "elapsed_ms": elapsed,
        "host_before": before,
        "host_after": after,
        "http_codes": [r.get("http") for r in res],
    }


def main() -> int:
    import re
    import requests

    report = {
        "generated_at": utc(),
        "base_url": BASE,
        "host_idle": host_metrics(),
        "login": measure_login(None),
        "db": measure_db(),
        "background": measure_background(),
    }

    s = requests.Session()
    s.headers["User-Agent"] = "NOVUS-Diagnosis/1.0"
    r0 = s.get(BASE + "/login", timeout=30)
    csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', r0.text)
    s.post(
        BASE + "/login",
        data={"email": PROD_EMAIL, "password": PROD_PASS, "csrf_token": csrf.group(1) if csrf else ""},
        timeout=120,
    )
    report["endpoints_sequential"] = measure_endpoints(s)
    report["concurrent_25_single_session"] = measure_concurrent_light(s)

    # Cuello de botella inferido
    bottlenecks = []
    if report["login"]["p95_ms"] > 3000:
        bottlenecks.append({"component": "login", "p95_ms": report["login"]["p95_ms"], "severity": "high"})
    slow_eps = [e for e in report["endpoints_sequential"] if e["p95_ms"] > 3000]
    for e in slow_eps:
        bottlenecks.append({"component": f"http:{e['path']}", "p95_ms": e["p95_ms"], "severity": "high"})
    slow_q = [q for q in report["db"]["queries"] if q["p95_ms"] > 50]
    for q in slow_q:
        bottlenecks.append({"component": f"db:{q['query']}", "p95_ms": q["p95_ms"], "severity": "medium"})
    c25 = report["concurrent_25_single_session"]
    if c25["ok"] < c25["n"] or c25["p95_ms"] > 3000:
        bottlenecks.append({
            "component": "concurrent_25_single_session",
            "ok": f"{c25['ok']}/{c25['n']}",
            "p95_ms": c25["p95_ms"],
            "severity": "critical",
        })
    report["bottlenecks"] = bottlenecks
    report["diagnosis_verdict"] = "NEEDS_FIX" if bottlenecks else "BASELINE_OK"

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"verdict": report["diagnosis_verdict"], "bottlenecks": len(bottlenecks), "out": str(OUT)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
