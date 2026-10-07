#!/usr/bin/env python3
"""
Phase 1 — benchmark APIs críticas + niveles concurrentes aislados.
No desactiva seguridad. Usa sesiones LOADTEST cacheadas.
"""
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
SESS = ROOT / "data" / "production_closure" / "loadtest_sessions.pkl"
BASE = os.environ.get("NOVUS_LOAD_BASE", "http://127.0.0.1:5000")
CRITICAL = [
    "/api/dashboard/live",
    "/api/security/summary",
    "/api/tenant/scope",
    "/api/network/nodes?trigger_discovery=false",
    "/api/security/threats",
    "/api/security/vulnerabilities",
    "/api/notifications",
    "/api/manual-defense/summary",
]
LEVELS = [10, 25, 50, 100, 250, 400, 600]
P95_LIMIT = 3000.0
TIMEOUT = float(os.environ.get("NOVUS_LOAD_REQUEST_TIMEOUT", "15"))
WORKERS = int(os.environ.get("NOVUS_WAITRESS_THREADS", "64"))


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


def host() -> dict:
    import psutil

    vm = psutil.virtual_memory()
    return {
        "ram_pct": round(vm.percent, 1),
        "ram_avail_gb": round(vm.available / (1024**3), 2),
        "cpu_pct": round(psutil.cpu_percent(interval=0.2), 1),
    }


def reset_guard() -> None:
    import requests

    try:
        requests.post(BASE + "/api/system/internal/benchmark/reset-abuse-guard", timeout=8)
    except Exception:
        pass


def run_one(sess_rec: dict, path: str) -> dict:
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers

    t0 = time.perf_counter()
    s = requests.Session()
    apply_loadtest_client_headers(s, sess_rec["email"])
    s.cookies.update(sess_rec["cookies"])
    try:
        r = s.get(BASE + path, timeout=TIMEOUT)
        ms = round((time.perf_counter() - t0) * 1000, 2)
        return {"ok": r.status_code == 200, "http": r.status_code, "ms": ms}
    except Exception as exc:
        err = str(exc)[:120]
        return {
            "ok": False,
            "http": 0,
            "ms": round((time.perf_counter() - t0) * 1000, 2),
            "error": err,
            "timeout": "timeout" in err.lower(),
        }


def run_level(sessions: list, path: str, n: int) -> dict:
    subset = sessions[:n]
    results = []
    counts = {"429": 0, "5xx": 0, "timeout": 0, "401": 0}
    lock = threading.Lock()
    hb = host()
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=min(n, WORKERS)) as ex:
        futs = [ex.submit(run_one, subset[i], path) for i in range(n)]
        for fut in as_completed(futs):
            r = fut.result()
            results.append(r)
            with lock:
                if r.get("http") == 429:
                    counts["429"] += 1
                elif r.get("http") == 401:
                    counts["401"] += 1
                elif (r.get("http") or 0) >= 500:
                    counts["5xx"] += 1
                if r.get("timeout"):
                    counts["timeout"] += 1
    ha = host()
    lat = [r["ms"] for r in results if r.get("ms") is not None]
    oks = sum(1 for r in results if r.get("ok"))
    elapsed = max(0.001, (time.perf_counter() - t0))
    return {
        "n": n,
        "path": path,
        "ok": oks,
        "errors": n - oks,
        "all_ok": oks == n,
        "p50": pct(lat, 50),
        "p95": pct(lat, 95),
        "p99": pct(lat, 99),
        "max": max(lat) if lat else 0,
        "p95_pass": pct(lat, 95) <= P95_LIMIT if lat else False,
        "http_429": counts["429"],
        "http_5xx": counts["5xx"],
        "http_401": counts["401"],
        "timeouts": counts["timeout"],
        "rps": round(n / elapsed, 2),
        "host_before": hb,
        "host_after": ha,
    }


def sequential(sessions: list) -> list:
    out = []
    rec = sessions[0]
    for path in CRITICAL:
        samples = []
        for _ in range(5):
            samples.append(run_one(rec, path))
            time.sleep(0.15)
        lat = [s["ms"] for s in samples]
        out.append(
            {
                "path": path,
                "samples": len(samples),
                "p50": pct(lat, 50),
                "p95": pct(lat, 95),
                "p99": pct(lat, 99),
                "max": max(lat) if lat else 0,
                "http_codes": [s.get("http") for s in samples],
                "ok": all(s.get("ok") for s in samples),
            }
        )
        print(
            f"[SEQ] {path} p95={out[-1]['p95']} ok={out[-1]['ok']}",
            flush=True,
        )
    return out


def wait_host_ready(max_wait: int = 90, ram_target: float = 88.0) -> dict:
    """Espera suave — no bloquea indefinidamente si el host ya satura (~8GB)."""
    import psutil

    deadline = time.time() + max_wait
    last = host()
    best = last
    while time.time() < deadline:
        last = host()
        if last.get("ram_pct", 100) < best.get("ram_pct", 100):
            best = last
        # Con ~8GB, 88% puede ser inalcanzable con NOVUS vivo — aceptar mejor momento
        if last.get("ram_pct", 100) <= ram_target:
            return last
        if last.get("ram_pct", 100) <= ram_target + 4 and last.get("cpu_pct", 100) < 70:
            return last
        time.sleep(2)
    return best


def main() -> int:
    if not SESS.is_file():
        print("missing sessions", file=sys.stderr)
        return 2
    sessions = pickle.loads(SESS.read_bytes())
    if len(sessions) < 600:
        print(f"need 600 sessions, have {len(sessions)}", file=sys.stderr)
        return 2

    report = {
        "generated_at": utc(),
        "host_start": host(),
        "sessions": len(sessions),
        "sequential": [],
        "levels": [],
        "verdict": "NOT_CLOSED",
    }

    print("Warmup...", flush=True)
    reset_guard()
    for rec in sessions[:15]:
        for path in CRITICAL:
            try:
                run_one(rec, path)
            except Exception:
                pass
    time.sleep(3)

    report["sequential"] = sequential(sessions)

    for n in LEVELS:
        if n > len(sessions):
            continue
        print(f"Cooldowning for host ready before n={n}...", flush=True)
        hb = wait_host_ready(max_wait=120 if n >= 100 else 60)
        print(f"Host before n={n}: {hb}", flush=True)
        reset_guard()
        time.sleep(3)
        for path in [
            "/api/dashboard/live",
            "/api/security/summary",
            "/api/tenant/scope",
            "/api/notifications",
        ]:
            reset_guard()
            time.sleep(2)
            # warm path with 5 sessions
            for rec in sessions[:5]:
                try:
                    run_one(rec, path)
                except Exception:
                    pass
            rec = run_level(sessions, path, n)
            report["levels"].append(rec)
            tag = "PASS" if rec["all_ok"] and rec["p95_pass"] and rec["timeouts"] == 0 and rec["http_5xx"] == 0 else "FAIL"
            print(
                f"[{tag}] n={n} {path} ok={rec['ok']}/{n} p95={rec['p95']} "
                f"429={rec['http_429']} tout={rec['timeouts']} 5xx={rec['http_5xx']}",
                flush=True,
            )
        # cooldown after level
        time.sleep(15 if n < 250 else 45)

    report["host_end"] = host()
    crit600 = [r for r in report["levels"] if r.get("n") == 600]
    report["600_ok"] = bool(crit600) and all(
        r.get("all_ok") and r.get("p95_pass") and r.get("timeouts", 0) == 0 and r.get("http_5xx", 0) == 0
        for r in crit600
    )
    notif_seq = next((s for s in report["sequential"] if "/api/notifications" in s["path"]), None)
    report["notifications_p95_seq"] = (notif_seq or {}).get("p95")
    report["notifications_target_met"] = (
        notif_seq is not None and notif_seq.get("p95", 99999) <= 1000
    )
    report["verdict"] = "CLOSED" if report["600_ok"] and report["notifications_target_met"] else "NOT_CLOSED"
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"verdict": report["verdict"], "out": str(OUT)}, indent=2))
    return 0 if report["verdict"] == "CLOSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
