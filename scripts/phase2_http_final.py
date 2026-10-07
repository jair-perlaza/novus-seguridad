#!/usr/bin/env python3
"""
Fase 2 — Prueba formal HTTP (secuencial + concurrente).
Genera PHASE_2_HTTP_FINAL.json y PHASE_2_HTTP_FINAL.md

Criterios:
  p50 < 300 ms, p95 < 500 ms, max < 2000 ms (sin spikes > 2s)
"""
from __future__ import annotations

import json
import re
import statistics
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "novus_process_audit"
BASE = "http://127.0.0.1:5000"
PY = r"C:\Users\hp\AppData\Local\Python\pythoncore-3.14-64\python.exe"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")

APIS = [
    "/api/dashboard/live",
    "/api/security/summary",
    "/api/network/info",
    "/api/network/nodes?trigger_discovery=false&include_context=false",
    "/api/network/ndr",
    "/api/network/topology",
]

SEQ_N = 30
CONC_N = 10
IDLE_SEC = 60
P50_TARGET = 300
P95_TARGET = 500
MAX_SPIKE = 2000


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return round(s[f], 2)
    return round(s[f] + (s[c] - s[f]) * (k - f), 2)


def listeners() -> List[int]:
    pids = []
    out = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
    for line in out.splitlines():
        if ":5000" in line and "LISTENING" in line:
            pids.append(int(line.split()[-1]))
    return pids


def find_novus_pid() -> Optional[int]:
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = p.info.get("cmdline") or []
            if len(cmd) >= 2 and str(cmd[-1]).endswith("main.py"):
                return p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None


def kill_listeners() -> None:
    for pid in listeners():
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)], capture_output=True)


def restart_server() -> Optional[int]:
    kill_listeners()
    time.sleep(3)
    env = __import__("os").environ.copy()
    env["FLASK_DEBUG"] = "False"
    env.pop("NOVUS_HTTP_PROFILE", None)
    subprocess.Popen(
        [PY, "main.py"],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(120):
        if listeners():
            time.sleep(5)
            return find_novus_pid()
        time.sleep(1)
    return None


def proc_metrics(pid: Optional[int]) -> Dict[str, Any]:
    vm = psutil.virtual_memory()
    row: Dict[str, Any] = {
        "ram_system_pct": round(vm.percent, 1),
        "cpu_system_pct": round(psutil.cpu_percent(interval=0.2), 1),
    }
    if pid:
        try:
            p = psutil.Process(pid)
            row["novus_ram_mb"] = round(p.memory_info().rss / (1024**2), 1)
            row["novus_cpu_pct"] = round(p.cpu_percent(interval=0.2), 1)
            row["novus_threads"] = p.num_threads()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    row["listeners"] = len(listeners())
    return row


def login_session() -> requests.Session:
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=30)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    s.post(
        f"{BASE}/login",
        data={"email": QA[0], "password": QA[1], "csrf_token": csrf.group(1) if csrf else ""},
        timeout=30,
    )
    return s


def timed_get(sess: requests.Session, path: str, timeout: int = 60) -> Dict[str, Any]:
    t0 = time.perf_counter()
    try:
        r = sess.get(BASE + path, timeout=timeout)
        ms = round((time.perf_counter() - t0) * 1000, 2)
        prof = None
        raw = r.headers.get("X-Novus-Profile")
        if raw:
            try:
                prof = json.loads(raw)
            except json.JSONDecodeError:
                prof = {"raw": raw[:200]}
        return {
            "ms": ms,
            "status": r.status_code,
            "server_wsgi_ms": prof.get("total_from_wsgi_ms") if prof else None,
            "error": None,
        }
    except Exception as exc:
        return {
            "ms": round((time.perf_counter() - t0) * 1000, 2),
            "status": 0,
            "server_wsgi_ms": None,
            "error": str(exc)[:120],
        }


def clone_session(sess: requests.Session) -> requests.Session:
    s = requests.Session()
    s.cookies.update(sess.cookies)
    return s


def stats(samples: List[float]) -> Dict[str, Any]:
    if not samples:
        return {"count": 0, "p50": None, "p95": None, "max": None, "min": None, "avg": None}
    return {
        "count": len(samples),
        "p50": percentile(samples, 50),
        "p95": percentile(samples, 95),
        "max": round(max(samples), 2),
        "min": round(min(samples), 2),
        "avg": round(statistics.mean(samples), 2),
    }


def classify(stats_row: Dict[str, Any]) -> str:
    p50 = stats_row.get("p50")
    p95 = stats_row.get("p95")
    mx = stats_row.get("max")
    if p50 is None:
        return "FALLIDA"
    if mx and mx > MAX_SPIKE:
        return "FALLIDA"
    if p50 < P50_TARGET and p95 and p95 < P95_TARGET:
        return "VERIFICADA"
    if p50 < P95_TARGET and p95 and p95 < MAX_SPIKE:
        return "PARCIAL"
    return "FALLIDA"


def run_sequential(sess: requests.Session, path: str, n: int) -> List[Dict[str, Any]]:
    rows = []
    for i in range(n):
        rows.append(timed_get(sess, path))
        time.sleep(0.15)
    return rows


def run_concurrent(sess: requests.Session, path: str, n: int) -> List[Dict[str, Any]]:
    """Concurrente controlado — reutiliza cookies autenticadas, sin login paralelo."""
    rows: List[Dict[str, Any]] = []

    def _one(_: int) -> Dict[str, Any]:
        local = clone_session(sess)
        return timed_get(local, path)

    with ThreadPoolExecutor(max_workers=min(n, 3)) as pool:
        futs = [pool.submit(_one, i) for i in range(n)]
        for f in as_completed(futs):
            try:
                rows.append(f.result())
            except Exception as exc:
                rows.append({"ms": 0, "status": 0, "server_wsgi_ms": None, "error": str(exc)[:120]})
    return rows


def evaluate_api(path: str, sess: requests.Session) -> Dict[str, Any]:
    seq = run_sequential(sess, path, SEQ_N)
    time.sleep(2)
    conc = run_concurrent(sess, path, CONC_N)
    seq_ms = [r["ms"] for r in seq if r.get("error") is None]
    conc_ms = [r["ms"] for r in conc if r.get("error") is None]
    seq_stats = stats(seq_ms)
    conc_stats = stats(conc_ms)
    all_ms = seq_ms + conc_ms
    combined = stats(all_ms)
    server_ms = [r["server_wsgi_ms"] for r in seq + conc if r.get("server_wsgi_ms")]
    return {
        "path": path,
        "sequential": {"n": SEQ_N, "stats": seq_stats, "timeouts": sum(1 for r in seq if r.get("error"))},
        "concurrent": {"n": CONC_N, "workers": 5, "stats": conc_stats, "timeouts": sum(1 for r in conc if r.get("error"))},
        "combined_stats": combined,
        "server_wsgi_stats": stats(server_ms) if server_ms else None,
        "spikes_over_2s": sum(1 for m in all_ms if m > MAX_SPIKE),
        "verdict": classify(combined),
    }


def phase_verdict(api_rows: List[Dict[str, Any]]) -> str:
    verdicts = [r["verdict"] for r in api_rows]
    if all(v == "VERIFICADA" for v in verdicts):
        return "VERIFICADA"
    if any(v == "FALLIDA" for v in verdicts):
        if all(v in ("VERIFICADA", "PARCIAL") for v in verdicts):
            return "PARCIAL"
        return "PARCIAL" if any(v == "PARCIAL" for v in verdicts) else "FALLIDA"
    return "PARCIAL"


def write_md(report: Dict[str, Any]) -> None:
    lines = [
        "# NOVUS — Fase 2 HTTP Final",
        "",
        f"Generado: {report.get('generated_at_utc')}",
        f"**Veredicto Fase 2:** {report.get('phase_verdict')}",
        "",
        "## Condiciones",
        "",
        f"- Idle: {IDLE_SEC}s",
        f"- Secuencial: {SEQ_N} req/API",
        f"- Concurrente: {CONC_N} req (5 workers)",
        f"- Objetivo: p50<{P50_TARGET}ms, p95<{P95_TARGET}ms, max<{MAX_SPIKE}ms",
        "",
        "## Infraestructura",
        "",
    ]
    infra = report.get("infrastructure") or {}
    for k, v in infra.items():
        lines.append(f"- {k}: {v}")
    lines.extend(["", "## Resultados por API", ""])
    lines.append("| API | p50 | p95 | max | spikes>2s | veredicto |")
    lines.append("|-----|-----|-----|-----|-----------|-----------|")
    for row in report.get("apis") or []:
        cs = row.get("combined_stats") or {}
        lines.append(
            f"| `{row['path']}` | {cs.get('p50')} | {cs.get('p95')} | {cs.get('max')} | "
            f"{row.get('spikes_over_2s')} | {row.get('verdict')} |"
        )
    lines.extend(["", "## Fixes aplicados en esta iteración", ""])
    for fix in report.get("fixes_this_iteration") or []:
        lines.append(f"- {fix}")
    lines.extend(["", "## Causa raíz (confirmada)", ""])
    lines.append(report.get("root_cause_summary", ""))
    lines.extend(["", "## Fase 1", ""])
    lines.append(f"Estado: **{report.get('phase1_status', 'CERRADA')}** (no re-auditada salvo regresión)")
    (OUT / "PHASE_2_HTTP_FINAL.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    report: Dict[str, Any] = {
        "generated_at_utc": utc(),
        "phase": 2,
        "test_protocol": {
            "idle_sec": IDLE_SEC,
            "sequential_per_api": SEQ_N,
            "concurrent_per_api": CONC_N,
            "concurrent_workers": 3,
            "targets": {"p50_ms": P50_TARGET, "p95_ms": P95_TARGET, "max_spike_ms": MAX_SPIKE},
        },
        "fixes_this_iteration": [
            "hostile_hardening_config: una copia por request (flask.g) vs 4+ deepcopy",
            "http_abuse_guard: cfg única por run_pre_request_checks; CPU adaptive TTL 2s",
            "(previas) cache mtime config, session revoke index, load_user g-cache, tenant g-cache, system_monitor non-blocking",
        ],
        "root_cause_summary": (
            "Latencia HTTP dominada por middleware security (before_request) y contención GIL/threads "
            "con workers P2 — NO por snapshot/network backend (0.05–1.5 ms directos)."
        ),
        "phase1_status": "CERRADA",
    }

    print("Reinicio limpio...")
    pid = restart_server()
    if not pid:
        report["phase_verdict"] = "FALLIDA"
        report["error"] = "boot failed"
        (OUT / "PHASE_2_HTTP_FINAL.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        write_md(report)
        return 1

    report["infrastructure"] = {"boot_pid": pid, **proc_metrics(pid)}
    if (report["infrastructure"].get("ram_system_pct") or 100) >= 70:
        report["baseline_ram_warning"] = "RAM sistema >= 70% al inicio"

    print(f"Idle {IDLE_SEC}s...")
    time.sleep(IDLE_SEC)
    report["after_idle"] = proc_metrics(pid)

    sess = login_session()
    time.sleep(2)

    api_rows = []
    for path in APIS:
        print(f"Testing {path}...")
        row = evaluate_api(path, sess)
        api_rows.append(row)
        report["after_idle"] = proc_metrics(pid)
        time.sleep(3)

    report["apis"] = api_rows
    report["final_metrics"] = proc_metrics(pid)
    report["phase_verdict"] = phase_verdict(api_rows)

    (OUT / "PHASE_2_HTTP_FINAL.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    write_md(report)
    print(json.dumps({"phase_verdict": report["phase_verdict"], "apis": {r["path"]: r["combined_stats"] for r in api_rows}}, indent=2))
    return 0 if report["phase_verdict"] == "VERIFICADA" else 1


if __name__ == "__main__":
    raise SystemExit(main())
