#!/usr/bin/env python3
"""Benchmark enterprise de rendimiento NOVUS (medición real, sin simulación)."""
from __future__ import annotations

import json
import os
import re
import shutil
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "data" / "performance_enterprise"
OUT_DIR.mkdir(parents=True, exist_ok=True)

BASE_URL = os.environ.get("NOVUS_BENCH_BASE_URL", "http://127.0.0.1:5000")
LOGIN_EMAIL = os.environ.get("NOVUS_BENCH_EMAIL", "novus.qa.jul2026@example.com")
LOGIN_PASSWORD = os.environ.get("NOVUS_BENCH_PASSWORD", "NovusQA2026!")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_startup_seconds(terminal_log: Optional[str]) -> Optional[float]:
    if not terminal_log:
        return None
    p = Path(terminal_log)
    if not p.is_file():
        return None
    try:
        txt = p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None
    m_start = re.search(r"started_at:\s*([0-9T:\.\-]+Z)", txt)
    m_ready = re.search(r"Running on http://127\.0\.0\.1:500[01]", txt)
    if not m_start or not m_ready:
        return None
    # Buscar timestamp de línea "Press CTRL+C to quit" (marca estable de servidor listo)
    lines = txt.splitlines()
    ready_ts = None
    for line in lines:
        if "Press CTRL+C to quit" in line:
            m = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line.strip())
            if m:
                ready_ts = m.group(1)
                break
    if not ready_ts:
        return None
    try:
        t0_utc = datetime.strptime(m_start.group(1), "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        t0_local = t0_utc.astimezone().replace(tzinfo=None)
        t1_local = datetime.strptime(ready_ts, "%Y-%m-%d %H:%M:%S")
        delta = (t1_local - t0_local).total_seconds()
        if delta < 0:
            return None
        return round(delta, 3)
    except Exception:
        return None


def _bench_path(session: requests.Session, path: str, n: int = 1, timeout: float = 12.0) -> Dict[str, Any]:
    times: List[float] = []
    statuses: List[Any] = []
    errors: List[str] = []
    for _ in range(n):
        t0 = time.perf_counter()
        try:
            r = session.get(f"{BASE_URL}{path}", timeout=timeout, allow_redirects=False)
            statuses.append(r.status_code)
        except Exception as exc:
            statuses.append(None)
            errors.append(type(exc).__name__)
        times.append((time.perf_counter() - t0) * 1000)
    return {
        "path": path,
        "calls": n,
        "status_last": statuses[-1] if statuses else None,
        "status_all": statuses,
        "ms_min": round(min(times), 1),
        "ms_avg": round(statistics.mean(times), 1),
        "ms_max": round(max(times), 1),
        "errors": errors,
    }


def run(label: str, pid: int, terminal_log: Optional[str]) -> Dict[str, Any]:
    try:
        conn_count = len(proc.net_connections(kind="inet"))  # psutil modern
    except Exception:
        try:
            conn_count = len(proc.connections(kind="inet"))  # compat
        except Exception:
            conn_count = None

    proc = psutil.Process(pid)
    # warm cpu counter
    proc.cpu_percent(interval=None)
    session = requests.Session()

    # login flow measurement
    t0 = time.perf_counter()
    login_get = session.get(f"{BASE_URL}/login", timeout=30, allow_redirects=False)
    login_get_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    login_post = session.post(
        f"{BASE_URL}/login",
        data={"email": LOGIN_EMAIL, "password": LOGIN_PASSWORD},
        timeout=45,
        allow_redirects=False,
    )
    login_post_ms = (time.perf_counter() - t0) * 1000

    module_paths = [
        "/dashboard",
        "/network",
        "/topology",
        "/vulnerabilidades",
        "/centro-defensa",
        "/zdde",
    ]
    api_paths = [
        "/api/security/summary",
        "/api/dashboard/live",
        "/api/network/ndr",
        "/api/zdde/dashboard",
        "/api/swarm-defense/observability",
    ]
    module_metrics = [_bench_path(session, p, n=1) for p in module_paths]
    api_metrics = [_bench_path(session, p, n=1) for p in api_paths]

    # system/process metrics
    proc_cpu = proc.cpu_percent(interval=2.0)
    mem = proc.memory_info()
    vm = psutil.virtual_memory()
    disk_root = str(Path.cwd().anchor or "C:/")
    disk_total, disk_used, _disk_free = shutil.disk_usage(disk_root)
    net = psutil.net_io_counters()

    data = {
        "label": label,
        "captured_at_utc": _utc(),
        "base_url": BASE_URL,
        "pid": pid,
        "startup_seconds": _parse_startup_seconds(terminal_log),
        "login": {
            "get_status": login_get.status_code,
            "get_ms": round(login_get_ms, 1),
            "post_status": login_post.status_code,
            "post_ms": round(login_post_ms, 1),
        },
        "module_switch": module_metrics,
        "api_response": api_metrics,
        "process": {
            "cpu_pct_2s": round(proc_cpu, 2),
            "rss_mb": round(mem.rss / 1024 / 1024, 1),
            "vms_mb": round(mem.vms / 1024 / 1024, 1),
            "threads": proc.num_threads(),
            "children": [c.pid for c in proc.children(recursive=True)],
            "open_files": len(proc.open_files()),
            "connections": conn_count,
            "io_read_mb": round(proc.io_counters().read_bytes / 1024 / 1024, 1) if proc.io_counters() else None,
            "io_write_mb": round(proc.io_counters().write_bytes / 1024 / 1024, 1) if proc.io_counters() else None,
        },
        "system": {
            "cpu_pct_1s": round(psutil.cpu_percent(interval=1.0), 2),
            "ram_pct": round(vm.percent, 2),
            "disk_pct": round((disk_used / max(disk_total, 1)) * 100.0, 2),
            "net_sent_mb": round(net.bytes_sent / 1024 / 1024, 1),
            "net_recv_mb": round(net.bytes_recv / 1024 / 1024, 1),
            "process_count": len(psutil.pids()),
        },
    }
    return data


def main() -> int:
    label = sys.argv[1] if len(sys.argv) > 1 else "before"
    pid = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    terminal_log = sys.argv[3] if len(sys.argv) > 3 else None
    if pid <= 0:
        print("Usage: benchmark_performance_enterprise.py <label> <pid> [terminal_log_path]")
        return 2
    data = run(label, pid, terminal_log)
    out_path = OUT_DIR / f"BENCHMARK_RENDIMIENTO_{label.upper()}.json"
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"ok": True, "out": str(out_path), "pid": pid, "label": label}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
