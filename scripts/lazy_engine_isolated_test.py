#!/usr/bin/env python3
"""Prueba aislada de lazy engines — uno por uno, tras idle estable."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "novus_process_audit"
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")
ENGINES = ["endpoint_realtime", "btde", "zdde", "health_engine"]
IDLE_SEC = 60
START_WAIT = 45


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_pid() -> Optional[int]:
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = p.info.get("cmdline") or []
            if len(cmd) >= 2 and cmd[-1] == "main.py":
                return p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None


def snap(pid: Optional[int]) -> Dict[str, Any]:
    vm = psutil.virtual_memory()
    row = {"ram_system_pct": round(vm.percent, 1), "timestamp_utc": utc()}
    if pid:
        try:
            p = psutil.Process(pid)
            row["novus_ram_mb"] = round(p.memory_info().rss / (1024**2), 1)
            row["threads"] = p.num_threads()
        except psutil.NoSuchProcess:
            pass
    return row


def login() -> requests.Session:
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=15)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    s.post(f"{BASE}/login", data={"email": QA[0], "password": QA[1], "csrf_token": csrf.group(1) if csrf else ""}, timeout=20)
    return s


def wait_running(sess: requests.Session, name: str, timeout: float = START_WAIT) -> Dict[str, Any]:
    deadline = time.time() + timeout
    last = {}
    while time.time() < deadline:
        try:
            r = sess.get(f"{BASE}/api/engines/status/{name}", timeout=8)
            last = r.json()
            if last.get("engine_running") or last.get("state") == "RUNNING":
                last["startup_sec"] = round(timeout - (deadline - time.time()), 1)
                return last
        except Exception as exc:
            last = {"error": str(exc)[:120]}
        time.sleep(1.0)
    last["timeout"] = True
    return last


def test_engine(sess: requests.Session, pid: int, name: str) -> Dict[str, Any]:
    print(f"  Testing {name}...")
    row: Dict[str, Any] = {"engine": name}
    row["before"] = snap(pid)
    t0 = time.perf_counter()
    try:
        r = sess.post(f"{BASE}/api/engines/start/{name}", timeout=5)
        row["start_http"] = r.status_code
        row["start_body"] = r.json()
    except Exception as exc:
        row["start_error"] = str(exc)[:160]
    row["during"] = snap(pid)
    ready = wait_running(sess, name)
    row["ready"] = ready
    row["startup_sec"] = round(time.perf_counter() - t0, 2)
    row["after_start"] = snap(pid)
    time.sleep(5)
    try:
        sess.post(f"{BASE}/api/engines/stop/{name}", timeout=8)
    except Exception as exc:
        row["stop_error"] = str(exc)[:120]
    time.sleep(8)
    row["after_stop"] = snap(pid)
    try:
        st = sess.get(f"{BASE}/api/engines/status/{name}", timeout=8).json()
        row["final_state"] = st.get("state")
        row["final_running"] = st.get("engine_running")
    except Exception as exc:
        row["final_error"] = str(exc)[:120]
    row["verdict"] = "VERIFICADO" if ready.get("engine_running") or ready.get("state") == "RUNNING" else "FALLO"
    return row


def main() -> int:
    pid = find_pid()
    if not pid:
        print("NOVUS not running")
        return 1
    print(f"Idle {IDLE_SEC}s before tests...")
    time.sleep(IDLE_SEC)
    sess = login()
    report = {"generated_at_utc": utc(), "idle_sec": IDLE_SEC, "engines": {}}
    for name in ENGINES:
        report["engines"][name] = test_engine(sess, pid, name)
        print(f"  idle {IDLE_SEC}s before next...")
        time.sleep(IDLE_SEC)
    (OUT / "ENGINE_LIFECYCLE_ISOLATED.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: v.get("verdict") for k, v in report["engines"].items()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
