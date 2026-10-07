#!/usr/bin/env python3
"""Gate audit — Fases 1-4 con evidencia objetiva."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "novus_process_audit"
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")
SAMPLE = [0, 30, 60, 120, 180, 300]
APIS = [
    "/api/dashboard/live",
    "/api/security/summary",
    "/api/network/nodes?trigger_discovery=false&include_context=false",
    "/api/network/info",
    "/api/network/ndr",
    "/api/network/topology",
]


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def listeners() -> List[int]:
    pids = []
    out = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
    for line in out.splitlines():
        if ":5000" in line and "LISTENING" in line:
            pids.append(int(line.split()[-1]))
    return pids


def find_pid() -> Optional[int]:
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = p.info.get("cmdline") or []
            if len(cmd) >= 2 and cmd[-1] == "main.py":
                return p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None


def classify_ms(ms: float) -> str:
    if ms < 500:
        return "green"
    if ms < 1000:
        return "yellow"
    if ms < 3000:
        return "orange"
    return "red"


def login() -> requests.Session:
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=15)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    s.post(f"{BASE}/login", data={"email": QA[0], "password": QA[1], "csrf_token": csrf.group(1) if csrf else ""}, timeout=20)
    return s


def restart_clean() -> int:
    for pid in listeners():
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)], capture_output=True)
    time.sleep(2)
    env = __import__("os").environ.copy()
    env["FLASK_DEBUG"] = "False"
    subprocess.Popen([sys.executable, "main.py"], cwd=str(ROOT), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(120):
        if listeners():
            time.sleep(3)
            return find_pid() or listeners()[0]
        time.sleep(1)
    return 0


def profile(pid: int) -> Dict[str, Any]:
    timeline = []
    t0 = time.time()
    idx = 0
    while idx < len(SAMPLE):
        if time.time() - t0 >= SAMPLE[idx] - 0.05:
            vm = psutil.virtual_memory()
            p = psutil.Process(pid)
            timeline.append({
                "sec": SAMPLE[idx],
                "ram_system_pct": round(vm.percent, 1),
                "novus_ram_mb": round(p.memory_info().rss / (1024**2), 1),
                "threads": p.num_threads(),
            })
            idx += 1
        time.sleep(0.2)
    stable = len(timeline) >= 2 and abs(timeline[-1]["novus_ram_mb"] - timeline[-2]["novus_ram_mb"]) < 80
    return {"timeline": timeline, "stable_5min": stable, "listeners": listeners()}


def probe_apis(sess: requests.Session) -> List[Dict[str, Any]]:
    rows = []
    for path in APIS:
        t0 = time.perf_counter()
        try:
            r = sess.get(BASE + path, timeout=10)
            ms = round((time.perf_counter() - t0) * 1000, 1)
            rows.append({"path": path, "ms": ms, "http": r.status_code, "class": classify_ms(ms)})
        except Exception as exc:
            ms = round((time.perf_counter() - t0) * 1000, 1)
            rows.append({"path": path, "ms": ms, "error": str(exc)[:120], "class": "black"})
        time.sleep(2)
    return rows


def main() -> int:
    report: Dict[str, Any] = {"generated_at_utc": utc()}
    pid = restart_clean()
    if not pid:
        report["phase1"] = {"verdict": "FALLO", "reason": "boot failed"}
        _write(report)
        return 1
    report["phase1"] = profile(pid)
    report["phase1"]["verdict"] = (
        "VERIFICADO"
        if report["phase1"]["stable_5min"] and len(report["phase1"]["listeners"]) == 1
        and (report["phase1"]["timeline"][-1]["ram_system_pct"] or 100) < 80
        else "PARCIAL"
    )
    sess = login()
    apis = probe_apis(sess)
    report["phase2_apis"] = apis
    all_green = all(a.get("class") == "green" for a in apis)
    report["phase2"] = {"verdict": "VERIFICADO" if all_green else "PARCIAL" if any(a.get("class") == "green" for a in apis) else "FALLO"}
    _write(report)
    print(json.dumps({"phase1": report["phase1"]["verdict"], "phase2": report["phase2"]["verdict"], "apis": apis}, indent=2))
    return 0


def _write(report: Dict[str, Any]) -> None:
    (OUT / "PHASE_GATE_AUDIT.json").write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
