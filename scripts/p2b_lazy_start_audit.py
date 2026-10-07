#!/usr/bin/env python3
"""P2B Lazy Start — perfil RAM, activación bajo demanda, regresión API."""
from __future__ import annotations

import json
import os
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
OUT_DIR = ROOT / "data" / "novus_process_audit"
OUT_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_POINTS = [0, 15, 30, 45, 60, 90, 120, 180]
BASE = os.environ.get("NOVUS_TEST_BASE", "http://127.0.0.1:5000")
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def listener_pids() -> List[int]:
    out = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
    pids = []
    for line in out.splitlines():
        if ":5000" in line and "LISTENING" in line:
            pids.append(int(line.split()[-1]))
    return sorted(set(pids))


def find_novus_pid() -> Optional[int]:
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = p.info.get("cmdline") or []
            if len(cmd) >= 2 and cmd[-1] == "main.py" and "python" in (cmd[0] or "").lower():
                return p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None


def kill_novus() -> Dict[str, Any]:
    killed = []
    for pid in listener_pids():
        try:
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)], check=False, capture_output=True)
            killed.append(pid)
        except Exception:
            pass
    time.sleep(2)
    return {"killed_pids": killed, "listeners_after": listener_pids()}


def proc_metrics(pid: Optional[int]) -> Dict[str, Any]:
    vm = psutil.virtual_memory()
    base = {
        "ram_system_pct": round(vm.percent, 1),
        "ram_used_gb": round(vm.used / (1024**3), 2),
        "cpu_system_pct": round(psutil.cpu_percent(interval=0.1), 1),
        "timestamp_utc": utc(),
    }
    if not pid:
        base["novus_ram_mb"] = None
        base["threads"] = None
        return base
    try:
        p = psutil.Process(pid)
        base["novus_ram_mb"] = round(p.memory_info().rss / (1024**2), 1)
        base["threads"] = p.num_threads()
        base["cpu_novus_pct"] = round(p.cpu_percent(interval=0.1), 1)
    except psutil.NoSuchProcess:
        base["novus_ram_mb"] = None
        base["threads"] = None
    return base


def wait_http(timeout: float = 120.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{BASE}/login", timeout=3)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def login_session() -> Optional[requests.Session]:
    s = requests.Session()
    try:
        r = s.get(f"{BASE}/login", timeout=15)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
        token = csrf.group(1) if csrf else ""
        s.post(
            f"{BASE}/login",
            data={"email": QA[0], "password": QA[1], "csrf_token": token},
            timeout=20,
        )
        return s
    except Exception:
        return None


def api_ms(path: str, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    sess = session or requests.Session()
    t0 = time.perf_counter()
    try:
        r = sess.get(f"{BASE}{path}", timeout=30)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        return {"path": path, "ms": ms, "status": r.status_code, "ok": r.status_code < 500}
    except Exception as exc:
        ms = round((time.perf_counter() - t0) * 1000, 1)
        return {"path": path, "ms": ms, "status": 0, "ok": False, "error": str(exc)[:120]}


def poll_engine_running(name: str, session: requests.Session, timeout: float = 90.0) -> Dict[str, Any]:
    deadline = time.time() + timeout
    last = {}
    while time.time() < deadline:
        try:
            r = session.get(f"{BASE}/api/engines/status/{name}", timeout=10)
            last = r.json() if r.status_code == 200 else {"error": r.text[:200]}
            if last.get("engine_running") or last.get("state") == "RUNNING":
                last["ready_ms"] = round((timeout - (deadline - time.time())) * 1000, 0)
                return last
            if last.get("state") == "ERROR":
                return last
        except Exception as exc:
            last = {"error": str(exc)[:200]}
        time.sleep(1.5)
    last["timeout"] = True
    return last


def main() -> int:
    report: Dict[str, Any] = {
        "generated_at_utc": utc(),
        "phase": "P2B_LAZY_START",
        "sample_points_sec": SAMPLE_POINTS,
    }

    print("=== Kill existing NOVUS ===")
    report["kill"] = kill_novus()
    if report["kill"]["listeners_after"]:
        report["verdict_boot"] = "FALLO — puerto 5000 ocupado"
        _write_reports(report)
        return 1

    print("=== Start single instance ===")
    env = os.environ.copy()
    env["FLASK_DEBUG"] = "False"
    proc = subprocess.Popen(
        [sys.executable, "main.py"],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    report["started_pid"] = proc.pid
    if not wait_http():
        report["verdict_boot"] = "FALLO — servidor no respondió"
        _write_reports(report)
        return 1

    session = login_session()
    report["login_ok"] = session is not None

    pid = find_novus_pid() or proc.pid
    timeline: List[Dict[str, Any]] = []
    t0 = time.time()
    next_idx = 0
    while next_idx < len(SAMPLE_POINTS):
        elapsed = time.time() - t0
        if elapsed >= SAMPLE_POINTS[next_idx] - 0.05:
            snap = proc_metrics(pid)
            snap["elapsed_sec"] = SAMPLE_POINTS[next_idx]
            try:
                if session:
                    r = session.get(f"{BASE}/api/engines/status", timeout=15)
                    if r.status_code == 200:
                        eng = r.json()
                        snap["p2_pending"] = eng.get("p2_pending")
                        snap["engines_running"] = [
                            k for k, v in (eng.get("engines") or {}).items() if v.get("engine_running")
                        ]
            except Exception as exc:
                snap["engines_error"] = str(exc)[:120]
            timeline.append(snap)
            print(f"  t={SAMPLE_POINTS[next_idx]}s RAM sys={snap['ram_system_pct']}% NOVUS={snap.get('novus_ram_mb')}MB threads={snap.get('threads')}")
            next_idx += 1
        time.sleep(0.25)

    report["ram_timeline"] = timeline

    print("=== P2 activation: endpoint ===")
    ram_before = proc_metrics(pid)
    t_start = time.perf_counter()
    if session:
        try:
            r = session.post(f"{BASE}/api/engines/start/endpoint", timeout=10)
            endpoint_boot = r.json()
        except Exception as exc:
            endpoint_boot = {"error": str(exc)}
        endpoint_ready = poll_engine_running("endpoint", session, timeout=120)
    else:
        endpoint_boot = {"error": "no_session"}
        endpoint_ready = {"error": "no_session"}
    ram_after = proc_metrics(pid)
    report["endpoint_activation"] = {
        "ram_before_mb": ram_before.get("novus_ram_mb"),
        "ram_after_mb": ram_after.get("novus_ram_mb"),
        "ram_delta_mb": round((ram_after.get("novus_ram_mb") or 0) - (ram_before.get("novus_ram_mb") or 0), 1),
        "boot_response": endpoint_boot,
        "ready_state": endpoint_ready,
        "startup_sec": round(time.perf_counter() - t_start, 2),
        "verdict": "VERIFICADO" if endpoint_ready.get("engine_running") or endpoint_ready.get("state") == "RUNNING" else "FALLO",
    }

    print("=== P2 activation: btde ===")
    ram_before = proc_metrics(pid)
    t_start = time.perf_counter()
    if session:
        try:
            r = session.post(f"{BASE}/api/engines/start/btde", timeout=10)
            btde_boot = r.json()
        except Exception as exc:
            btde_boot = {"error": str(exc)}
        btde_ready = poll_engine_running("btde", session, timeout=120)
    else:
        btde_boot = {"error": "no_session"}
        btde_ready = {"error": "no_session"}
    ram_after = proc_metrics(pid)
    report["btde_activation"] = {
        "ram_before_mb": ram_before.get("novus_ram_mb"),
        "ram_after_mb": ram_after.get("novus_ram_mb"),
        "boot_response": btde_boot,
        "ready_state": btde_ready,
        "startup_sec": round(time.perf_counter() - t_start, 2),
        "verdict": "VERIFICADO" if btde_ready.get("engine_running") else "FALLO",
    }

    print("=== API regression (sequential) ===")
    paths = [
        "/api/network/nodes",
        "/api/network/info",
        "/api/network/ndr",
        "/api/network/topology",
        "/api/security/summary",
        "/api/dashboard/live",
    ]
    regression = [api_ms(p, session) for p in paths]
    report["api_regression"] = regression
    report["api_regression_verdict"] = (
        "VERIFICADO"
        if all(x.get("ok") and x.get("ms", 9999) < 500 for x in regression)
        else "PARCIAL"
    )

    # RAM targets
    t60 = next((x for x in timeline if x["elapsed_sec"] == 60), {})
    t120 = next((x for x in timeline if x["elapsed_sec"] == 120), {})
    t180 = next((x for x in timeline if x["elapsed_sec"] == 180), {})
    report["ram_verdict"] = (
        "VERIFICADO"
        if all((x.get("ram_system_pct") or 100) < 80 for x in (t60, t120, t180) if x)
        else "FALLO"
    )
    report["listeners_final"] = listener_pids()
    report["single_listener"] = len(report["listeners_final"]) == 1

    _write_reports(report)
    print(json.dumps({"ram_verdict": report["ram_verdict"], "endpoint": report["endpoint_activation"]["verdict"]}, indent=2))
    return 0


def _write_reports(report: Dict[str, Any]) -> None:
    json_path = OUT_DIR / "P2B_LAZY_START_REPORT.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    md_lines = [
        "# P2B Lazy Start Report",
        "",
        f"Generated: {report.get('generated_at_utc')}",
        "",
        "## RAM timeline",
        "",
        "| sec | sys RAM % | NOVUS MB | threads | P2 pending |",
        "|-----|-----------|----------|---------|------------|",
    ]
    for row in report.get("ram_timeline") or []:
        pending = len(row.get("p2_pending") or [])
        md_lines.append(
            f"| {row.get('elapsed_sec')} | {row.get('ram_system_pct')} | {row.get('novus_ram_mb')} | {row.get('threads')} | {pending} |"
        )
    md_lines.extend(
        [
            "",
            f"**RAM verdict:** {report.get('ram_verdict', 'NO VERIFICADO')}",
            "",
            "## Endpoint activation",
            f"- Verdict: {report.get('endpoint_activation', {}).get('verdict')}",
            f"- Startup sec: {report.get('endpoint_activation', {}).get('startup_sec')}",
            "",
            "## BTDE activation",
            f"- Verdict: {report.get('btde_activation', {}).get('verdict')}",
            "",
            "## API regression",
            f"- Verdict: {report.get('api_regression_verdict')}",
        ]
    )
    (OUT_DIR / "P2B_LAZY_START_REPORT.md").write_text("\n".join(md_lines), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
