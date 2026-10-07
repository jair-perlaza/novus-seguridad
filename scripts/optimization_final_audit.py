#!/usr/bin/env python3
"""
NOVUS Optimization Final Audit — genera informes de estabilidad, startup, polling, engines.
NO ejecuta auditoría de 46 módulos.
"""
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
OUT = ROOT / "data" / "novus_process_audit"
OUT.mkdir(parents=True, exist_ok=True)
BASE = os.environ.get("NOVUS_TEST_BASE", "http://127.0.0.1:5000")
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")
SAMPLE_SEC = [0, 30, 60, 120, 180, 300]


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def listeners() -> List[int]:
    pids = []
    try:
        out = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
        for line in out.splitlines():
            if ":5000" in line and "LISTENING" in line:
                pids.append(int(line.split()[-1]))
    except Exception:
        pass
    return sorted(set(pids))


def find_novus_pid() -> Optional[int]:
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = p.info.get("cmdline") or []
            if len(cmd) >= 2 and cmd[-1] == "main.py":
                return p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None


def proc_snap(pid: Optional[int]) -> Dict[str, Any]:
    vm = psutil.virtual_memory()
    row = {
        "timestamp_utc": utc(),
        "ram_system_pct": round(vm.percent, 1),
        "ram_used_gb": round(vm.used / (1024**3), 2),
        "cpu_system_pct": round(psutil.cpu_percent(interval=0.1), 1),
    }
    if pid:
        try:
            p = psutil.Process(pid)
            row["novus_ram_mb"] = round(p.memory_info().rss / (1024**2), 1)
            row["novus_cpu_pct"] = round(p.cpu_percent(interval=0.1), 1)
            row["threads"] = p.num_threads()
        except psutil.NoSuchProcess:
            pass
    return row


def login_session() -> Optional[requests.Session]:
    s = requests.Session()
    try:
        r = s.get(f"{BASE}/login", timeout=15)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
        token = csrf.group(1) if csrf else ""
        s.post(f"{BASE}/login", data={"email": QA[0], "password": QA[1], "csrf_token": token}, timeout=20)
        return s
    except Exception:
        return None


def api_probe(sess: requests.Session, path: str) -> Dict[str, Any]:
    t0 = time.perf_counter()
    row = {"path": path}
    try:
        r = sess.get(BASE + path, timeout=15)
        row["ms"] = round((time.perf_counter() - t0) * 1000, 1)
        row["http"] = r.status_code
        try:
            body = r.json()
            row["status_field"] = body.get("status") or body.get("ok")
            row["scan_status"] = body.get("scan_status")
            row["snapshot_pending"] = body.get("snapshot_pending")
        except Exception:
            pass
    except Exception as exc:
        row["ms"] = round((time.perf_counter() - t0) * 1000, 1)
        row["error"] = str(exc)[:160]
    return row


def scan_polling_inventory() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    patterns = [
        (r"setInterval\s*\(\s*([^,]+)\s*,\s*(\d+)", "setInterval"),
        (r"EventSource\s*\(\s*['\"]([^'\"]+)", "EventSource"),
        (r"new WebSocket\s*\(\s*['\"]([^'\"]+)", "WebSocket"),
    ]
    for base in [ROOT / "templates", ROOT / "static" / "js"]:
        if not base.is_dir():
            continue
        for fp in base.rglob("*"):
            if fp.suffix not in (".html", ".js"):
                continue
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            rel = str(fp.relative_to(ROOT)).replace("\\", "/")
            for pat, kind in patterns:
                for m in re.finditer(pat, text):
                    items.append({
                        "file": rel,
                        "kind": kind,
                        "target": m.group(1).strip()[:80] if m.lastindex else None,
                        "interval_ms": int(m.group(2)) if kind == "setInterval" and m.lastindex >= 2 else None,
                    })
    return items


def load_startup_map() -> Dict[str, Any]:
    p = OUT / "STARTUP_DEPENDENCY_MAP.json"
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return {"note": "generate via Phase 1 analysis"}


def run_stability_profile(pid: int) -> Dict[str, Any]:
    timeline = []
    t0 = time.time()
    idx = 0
    max_ram_sys = 0.0
    max_novus = 0.0
    while idx < len(SAMPLE_SEC):
        if time.time() - t0 >= SAMPLE_SEC[idx] - 0.05:
            snap = proc_snap(pid)
            snap["elapsed_sec"] = SAMPLE_SEC[idx]
            max_ram_sys = max(max_ram_sys, snap.get("ram_system_pct") or 0)
            max_novus = max(max_novus, snap.get("novus_ram_mb") or 0)
            timeline.append(snap)
            idx += 1
        time.sleep(0.25)
    growth = []
    for i in range(1, len(timeline)):
        prev = timeline[i - 1].get("novus_ram_mb") or 0
        cur = timeline[i].get("novus_ram_mb") or 0
        growth.append({"from_sec": timeline[i - 1]["elapsed_sec"], "to_sec": timeline[i]["elapsed_sec"], "delta_mb": round(cur - prev, 1)})
    stable_5min = len(timeline) >= 2 and abs((timeline[-1].get("novus_ram_mb") or 0) - (timeline[-2].get("novus_ram_mb") or 0)) < 50
    return {
        "timeline": timeline,
        "growth_deltas": growth,
        "ram_system_max_pct": max_ram_sys,
        "novus_ram_max_mb": max_novus,
        "stable_no_continuous_growth_300s": stable_5min,
    }


def main() -> int:
    report: Dict[str, Any] = {"generated_at_utc": utc(), "phase": "OPTIMIZATION_FINAL"}

    # Polling inventory
    polling = scan_polling_inventory()
    (OUT / "POLLING_INVENTORY.json").write_text(json.dumps({"generated_at_utc": utc(), "items": polling}, indent=2), encoding="utf-8")
    report["polling_count"] = len(polling)

    # Kill + restart
    for pid in listeners():
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)], capture_output=True)
    time.sleep(2)
    report["listeners_before"] = listeners()
    if report["listeners_before"]:
        report["boot_verdict"] = "FALLO — puerto ocupado"
        _write_all(report, {}, {}, {}, {}, {})
        return 1

    env = os.environ.copy()
    env["FLASK_DEBUG"] = "False"
    subprocess.Popen([sys.executable, "main.py"], cwd=str(ROOT), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 120
    while time.time() < deadline:
        if listeners():
            break
        time.sleep(1)
    report["listeners_after_start"] = listeners()
    pid = find_novus_pid()
    report["novus_pid"] = pid

    if not pid:
        report["boot_verdict"] = "FALLO — no arrancó"
        _write_all(report, {}, {}, {}, {}, {})
        return 1

    resource = run_stability_profile(pid)
    (OUT / "RESOURCE_PROFILE.json").write_text(json.dumps({"generated_at_utc": utc(), **resource}, indent=2), encoding="utf-8")

    sess = login_session()
    api_lat = []
    if sess:
        for path in [
            "/api/security/summary",
            "/api/dashboard/live",
            "/api/network/nodes?trigger_discovery=false&include_context=false",
            "/api/network/info",
            "/api/network/ndr",
            "/api/network/topology",
            "/api/engines/status",
        ]:
            api_lat.append(api_probe(sess, path))
            time.sleep(1)
    (OUT / "API_LATENCY_FINAL.json").write_text(json.dumps({"generated_at_utc": utc(), "probes": api_lat}, indent=2), encoding="utf-8")

    engine_lifecycle: Dict[str, Any] = {"note": "requires RAM baseline <80% for full lifecycle test"}
    if sess and (resource.get("ram_system_max_pct") or 100) < 85:
        engine_lifecycle = _test_lazy_engine(sess, pid)
    (OUT / "ENGINE_LIFECYCLE_REPORT.json").write_text(json.dumps(engine_lifecycle, indent=2), encoding="utf-8")

    startup_map = load_startup_map()
    report["resource"] = {
        "ram_initial_pct": resource["timeline"][0].get("ram_system_pct") if resource.get("timeline") else None,
        "ram_300s_pct": resource["timeline"][-1].get("ram_system_pct") if resource.get("timeline") else None,
        "novus_max_mb": resource.get("novus_ram_max_mb"),
        "stable_5min": resource.get("stable_no_continuous_growth_300s"),
    }
    report["api_latency"] = api_lat
    report["single_listener"] = len(listeners()) == 1

    _write_all(report, resource, api_lat, polling, engine_lifecycle, startup_map)
    print(json.dumps({"ram_max": resource.get("novus_ram_max_mb"), "listeners": listeners()}, indent=2))
    return 0


def _test_lazy_engine(sess: requests.Session, pid: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for name in ["endpoint", "btde", "zdde", "health_engine"]:
        row: Dict[str, Any] = {"engine": name}
        row["before"] = proc_snap(pid)
        try:
            r = sess.post(f"{BASE}/api/engines/start/{name}", timeout=10)
            row["start_response"] = r.json() if r.status_code < 500 else {"http": r.status_code}
        except Exception as exc:
            row["start_error"] = str(exc)[:120]
        time.sleep(8)
        row["during"] = proc_snap(pid)
        try:
            st = sess.get(f"{BASE}/api/engines/status/{name}", timeout=10).json()
            row["status_after"] = st.get("state"), st.get("engine_running")
        except Exception as exc:
            row["status_error"] = str(exc)[:120]
        try:
            sess.post(f"{BASE}/api/engines/start/{name}", timeout=5)  # duplicate start test
            st2 = sess.get(f"{BASE}/api/engines/status/{name}", timeout=10).json()
            row["duplicate_start_state"] = st2.get("state")
        except Exception:
            pass
        out[name] = row
    return out


def _write_all(report, resource, api_lat, polling, engine_lifecycle, startup_map) -> None:
    final = {
        **report,
        "startup_map_ref": "STARTUP_DEPENDENCY_MAP.json",
        "resource_profile_ref": "RESOURCE_PROFILE.json",
    }
    (OUT / "OPTIMIZATION_FINAL_REPORT.json").write_text(json.dumps(final, indent=2, ensure_ascii=False), encoding="utf-8")

    md = [
        "# OPTIMIZATION FINAL REPORT",
        "",
        f"Generated: {report.get('generated_at_utc')}",
        "",
        "## Resource profile",
        f"- RAM sistema max: {resource.get('ram_system_max_pct')}%",
        f"- NOVUS RAM max: {resource.get('novus_ram_max_mb')} MB",
        f"- Estable 5min: {resource.get('stable_no_continuous_growth_300s')}",
        f"- Single listener: {report.get('single_listener')}",
        "",
        "## API latency",
    ]
    for p in api_lat or []:
        md.append(f"- {p.get('path')}: {p.get('ms')} ms HTTP {p.get('http', '?')}")
    (OUT / "OPTIMIZATION_FINAL_REPORT.md").write_text("\n".join(md), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
