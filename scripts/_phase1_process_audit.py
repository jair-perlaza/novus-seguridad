#!/usr/bin/env python3
"""FASE 1 — Inventario de procesos NOVUS (solo lectura)."""
from __future__ import annotations

import datetime
import json
import socket
import subprocess
import sys
from pathlib import Path

try:
    import psutil
except ImportError:
    print("psutil required")
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
NOVUS_MAIN = ROOT / "main.py"
MAIN_MTIME = NOVUS_MAIN.stat().st_mtime if NOVUS_MAIN.exists() else None


def fmt_ts(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def proc_info(p: psutil.Process) -> dict:
    try:
        with p.oneshot():
            mem = p.memory_info().rss / (1024 * 1024)
            return {
                "pid": p.pid,
                "ppid": p.ppid(),
                "name": p.name(),
                "cmdline": p.cmdline(),
                "cwd": p.cwd(),
                "start": fmt_ts(p.create_time()),
                "start_epoch": p.create_time(),
                "ram_mb": round(mem, 1),
                "cpu_pct": round(p.cpu_percent(interval=0.05), 1),
                "threads": p.num_threads(),
                "children": [c.pid for c in p.children(recursive=True)],
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
        return {"pid": p.pid, "error": str(exc)}


def parent_chain(pid: int) -> list[dict]:
    chain = []
    seen = set()
    cur = pid
    while cur and cur not in seen:
        seen.add(cur)
        try:
            p = psutil.Process(cur)
            chain.append(
                {
                    "pid": cur,
                    "name": p.name(),
                    "cmdline": " ".join(p.cmdline()[:3]),
                }
            )
            cur = p.ppid()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            break
    return chain


def listeners_5000() -> list[dict]:
    out = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
    rows = []
    for line in out.splitlines():
        if ":5000" not in line:
            continue
        parts = line.split()
        if len(parts) >= 5 and parts[0] in ("TCP", "UDP"):
            state = parts[3] if parts[0] == "TCP" and len(parts) >= 5 else parts[2]
            pid = int(parts[-1]) if parts[-1].isdigit() else None
            rows.append({"proto": parts[0], "local": parts[1], "state": state, "pid": pid})
    listening = [r for r in rows if r.get("state") == "LISTENING"]
    return listening


def is_novus(p: psutil.Process) -> bool:
    try:
        cwd = p.cwd()
        cmd = " ".join(p.cmdline()).lower()
        if str(ROOT).lower() in cwd.lower():
            return True
        if "main.py" in cmd and p.name().lower() in ("python.exe", "py.exe"):
            return cwd.lower().endswith("novus") or str(ROOT).lower() in cwd.lower()
        if "novus" in cmd and p.name().lower() == "python.exe":
            return True
        audit_scripts = (
            "novus_master_capability_audit",
            "novus_full_integration_verify",
            "novus_full_integration_report",
        )
        return any(s in cmd for s in audit_scripts)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def main() -> None:
    vm = psutil.virtual_memory()
    report = {
        "generated_at": datetime.datetime.now().isoformat(),
        "novus_root": str(ROOT),
        "main_py_mtime": fmt_ts(MAIN_MTIME) if MAIN_MTIME else None,
        "system_ram_pct": round(vm.percent, 1),
        "system_ram_used_gb": round(vm.used / (1024**3), 2),
        "listeners_port_5000": listeners_5000(),
        "novus_processes": [],
        "listener_details": [],
    }

    novus_procs = [p for p in psutil.process_iter() if is_novus(p)]
    novus_procs.sort(key=lambda p: p.create_time())

    for p in novus_procs:
        info = proc_info(p)
        info["parent_chain"] = parent_chain(info.get("ppid", 0))
        info["is_listener_5000"] = info["pid"] in {r["pid"] for r in report["listeners_port_5000"]}
        report["novus_processes"].append(info)

    listener_pids = sorted({r["pid"] for r in report["listeners_port_5000"] if r.get("pid")})
    for pid in listener_pids:
        try:
            p = psutil.Process(pid)
            detail = proc_info(p)
            detail["parent_chain"] = parent_chain(detail.get("ppid", 0))
            age_min = (datetime.datetime.now().timestamp() - detail["start_epoch"]) / 60
            detail["age_minutes"] = round(age_min, 1)
            report["listener_details"].append(detail)
        except psutil.NoSuchProcess:
            report["listener_details"].append({"pid": pid, "error": "process gone"})

    out_path = ROOT / "data" / "novus_process_audit" / "PHASE1_PROCESS_INVENTORY.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
