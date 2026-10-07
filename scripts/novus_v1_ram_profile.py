#!/usr/bin/env python3
"""Perfil RAM NOVUS V1 — boot, idle, navegación MVP."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "data" / "novus_release_candidate"
OUT_JSON = OUT_DIR / "NOVUS_V1_RAM_PROFILE.json"
BASE = os.environ.get("NOVUS_TEST_BASE", "http://127.0.0.1:5000")
PYTHON = sys.executable


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_pid() -> Optional[int]:
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or [])
            if "main.py" in cmd.replace("\\", "/"):
                return p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None


def sample(pid: Optional[int]) -> Dict[str, Any]:
    mem = psutil.virtual_memory()
    row: Dict[str, Any] = {
        "ts": utc(),
        "system_ram_pct": round(mem.percent, 1),
        "listeners_5000": len([
            c for c in psutil.net_connections(kind="inet")
            if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN"
        ]),
    }
    if pid:
        try:
            proc = psutil.Process(pid)
            row["rss_mb"] = round(proc.memory_info().rss / 1024 / 1024, 1)
            row["threads"] = proc.num_threads()
            row["cpu_pct"] = round(proc.cpu_percent(interval=0.1), 1)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    try:
        from services.resource_backpressure_service import get_backpressure_status

        row["backpressure"] = get_backpressure_status()
    except Exception:
        pass
    return row


def wait_server(timeout: int = 120) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(f"{BASE}/login", timeout=5).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def profile_phase(name: str, pid: Optional[int], duration_sec: int, interval: int = 30) -> List[Dict[str, Any]]:
    rows = []
    end = time.time() + duration_sec
    while time.time() < end:
        rows.append({"phase": name, **sample(pid)})
        time.sleep(interval)
    return rows


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    report: Dict[str, Any] = {"started_at": utc(), "phases": {}, "samples": []}

    pid = find_pid()
    if not pid:
        env = os.environ.copy()
        env["FLASK_DEBUG"] = "False"
        env.setdefault("NOVUS_ENV", "development")
        subprocess.Popen([PYTHON, str(ROOT / "main.py")], cwd=str(ROOT), env=env)
        if not wait_server():
            report["error"] = "server_not_ready"
            OUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
            return 1
        time.sleep(10)
        pid = find_pid()

    report["pid"] = pid
    for phase, duration in (("boot", 60), ("idle_5m", 300), ("idle_15m", 900)):
        if phase == "idle_15m" and os.environ.get("NOVUS_RAM_PROFILE_SHORT", "").strip() in ("1", "true", "yes"):
            break
        rows = profile_phase(phase, pid, duration, interval=30 if duration <= 300 else 60)
        report["samples"].extend(rows)
        report["phases"][phase] = {
            "count": len(rows),
            "rss_start_mb": rows[0].get("rss_mb") if rows else None,
            "rss_end_mb": rows[-1].get("rss_mb") if rows else None,
            "rss_delta_mb": (
                round(rows[-1]["rss_mb"] - rows[0]["rss_mb"], 1)
                if rows and rows[0].get("rss_mb") is not None and rows[-1].get("rss_mb") is not None
                else None
            ),
        }

    rss_values = [s["rss_mb"] for s in report["samples"] if s.get("rss_mb") is not None]
    if rss_values:
        report["summary"] = {
            "rss_min_mb": min(rss_values),
            "rss_max_mb": max(rss_values),
            "rss_growth_mb": round(rss_values[-1] - rss_values[0], 1),
            "runaway_suspected": (rss_values[-1] - rss_values[0]) > 200 and len(rss_values) >= 5,
        }
    report["finished_at"] = utc()
    OUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report.get("summary", report), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
