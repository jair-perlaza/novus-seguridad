#!/usr/bin/env python3
"""FASE 1 — Perfil forense RAM/CPU durante arranque NOVUS."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "data" / "novus_process_audit"
OUT_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_POINTS = [0, 30, 60, 90, 120, 180]


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_novus_pid() -> int | None:
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = p.info.get("cmdline") or []
            if len(cmd) >= 2 and cmd[-1] == "main.py" and "python" in (cmd[0] or "").lower():
                return p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None


def listener_pids() -> list[int]:
    out = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
    pids = []
    for line in out.splitlines():
        if ":5000" in line and "LISTENING" in line:
            pid = int(line.split()[-1])
            pids.append(pid)
    return pids


def snapshot_sizes() -> dict[str, float]:
    sizes = {}
    base = ROOT / "data"
    if not base.is_dir():
        return sizes
    for path in base.rglob("*.json"):
        try:
            rel = str(path.relative_to(ROOT))
            sizes[rel] = round(path.stat().st_size / 1024, 1)
        except OSError:
            pass
    return dict(sorted(sizes.items(), key=lambda x: -x[1])[:40])


def thread_inventory(pid: int) -> list[dict]:
    rows = []
    try:
        p = psutil.Process(pid)
        for t in p.threads():
            rows.append({"id": t.id, "user_time": t.user_time, "system_time": t.system_time})
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return rows


def named_threads(pid: int) -> list[str]:
    names = []
    try:
        p = psutil.Process(pid)
        for child in p.children(recursive=True):
            try:
                names.append(f"{child.pid}:{child.name()}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return names


def sample_point(pid: int | None, elapsed: int) -> dict:
    vm = psutil.virtual_memory()
    row: dict = {
        "elapsed_sec": elapsed,
        "timestamp_utc": utc(),
        "ram_system_pct": round(vm.percent, 1),
        "ram_system_used_gb": round(vm.used / (1024**3), 2),
        "listeners_5000": listener_pids(),
        "snapshot_sizes_kb_top": snapshot_sizes(),
    }
    if pid:
        try:
            p = psutil.Process(pid)
            mem = p.memory_info()
            row.update(
                {
                    "novus_pid": pid,
                    "novus_ram_mb": round(mem.rss / (1024 * 1024), 1),
                    "novus_cpu_pct": round(p.cpu_percent(interval=0.1), 1),
                    "novus_threads": p.num_threads(),
                    "novus_thread_detail_count": len(thread_inventory(pid)),
                    "novus_children": named_threads(pid),
                    "novus_handles": getattr(p, "num_handles", lambda: None)(),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            row["novus_error"] = str(exc)
    try:
        from services.resource_backpressure_service import get_status

        row["backpressure"] = get_status()
    except Exception:
        row["backpressure"] = None
    return row


def main() -> int:
    pid = find_novus_pid()
    if not pid:
        print("NOVUS main.py not running — start server first or pass PID via NOVUS_PID env")
        pid_env = os.environ.get("NOVUS_PID")
        if pid_env:
            pid = int(pid_env)
        else:
            return 1

    t0 = time.time()
    samples = []
    targets = set(SAMPLE_POINTS)
    next_target = min(targets)

    while True:
        elapsed = int(time.time() - t0)
        if elapsed >= next_target:
            samples.append(sample_point(pid, elapsed))
            targets.discard(next_target)
            if not targets:
                break
            next_target = min(targets)
        if elapsed > max(SAMPLE_POINTS) + 5:
            break
        time.sleep(1)

    report = {
        "generated_at_utc": utc(),
        "novus_pid": pid,
        "sample_points_sec": SAMPLE_POINTS,
        "samples": samples,
        "analysis_notes": [],
    }

    # Delta analysis between samples
    if len(samples) >= 2:
        for i in range(1, len(samples)):
            prev, cur = samples[i - 1], samples[i]
            delta_ram = (cur.get("novus_ram_mb") or 0) - (prev.get("novus_ram_mb") or 0)
            delta_sys = cur.get("ram_system_pct", 0) - prev.get("ram_system_pct", 0)
            report["analysis_notes"].append(
                {
                    "window": f"{prev['elapsed_sec']}s->{cur['elapsed_sec']}s",
                    "novus_ram_delta_mb": round(delta_ram, 1),
                    "system_ram_delta_pct": round(delta_sys, 1),
                }
            )

    out_json = OUT_DIR / "RAM_FORENSIC_PROFILE.json"
    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
