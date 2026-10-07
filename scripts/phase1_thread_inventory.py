#!/usr/bin/env python3
"""Inventario de threads del proceso NOVUS (PID en puerto 5000)."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "data" / "production_closure" / "phase1_thread_inventory.json"


def find_novus_process():
    import psutil

    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmd = " ".join(proc.info.get("cmdline") or [])
            if "main.py" not in cmd:
                continue
            p = psutil.Process(proc.info["pid"])
            for c in p.connections(kind="inet"):
                if c.laddr and getattr(c.laddr, "port", None) == 5000:
                    return p
        except Exception:
            continue
    return None


def main() -> int:
    proc = find_novus_process()
    if not proc:
        report = {"error": "NOVUS process on port 5000 not found", "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 1

    import psutil

    mem = proc.memory_info()
    threads = proc.threads()
    report = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pid": proc.pid,
        "thread_count": proc.num_threads(),
        "ram_mb": round(mem.rss / (1024 * 1024), 1),
        "cpu_pct": proc.cpu_percent(interval=0.5),
        "threads_sample": [
            {"id": t.id, "user_time": t.user_time, "system_time": t.system_time} for t in threads[:200]
        ],
        "waitress_threads_env": os.environ.get("NOVUS_WAITRESS_THREADS"),
    }
    try:
        from services.wsgi_server import recommended_threads

        report["waitress_threads_recommended"] = recommended_threads()
    except Exception:
        pass

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"thread_count": report["thread_count"], "ram_mb": report["ram_mb"], "out": str(OUT)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
