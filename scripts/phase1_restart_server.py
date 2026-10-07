#!/usr/bin/env python3
"""Restart NOVUS on :5000 for Phase 1 — Waitress 64 threads."""
from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import psutil

ROOT = Path(r"C:\NOVUS")


def kill_port_5000() -> list:
    killed = []
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and getattr(c.laddr, "port", None) == 5000 and c.pid:
            try:
                psutil.Process(c.pid).terminate()
                killed.append(c.pid)
            except Exception:
                pass
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or [])
            if "main.py" in cmd and str(ROOT) in cmd:
                psutil.Process(p.info["pid"]).terminate()
                killed.append(p.info["pid"])
        except Exception:
            pass
    time.sleep(4)
    for pid in list(killed):
        try:
            if psutil.pid_exists(pid):
                psutil.Process(pid).kill()
        except Exception:
            pass
    time.sleep(2)
    return killed


def main() -> int:
    killed = kill_port_5000()
    env = os.environ.copy()
    env["NOVUS_WSGI"] = "waitress"
    env["NOVUS_WAITRESS_THREADS"] = "64"
    env["NOVUS_LOADTEST_MODE"] = "1"
    env["NOVUS_ENGINE_RUNTIME_CACHE_TTL"] = "20"
    log = ROOT / "data" / "production_closure" / "phase1_server_stdout.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    fh = open(log, "w", encoding="utf-8", errors="replace")
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "main.py")],
        cwd=str(ROOT),
        env=env,
        stdout=fh,
        stderr=subprocess.STDOUT,
    )
    for i in range(60):
        time.sleep(1)
        try:
            urllib.request.urlopen("http://127.0.0.1:5000/login", timeout=5)
            print(f"OK pid={proc.pid} killed={killed} wait={i+1}s log={log}")
            return 0
        except Exception:
            if proc.poll() is not None:
                print(f"EXIT early code={proc.returncode} log={log}")
                return 1
    print(f"TIMEOUT pid={proc.pid} log={log}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
