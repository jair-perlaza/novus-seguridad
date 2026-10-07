#!/usr/bin/env python3
"""Start NOVUS for Phase 1 performance work."""
from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)

try:
    import psutil
except ImportError:
    psutil = None

if psutil:
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and getattr(c.laddr, "port", None) == 5000 and c.status == "LISTEN" and c.pid:
            try:
                psutil.Process(c.pid).terminate()
            except Exception:
                pass
    time.sleep(3)

env = os.environ.copy()
env["NOVUS_WSGI"] = "waitress"
env["NOVUS_WAITRESS_THREADS"] = env.get("NOVUS_WAITRESS_THREADS", "48")
env["NOVUS_LOADTEST_MODE"] = "1"
env["NOVUS_P1_HEAVY_DELAY_SEC"] = env.get("NOVUS_P1_HEAVY_DELAY_SEC", "7200")
env["NOVUS_ENGINE_RUNTIME_CACHE_TTL"] = "30"
env["NOVUS_FORCE_SINGLETON"] = "1"
env["NOVUS_SQLITE_BUSY_TIMEOUT_MS"] = env.get("NOVUS_SQLITE_BUSY_TIMEOUT_MS", "5000")
env["NOVUS_SQLITE_CONNECT_TIMEOUT_SEC"] = env.get("NOVUS_SQLITE_CONNECT_TIMEOUT_SEC", "5")
env["NOVUS_SQLITE_POOL_SIZE"] = env.get("NOVUS_SQLITE_POOL_SIZE", "16")
env["NOVUS_SQLITE_MAX_OVERFLOW"] = env.get("NOVUS_SQLITE_MAX_OVERFLOW", "16")
env["NOVUS_SWARM_BUS_WORKERS"] = env.get("NOVUS_SWARM_BUS_WORKERS", "3")
env["NOVUS_SWARM_BUS_PENDING_CAP"] = env.get("NOVUS_SWARM_BUS_PENDING_CAP", "48")
env["NOVUS_BG_POOL_WORKERS"] = env.get("NOVUS_BG_POOL_WORKERS", "3")
env["NOVUS_HTTP_ENDPOINT_CACHE_MAX"] = env.get("NOVUS_HTTP_ENDPOINT_CACHE_MAX", "192")
env["NOVUS_USER_CACHE_MAX"] = env.get("NOVUS_USER_CACHE_MAX", "1024")
env["NOVUS_WAITRESS_CONNECTION_LIMIT"] = env.get("NOVUS_WAITRESS_CONNECTION_LIMIT", "320")
env["NOVUS_WAITRESS_CHANNEL_TIMEOUT"] = env.get("NOVUS_WAITRESS_CHANNEL_TIMEOUT", "60")
env["NOVUS_WAITRESS_CLEANUP_INTERVAL"] = env.get("NOVUS_WAITRESS_CLEANUP_INTERVAL", "15")
env["NOVUS_PHASE3_WAVE_GAP_SEC"] = env.get("NOVUS_PHASE3_WAVE_GAP_SEC", "10")
# Phase3: prefer tighter defaults on constrained hosts (overridable via env)
env["NOVUS_SQLITE_POOL_SIZE"] = env.get("NOVUS_SQLITE_POOL_SIZE", "12")
env["NOVUS_SQLITE_MAX_OVERFLOW"] = env.get("NOVUS_SQLITE_MAX_OVERFLOW", "8")

log_path = ROOT / "data" / "production_closure" / "phase3_server_stdout.log"
log_path.parent.mkdir(parents=True, exist_ok=True)
logf = open(log_path, "w", encoding="utf-8", errors="replace")
proc = subprocess.Popen(
    [sys.executable, str(ROOT / "main.py")],
    cwd=str(ROOT),
    env=env,
    stdout=logf,
    stderr=subprocess.STDOUT,
)

ok = False
for i in range(60):
    time.sleep(1)
    try:
        urllib.request.urlopen("http://127.0.0.1:5000/login", timeout=3)
        print(f"SERVER_OK pid={proc.pid} wait={i}s")
        ok = True
        break
    except Exception:
        if proc.poll() is not None:
            print(f"SERVER_EXITED code={proc.returncode}")
            break

if not ok:
    print("SERVER_FAIL")
    try:
        print(log_path.read_text(encoding="utf-8", errors="replace")[-3000:])
    except Exception:
        pass
    sys.exit(1)
sys.exit(0)
