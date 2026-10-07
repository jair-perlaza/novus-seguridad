#!/usr/bin/env python3
"""
Pipeline de cierre definitivo NOVUS — reinicio, sesiones, load test, informes finales.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "data" / "production_closure"
PY = sys.executable


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(cmd: list, env: dict | None = None, timeout: int = 3600) -> dict:
    t0 = time.perf_counter()
    try:
        p = subprocess.run(cmd, cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=timeout)
        return {
            "cmd": cmd,
            "exit_code": p.returncode,
            "stdout": (p.stdout or "")[-4000:],
            "stderr": (p.stderr or "")[-2000:],
            "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
        }
    except Exception as exc:
        return {"cmd": cmd, "exit_code": -1, "error": str(exc)}


def restart_server() -> dict:
    import psutil

    killed = []
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and getattr(c.laddr, "port", None) == 5000 and c.status == "LISTEN" and c.pid:
            try:
                psutil.Process(c.pid).terminate()
                killed.append(c.pid)
            except Exception:
                pass
    time.sleep(3)
    env = os.environ.copy()
    env.setdefault("NOVUS_WSGI", "waitress")
    env.setdefault("NOVUS_WAITRESS_THREADS", "96")
    env.setdefault("NOVUS_LOADTEST_USER_COUNT", "1000")
    proc = subprocess.Popen(
        [PY, str(ROOT / "main.py")],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(30):
        time.sleep(1)
        try:
            import urllib.request
            urllib.request.urlopen("http://127.0.0.1:5000/login", timeout=3)
            return {"ok": True, "pid": proc.pid, "killed": killed}
        except Exception:
            continue
    return {"ok": False, "pid": proc.pid, "killed": killed}


def main() -> int:
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    pipeline = {"started_at": utc(), "steps": []}

    env = os.environ.copy()
    env.setdefault("NOVUS_WSGI", "waitress")
    env.setdefault("NOVUS_WAITRESS_THREADS", "96")
    env.setdefault("NOVUS_LOADTEST_USER_COUNT", "1000")
    env.setdefault("NOVUS_LOADTEST_SESSION_COUNT", "1000")
    pipeline["steps"].append({"restart": restart_server()})

    env["NOVUS_LOADTEST_SKIP_BUILD"] = "0"
    pipeline["steps"].append(run([PY, str(ROOT / "scripts/scalability_seed_loadtest_users.py")], env=env, timeout=120))
    pipeline["steps"].append(run([PY, str(ROOT / "scripts/scalability_build_loadtest_sessions.py")], env=env, timeout=900))

    env["NOVUS_LOADTEST_SKIP_BUILD"] = "1"
    pipeline["steps"].append(run([PY, str(ROOT / "scripts/scalability_multiuser_load_test.py")], env=env, timeout=1800))
    pipeline["steps"].append(run([PY, str(ROOT / "scripts/scalability_performance_diagnosis.py")], env=env, timeout=600))
    pipeline["steps"].append(run([PY, str(ROOT / "scripts/scalability_tenant_isolation_http.py")], env=env, timeout=120))
    pipeline["steps"].append(run([PY, str(ROOT / "scripts/tenant_isolation_service_test.py")], env=env, timeout=120))

    pipeline["steps"].append(run([PY, str(ROOT / "scripts/final_closure_reports.py")], env=env, timeout=60))
    pipeline["finished_at"] = utc()
    (OUT_DIR / "final_closure_pipeline.json").write_text(json.dumps(pipeline, indent=2), encoding="utf-8")
    multi = json.loads((OUT_DIR / "multiuser_load_test_report.json").read_text(encoding="utf-8"))
    print(json.dumps({"600": multi.get("600_CONCURRENT"), "PRODUCTION_READY": multi.get("PRODUCTION_READY")}, indent=2))
    return 0 if multi.get("PRODUCTION_READY") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
