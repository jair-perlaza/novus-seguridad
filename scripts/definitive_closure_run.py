#!/usr/bin/env python3
"""
Orquestador de cierre definitivo NOVUS — seed, sesiones, diagnóstico, load test, regresión, informes.
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
PY = sys.executable
OUT = ROOT / "data" / "production_closure"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_script(name: str, env: dict | None = None, timeout: int = 3600) -> dict:
    path = ROOT / "scripts" / name
    if not path.is_file():
        return {"script": name, "ok": False, "error": "missing"}
    merged = {**os.environ, **(env or {})}
    t0 = time.perf_counter()
    try:
        r = subprocess.run(
            [PY, str(path)],
            cwd=str(ROOT),
            env=merged,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "script": name,
            "ok": r.returncode == 0,
            "exit_code": r.returncode,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
            "stdout_tail": (r.stdout or "")[-2000:],
            "stderr_tail": (r.stderr or "")[-1000:],
        }
    except subprocess.TimeoutExpired:
        return {"script": name, "ok": False, "error": "timeout", "elapsed_ms": timeout * 1000}
    except Exception as exc:
        return {"script": name, "ok": False, "error": str(exc)}


def wait_for_server(base: str = "http://127.0.0.1:5000", timeout: float = 90.0) -> bool:
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/login", timeout=5) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False


def main() -> int:
    os.chdir(ROOT)
    steps = []

    steps.append(run_script("scalability_seed_loadtest_users.py", timeout=120))

    if not wait_for_server():
        steps.append({"step": "server_wait", "ok": False, "note": "Start NOVUS before load phases"})
        summary = {"generated_at": utc(), "steps": steps, "PRODUCTION_READY": "FAIL"}
        (OUT / "definitive_closure_run.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(json.dumps(summary, indent=2))
        return 1

    steps.append(run_script("scalability_build_loadtest_sessions.py", timeout=900))
    steps.append(run_script("scalability_performance_diagnosis.py", timeout=600))
    steps.append(
        run_script(
            "scalability_multiuser_load_test.py",
            env={
                "NOVUS_LOADTEST_SKIP_BUILD": "1",
            },
            timeout=7200,
        )
    )
    steps.append(run_script("scalability_tenant_isolation_http.py", timeout=120))
    steps.append(run_script("tenant_isolation_service_test.py", timeout=180))
    steps.append(run_script("final_closure_reports.py", timeout=60))

    multi_path = OUT / "multiuser_load_test_report.json"
    prod_ready = "FAIL"
    if multi_path.is_file():
        try:
            prod_ready = json.loads(multi_path.read_text(encoding="utf-8")).get("PRODUCTION_READY", "FAIL")
        except Exception:
            pass

    summary = {
        "generated_at": utc(),
        "steps": steps,
        "PRODUCTION_READY": prod_ready,
    }
    (OUT / "definitive_closure_run.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"PRODUCTION_READY": prod_ready, "steps_ok": sum(1 for s in steps if s.get("ok"))}, indent=2))
    return 0 if prod_ready == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
