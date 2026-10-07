#!/usr/bin/env python3
"""Fases 6-7 — verificación de código cargado + health check mínimo."""
from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")
OUT = ROOT / "data" / "novus_process_audit"
OUT.mkdir(parents=True, exist_ok=True)

FIX_FILES = [
    ROOT / "services" / "enterprise_api_auth.py",
    ROOT / "services" / "novus_enterprise_knowledge.py",
    ROOT / "services" / "network_snapshot_service.py",
    ROOT / "main.py",
]

HEALTH_PATHS = [
    "/login",
    "/api/health/status",
    "/api/dashboard/live",
    "/api/security/summary",
    "/api/network/info",
    "/api/ai/kernel/knowledge-status",
]


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def file_sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()[:16]


def find_listener_pid() -> int | None:
    import subprocess

    out = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
    pids = set()
    for line in out.splitlines():
        if ":5000" in line and "LISTENING" in line:
            parts = line.split()
            if parts and parts[-1].isdigit():
                pids.add(int(parts[-1]))
    return next(iter(pids)) if len(pids) == 1 else (list(pids)[0] if pids else None)


def login_session() -> requests.Session:
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=15)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    token = csrf.group(1) if csrf else ""
    s.post(
        f"{BASE}/login",
        data={"email": QA[0], "password": QA[1], "csrf_token": token},
        timeout=20,
    )
    return s


def probe(s: requests.Session | None, path: str, auth: bool) -> dict:
    t0 = time.perf_counter()
    try:
        client = s if auth else requests
        r = (s if auth else requests.Session()).get(BASE + path, timeout=12)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        body = {}
        try:
            body = r.json()
        except Exception:
            pass
        recovering = isinstance(body, dict) and (
            body.get("status") == "recovering" or body.get("_novusRecovery")
        )
        return {
            "path": path,
            "auth": auth,
            "http": r.status_code,
            "ms": ms,
            "ok": r.status_code == 200 and not recovering,
            "recovering": recovering,
            "body_status": body.get("status") if isinstance(body, dict) else None,
            "login_required": body.get("login_required") if isinstance(body, dict) else None,
            "sample_keys": list(body.keys())[:8] if isinstance(body, dict) else [],
        }
    except Exception as exc:
        return {
            "path": path,
            "auth": auth,
            "ms": round((time.perf_counter() - t0) * 1000, 1),
            "ok": False,
            "error": str(exc)[:160],
        }


def main() -> None:
    vm = psutil.virtual_memory()
    pid = find_listener_pid()
    proc_evidence = {}
    if pid:
        p = psutil.Process(pid)
        proc_evidence = {
            "pid": pid,
            "name": p.name(),
            "cmdline": p.cmdline(),
            "cwd": p.cwd(),
            "start": datetime.fromtimestamp(p.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
            "start_epoch": p.create_time(),
            "threads": p.num_threads(),
            "ram_mb": round(p.memory_info().rss / (1024 * 1024), 1),
            "cpu_pct": round(p.cpu_percent(interval=0.2), 1),
        }

    fix_evidence = []
    latest_fix_mtime = 0.0
    for fp in FIX_FILES:
        if fp.is_file():
            st = fp.stat()
            latest_fix_mtime = max(latest_fix_mtime, st.st_mtime)
            fix_evidence.append(
                {
                    "file": str(fp.relative_to(ROOT)),
                    "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "sha256_prefix": file_sha256(fp),
                }
            )

    code_loaded_proof = {
        "process_started_after_latest_fix": bool(
            proc_evidence.get("start_epoch", 0) > latest_fix_mtime
        ),
        "latest_fix_mtime": datetime.fromtimestamp(latest_fix_mtime).strftime("%Y-%m-%d %H:%M:%S")
        if latest_fix_mtime
        else None,
        "fix_files_on_disk": fix_evidence,
        "enterprise_api_auth_exists": (ROOT / "services" / "enterprise_api_auth.py").is_file(),
        "novus_enterprise_knowledge_exists": (ROOT / "services" / "novus_enterprise_knowledge.py").is_file(),
    }

    # Unauthenticated /login only; rest authenticated
    probes = [probe(None, "/login", auth=False)]
    try:
        sess = login_session()
        for path in HEALTH_PATHS[1:]:
            probes.append(probe(sess, path, auth=True))
    except Exception as exc:
        probes.append({"login_error": str(exc)})

    vm2 = psutil.virtual_memory()
    if pid:
        p = psutil.Process(pid)
        proc_after = {
            "ram_mb": round(p.memory_info().rss / (1024 * 1024), 1),
            "cpu_pct": round(p.cpu_percent(interval=0.2), 1),
            "threads": p.num_threads(),
        }
    else:
        proc_after = {}

    import subprocess

    listeners = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
    listener_count = sum(
        1 for line in listeners.splitlines() if ":5000" in line and "LISTENING" in line
    )

    report = {
        "generated_at_utc": utc(),
        "server": proc_evidence,
        "listeners_port_5000": listener_count,
        "code_loaded_proof": code_loaded_proof,
        "ram_system_pct_before": round(vm.percent, 1),
        "ram_system_pct_after_health": round(vm2.percent, 1),
        "process_after_health": proc_after,
        "health_probes": probes,
    }
    out_path = OUT / "PHASE6_7_HEALTH_CHECK.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
