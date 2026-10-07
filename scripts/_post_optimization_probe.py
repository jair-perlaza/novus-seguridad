#!/usr/bin/env python3
"""FASE 10 — verificación secuencial post-optimización."""
from __future__ import annotations

import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "novus_process_audit"
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")
PATHS = [
    "/login",
    "/api/health/status",
    "/api/dashboard/live",
    "/api/security/summary",
    "/api/network/info",
    "/api/network/nodes?trigger_discovery=false&include_context=false",
    "/api/network/ndr",
    "/api/network/topology",
    "/api/ai/kernel/knowledge-status",
]


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def listeners() -> list[int]:
    pids = []
    out = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
    for line in out.splitlines():
        if ":5000" in line and "LISTENING" in line:
            pids.append(int(line.split()[-1]))
    return pids


def login_session() -> requests.Session | None:
    s = requests.Session()
    try:
        r = s.get(f"{BASE}/login", timeout=15)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
        token = csrf.group(1) if csrf else ""
        s.post(f"{BASE}/login", data={"email": QA[0], "password": QA[1], "csrf_token": token}, timeout=20)
        return s
    except Exception:
        return None


def probe(path: str, session: requests.Session | None) -> dict:
    vm = psutil.virtual_memory()
    client = session or requests
    t0 = time.perf_counter()
    row = {"path": path, "ram_pct_before": round(vm.percent, 1)}
    try:
        r = client.get(BASE + path, timeout=15)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        body = {}
        try:
            body = r.json()
        except Exception:
            pass
        row.update({
            "http": r.status_code,
            "ms": ms,
            "status": body.get("status") if isinstance(body, dict) else None,
            "nodes": len(body.get("nodes") or []) if isinstance(body, dict) else None,
            "scan_status": body.get("scan_status") if isinstance(body, dict) else None,
        })
    except Exception as exc:
        row.update({"ms": round((time.perf_counter() - t0) * 1000, 1), "error": str(exc)[:160]})
    row["ram_pct_after"] = round(psutil.virtual_memory().percent, 1)
    return row


def main() -> int:
    report = {
        "generated_at_utc": utc(),
        "listeners": listeners(),
        "ram_before_pct": round(psutil.virtual_memory().percent, 1),
        "probes": [],
    }
    sess = None
    for path in PATHS:
        if path == "/login":
            report["probes"].append(probe(path, None))
            sess = login_session()
            continue
        if path.startswith("/api/") and sess is None:
            sess = login_session()
        report["probes"].append(probe(path, sess))
        time.sleep(2)
    report["ram_after_pct"] = round(psutil.virtual_memory().percent, 1)
    OUT.joinpath("POST_OPTIMIZATION_PROBE.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
