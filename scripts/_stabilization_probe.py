#!/usr/bin/env python3
"""Prueba controlada post-estabilización — secuencial, sin auditoría masiva."""
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
OUT.mkdir(parents=True, exist_ok=True)
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")
PATHS = [
    "/api/network/info",
    "/api/network/nodes",
    "/api/network/ndr",
    "/api/network/topology",
    "/api/security/summary",
    "/api/dashboard/live",
]


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def listeners() -> list[int]:
    out = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
    pids = []
    for line in out.splitlines():
        if ":5000" in line and "LISTENING" in line:
            pid = int(line.split()[-1])
            pids.append(pid)
    return pids


def login() -> requests.Session:
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=20)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    token = csrf.group(1) if csrf else ""
    s.post(f"{BASE}/login", data={"email": QA[0], "password": QA[1], "csrf_token": token}, timeout=25)
    return s


def probe(s: requests.Session, path: str) -> dict:
    vm = psutil.virtual_memory()
    t0 = time.perf_counter()
    row = {"path": path, "ram_system_pct_before": round(vm.percent, 1)}
    try:
        url = BASE + path
        if "nodes" in path:
            url += "?trigger_discovery=false"
        r = s.get(url, timeout=12)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        body = r.json()
        row.update(
            {
                "http": r.status_code,
                "ms": ms,
                "status": body.get("status"),
                "scan_status": body.get("scan_status"),
                "node_count": body.get("count") or body.get("node_count") or len(body.get("nodes") or []),
                "snapshot_pending": body.get("snapshot_pending"),
                "keys": list(body.keys())[:10],
            }
        )
    except Exception as exc:
        row.update({"ms": round((time.perf_counter() - t0) * 1000, 1), "error": str(exc)[:180]})
    row["ram_system_pct_after"] = round(psutil.virtual_memory().percent, 1)
    return row


def main() -> None:
    ram_boot = round(psutil.virtual_memory().percent, 1)
    lis = listeners()
    report = {
        "generated_at_utc": utc(),
        "ram_before_probes_pct": ram_boot,
        "listeners_port_5000": len(lis),
        "listener_pids": lis,
        "probes": [],
    }
    if len(lis) != 1:
        report["error"] = f"Expected 1 listener, found {len(lis)}"
        OUT.joinpath("STABILIZATION_PROBE.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 1

    s = login()
    for path in PATHS:
        vm = psutil.virtual_memory()
        if vm.percent > 90:
            report["probes"].append({"aborted": path, "reason": "RAM > 90%", "ram_pct": vm.percent})
            break
        report["probes"].append(probe(s, path))
        time.sleep(3)

    report["ram_after_probes_pct"] = round(psutil.virtual_memory().percent, 1)
    OUT.joinpath("STABILIZATION_PROBE.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
