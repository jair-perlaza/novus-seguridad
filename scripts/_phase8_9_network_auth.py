#!/usr/bin/env python3
"""Fase 8 — network endpoints secuenciales + Fase 9 auth probe."""
from __future__ import annotations

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

NETWORK_SEQ = [
    "/api/network/info",
    "/api/network/nodes",
    "/api/network/ndr",
    "/api/network/topology",
]

ENTERPRISE_AUTH_PROBE = "/api/asm/dashboard"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sys_metrics(pid: int | None) -> dict:
    vm = psutil.virtual_memory()
    out = {"ram_system_pct": round(vm.percent, 1), "ram_used_gb": round(vm.used / (1024**3), 2)}
    if pid:
        try:
            p = psutil.Process(pid)
            out.update(
                {
                    "process_ram_mb": round(p.memory_info().rss / (1024 * 1024), 1),
                    "process_cpu_pct": round(p.cpu_percent(interval=0.15), 1),
                    "process_threads": p.num_threads(),
                }
            )
        except psutil.NoSuchProcess:
            pass
    return out


def find_pid() -> int | None:
    import subprocess

    for line in subprocess.check_output(["netstat", "-ano"], text=True, errors="replace").splitlines():
        if ":5000" in line and "LISTENING" in line:
            pid = int(line.split()[-1])
            return pid
    return None


def login() -> requests.Session:
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=20)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    token = csrf.group(1) if csrf else ""
    s.post(f"{BASE}/login", data={"email": QA[0], "password": QA[1], "csrf_token": token}, timeout=25)
    return s


def probe_one(s: requests.Session, path: str, timeout: float = 10.0) -> dict:
    pid = find_pid()
    before = sys_metrics(pid)
    t0 = time.perf_counter()
    row = {"path": path, "before": before}
    try:
        r = s.get(BASE + path, timeout=timeout)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        body = {}
        try:
            body = r.json()
        except Exception:
            pass
        recovering = isinstance(body, dict) and (
            body.get("status") == "recovering" or body.get("_novusRecovery")
        )
        row.update(
            {
                "http": r.status_code,
                "ms": ms,
                "recovering": recovering,
                "body_status": body.get("status") if isinstance(body, dict) else None,
                "login_required": body.get("login_required") if isinstance(body, dict) else None,
                "pending": body.get("pending") if isinstance(body, dict) else None,
                "cache_hit": body.get("cache_hit") if isinstance(body, dict) else None,
                "node_count": body.get("node_count") or body.get("nodes_count") or (
                    len(body.get("nodes", [])) if isinstance(body.get("nodes"), list) else None
                ),
                "keys": list(body.keys())[:12] if isinstance(body, dict) else [],
                "error": body.get("error") if isinstance(body, dict) else None,
            }
        )
    except Exception as exc:
        row.update({"ms": round((time.perf_counter() - t0) * 1000, 1), "error": str(exc)[:200]})
    row["after"] = sys_metrics(find_pid())
    return row


def main() -> None:
    pid = find_pid()
    if not pid:
        print(json.dumps({"error": "no listener on 5000"}))
        return

    s = login()
    results = []
    aborted = False
    for path in NETWORK_SEQ:
        m = sys_metrics(pid)
        if m["ram_system_pct"] > 85:
            results.append({"aborted_at": path, "reason": "RAM > 85%", "metrics": m})
            aborted = True
            break
        results.append(probe_one(s, path))
        time.sleep(2)

    # Phase 9: enterprise auth vs backend
    auth_probe = probe_one(s, ENTERPRISE_AUTH_PROBE, timeout=8.0)
    unauth = requests.Session().get(BASE + ENTERPRISE_AUTH_PROBE, timeout=8)
    unauth_body = {}
    try:
        unauth_body = unauth.json()
    except Exception:
        pass

    report = {
        "generated_at_utc": utc(),
        "server_pid": pid,
        "network_sequential": results,
        "aborted_ram": aborted,
        "enterprise_auth_analysis": {
            "endpoint": ENTERPRISE_AUTH_PROBE,
            "authenticated": auth_probe,
            "unauthenticated": {
                "http": unauth.status_code,
                "body_status": unauth_body.get("status") if isinstance(unauth_body, dict) else None,
                "login_required": unauth_body.get("login_required") if isinstance(unauth_body, dict) else None,
                "recovering": unauth_body.get("_novusRecovery") if isinstance(unauth_body, dict) else None,
            },
        },
    }
    out = OUT / "PHASE8_9_NETWORK_AUTH.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
