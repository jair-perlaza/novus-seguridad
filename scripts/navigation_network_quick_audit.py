#!/usr/bin/env python3
"""Medición rápida módulo → Dashboard + Network proof."""
from __future__ import annotations

import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "navigation_network_optimization"
OUT.mkdir(parents=True, exist_ok=True)
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")


def login():
    import requests
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=30)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    csrf = csrf.group(1) if csrf else ""
    s.post(f"{BASE}/login", data={"email": QA[0], "password": QA[1], "csrf_token": csrf}, timeout=60)
    return s


def timed_get(session, path, timeout=30):
    t0 = time.perf_counter()
    r = session.get(f"{BASE}{path}", timeout=timeout)
    return {
        "path": path,
        "status": r.status_code,
        "ms": round((time.perf_counter() - t0) * 1000, 1),
        "bytes": len(r.content or b""),
    }


def nav_row(session, module, mod_path):
    timed_get(session, mod_path, timeout=60)
    html = timed_get(session, "/dashboard", timeout=60)
    apis = [timed_get(session, p, timeout=30) for p in [
        "/api/dashboard/live",
        "/api/security/summary",
        "/api/network/nodes",
        "/api/network/info",
    ]]
    return {"from": module, "dashboard_html": html, "apis": apis}


def main():
    phase = sys.argv[1] if len(sys.argv) > 1 else "AFTER"
    session = login()
    rows = []
    modules = [
        ("SOC", "/security-operations-center"),
        ("ASM", "/asset-intelligence"),
        ("VIEM", "/vulnerability-intelligence"),
        ("IMCM", "/incident-management"),
        ("TIE", "/threat-intelligence-center"),
        ("Network", "/network"),
    ]
    if phase == "AFTER" and len(sys.argv) > 2 and sys.argv[2] == "quick":
        modules = modules[:3]

    for mod, path in modules:
        try:
            rows.append(nav_row(session, mod, path))
        except Exception as exc:
            rows.append({"from": mod, "error": str(exc)})

    outfile = OUT / f"NAVIGATION_{phase}.json"
    outfile.write_text(json.dumps({"phase": phase, "rows": rows}, indent=2), encoding="utf-8")

    # Network pipeline inline
    from services.network_scanner import network_scanner
    from services.network_monitor_engine import get_monitor_status
    from services.network_scan_coordinator import get_network_context, get_coordinator_status

    pipe = {
        "monitor": get_monitor_status(),
        "cache_info": network_scanner.get_cache_info(),
        "nodes_count": len(network_scanner.get_cached_nodes() or []),
        "meta": network_scanner.get_network_meta(),
        "context": get_network_context(),
        "coordinator": get_coordinator_status(),
    }
    (OUT / "NETWORK_SNAPSHOT_STATUS.json").write_text(json.dumps(pipe, indent=2, ensure_ascii=False), encoding="utf-8")

    apis = {}
    for p in ["/api/network/info", "/api/network/nodes", "/api/network/monitor/status", "/api/network/ndr"]:
        t0 = time.perf_counter()
        r = session.get(f"{BASE}{p}", timeout=45)
        try:
            body = r.json()
        except Exception:
            body = {}
        apis[p] = {
            "status": r.status_code,
            "ms": round((time.perf_counter() - t0) * 1000, 1),
            "body": body,
        }
    (OUT / "NETWORK_API_PROOF.json").write_text(json.dumps(apis, indent=2, ensure_ascii=False), encoding="utf-8")

    print(json.dumps({
        "phase": phase,
        "avg_dashboard_html_ms": round(sum(x["dashboard_html"]["ms"] for x in rows) / len(rows), 1),
        "nodes_count": pipe["nodes_count"],
        "monitor_active": pipe["monitor"].get("active"),
        "out": str(outfile),
    }, indent=2))


if __name__ == "__main__":
    main()
