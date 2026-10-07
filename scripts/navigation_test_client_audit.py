#!/usr/bin/env python3
"""Medición navegación vía test_client (sin saturar servidor live)."""
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "navigation_network_optimization"
OUT.mkdir(parents=True, exist_ok=True)

QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")


def measure(phase: str):
    from core.app import create_app

    app = create_app("development")
    client = app.test_client()
    r = client.get("/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.get_data(as_text=True))
    csrf = csrf.group(1) if csrf else ""
    client.post("/login", data={"email": QA[0], "password": QA[1], "csrf_token": csrf}, follow_redirects=True)

    modules = [
        ("SOC", "/security-operations-center"),
        ("ASM", "/asset-intelligence"),
        ("VIEM", "/vulnerability-intelligence"),
        ("IMCM", "/incident-management"),
        ("TIE", "/threat-intelligence-center"),
        ("Network", "/network"),
    ]
    rows = []
    for name, mod_path in modules:
        client.get(mod_path)
        t0 = time.perf_counter()
        dash = client.get("/dashboard")
        html_ms = round((time.perf_counter() - t0) * 1000, 1)
        apis = []
        for p in ["/api/dashboard/live", "/api/security/summary", "/api/network/nodes", "/api/network/info"]:
            t1 = time.perf_counter()
            ar = client.get(p)
            apis.append({"path": p, "status": ar.status_code, "ms": round((time.perf_counter() - t1) * 1000, 1)})
        rows.append({"from": name, "dashboard_html_ms": html_ms, "dashboard_bytes": len(dash.data or b""), "apis": apis})

    outfile = OUT / f"NAVIGATION_{phase}.json"
    outfile.write_text(json.dumps({"phase": phase, "transport": "flask_test_client", "rows": rows}, indent=2), encoding="utf-8")
    avg = round(sum(r["dashboard_html_ms"] for r in rows) / len(rows), 1)
    print(json.dumps({"phase": phase, "avg_dashboard_html_ms": avg, "file": str(outfile)}, indent=2))
    return rows


if __name__ == "__main__":
    measure(sys.argv[1] if len(sys.argv) > 1 else "AFTER")
