#!/usr/bin/env python3
"""Regresión final NOVUS V1 — post-remediación datos 100% reales."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_release_candidate" / "NOVUS_V1_FINAL_REGRESSION.json"
BASE = "http://127.0.0.1:5000"

QA_MARKERS = (
    "QA-NOVUS-2026",
    "TEST-PORT-9999",
    "203.0.113.",
    "simulated",
    "fixture",
)


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_script(name: str, *args: str) -> Dict[str, Any]:
    cmd = [sys.executable, str(ROOT / "scripts" / name), *args]
    p = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=600)
    return {
        "script": name,
        "exit_code": p.returncode,
        "stdout_tail": (p.stdout or "")[-2000:],
        "stderr_tail": (p.stderr or "")[-1000:],
        "pass": p.returncode == 0,
    }


def check_v1_surface() -> Dict[str, Any]:
    import requests
    from services.v1_runtime_surface import client_runtime_active, is_v1_nav_route_visible

    hidden = [k for k in (
        "deception_center", "csv_bas_center", "threat_intel", "siem", "soc_center"
    ) if not is_v1_nav_route_visible(k)]
    return {
        "name": "v1_surface",
        "client_runtime_active": client_runtime_active(),
        "hidden_nav_keys": hidden,
        "pass": client_runtime_active() and len(hidden) >= 4,
    }


def check_lab_search() -> Dict[str, Any]:
    import requests

    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=30)
    if r.status_code != 200:
        return {"name": "search_lab", "pass": False, "error": "login_page_unreachable"}
    from scripts.reports_regression_probe import login

    login(s)
    r2 = s.get(f"{BASE}/api/search?q=TEST-PORT-9999", timeout=60)
    body = r2.json() if r2.headers.get("content-type", "").startswith("application/json") else {}
    hits = []
    for item in body.get("results") or body.get("items") or []:
        blob = json.dumps(item, ensure_ascii=False).lower()
        for m in QA_MARKERS:
            if m.lower() in blob:
                hits.append(m)
    return {"name": "search_lab", "pass": not hits, "contamination": sorted(set(hits))}


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    report: Dict[str, Any] = {"generated_at_utc": utc(), "checks": []}

    report["checks"].append(run_script("quarantine_lab_runtime_data.py"))
    report["checks"].append(run_script("tenant_isolation_service_test.py"))
    report["checks"].append(run_script("novus_v1_clean_tenant_e2e.py"))
    report["checks"].append(run_script("reports_regression_probe.py"))
    report["checks"].append(check_v1_surface())
    try:
        report["checks"].append(check_lab_search())
    except Exception as exc:
        report["checks"].append({"name": "search_lab", "pass": False, "error": str(exc)})
    report["checks"].append(run_script("novus_ui_response_integrity_probe.py"))
    passed = sum(1 for c in report["checks"] if c.get("pass"))
    total = len(report["checks"])
    report["summary"] = {"passed": passed, "total": total, "overall": passed == total}
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    return 0 if report["summary"]["overall"] else 1


if __name__ == "__main__":
    sys.exit(main())
