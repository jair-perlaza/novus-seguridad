#!/usr/bin/env python3
"""Detecta datos LAB/simulados o stdout OS crudo en respuestas API cliente."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

BASE = "http://127.0.0.1:5000"
OUT = ROOT / "data" / "novus_release_candidate" / "NOVUS_UI_RESPONSE_INTEGRITY.json"

QA_MARKERS = (
    "qa-novus-2026",
    "test-port-9999",
    "203.0.113.",
    "192.0.2.",
    "simulated",
    "fixture",
    "mock",
    "demo fixture",
    "eicar-standard",
)
RAW_OS_MARKERS = (
    "configuración para la interfaz",
    "configuration for interface",
    "servidores dns configurados a trav",
    "dns servers configured",
    "registrar con el sufijo",
    "traceback (most recent call last)",
)
RAW_OS_SKIP_KEYS = frozenset({"tenant_id", "nit_pyme", "company_id"})
RAW_OS_SKIP_SUBSTRINGS = ("/configuracion", "/configuración", "configuracion", "playbook_center")


def _walk(obj: Any, path: str = "") -> List[str]:
    hits: List[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else k
            if k == "raw_excerpt":
                hits.append(f"{p}:raw_excerpt_present")
            if k in RAW_OS_SKIP_KEYS:
                continue
            hits.extend(_walk(v, p))
        return hits
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            hits.extend(_walk(v, f"{path}[{i}]"))
        return hits
    if isinstance(obj, str):
        low = obj.lower()
        if any(skip in low for skip in RAW_OS_SKIP_SUBSTRINGS):
            return hits
        for m in QA_MARKERS:
            if m in low and "tenant_id" not in path:
                hits.append(f"{path}:qa_marker:{m}")
        for m in RAW_OS_MARKERS:
            if m in low:
                hits.append(f"{path}:raw_os:{m[:40]}")
    return hits


def main() -> int:
    import requests

    OUT.parent.mkdir(parents=True, exist_ok=True)
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=20)
    if r.status_code != 200:
        print(json.dumps({"pass": False, "error": "login_unreachable"}))
        return 1
    from scripts.reports_regression_probe import login

    login(s)
    endpoints = [
        ("/api/network/info", "network_info"),
        ("/api/network/nodes?trigger_discovery=false", "network_nodes"),
        ("/api/network-security-history/summary", "network_history_summary"),
        ("/api/security/summary", "security_summary"),
        ("/api/security/vulnerabilities", "vulnerabilities"),
        ("/api/security/threats", "threats"),
        ("/api/reports", "reports"),
        ("/api/search?q=alert", "search"),
        ("/api/health/status", "health"),
    ]
    report: Dict[str, Any] = {"checks": [], "pass": True}
    for path, name in endpoints:
        row: Dict[str, Any] = {"name": name, "path": path}
        try:
            resp = s.get(f"{BASE}{path}", timeout=90)
            row["http_status"] = resp.status_code
            body = resp.json() if "application/json" in (resp.headers.get("content-type") or "") else {}
            row["hits"] = _walk(body)
            row["pass"] = not row["hits"]
            if row["hits"]:
                report["pass"] = False
        except Exception as exc:
            row["pass"] = False
            row["error"] = str(exc)[:200]
            report["pass"] = False
        report["checks"].append(row)
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"pass": report["pass"], "failures": sum(1 for c in report["checks"] if not c.get("pass"))}))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
