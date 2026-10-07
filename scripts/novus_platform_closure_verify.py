#!/usr/bin/env python3
"""Verificación de cierre funcional NOVUS — HTTP real contra módulos principales."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_release_candidate" / "NOVUS_PLATFORM_CLOSURE_VERIFY.json"
BASE = "http://127.0.0.1:5000"

MODULES = [
    ("/api/tenant/scope", "tenant_scope", {"monitoring_enabled": bool}),
    ("/api/dashboard/live", "dashboard", {}),
    ("/api/network/nodes?trigger_discovery=false", "network", {"status": str}),
    ("/api/monitoring/network-config", "network_config", {"operational": bool}),
    ("/api/security/summary", "security_summary", {}),
    ("/api/security/threats", "threats", {}),
    ("/api/security/vulnerabilities", "vulnerabilities", {}),
    ("/api/security/endpoints", "endpoints", {}),
    ("/api/reports", "reports", {}),
    ("/api/search?q=alert", "search", {}),
    ("/api/system/evidence-center", "evidence", {}),
    ("/api/system/login-sessions", "sessions", {}),
    ("/api/health/status", "health", {}),
    ("/api/network/topology", "topology", {}),
]

RAW_MARKERS = (
    "traceback",
    "configuración para la interfaz",
    "raw_excerpt",
    "exception:",
    "file \"c:\\\\novus",
)
FAKE_MARKERS = ("simulated", "fixture", "demo threat", "fake_", "lorem ipsum")


def _walk(obj, path=""):
    hits = []
    if isinstance(obj, dict):
        if "raw_excerpt" in obj:
            hits.append(f"{path}.raw_excerpt")
        for k, v in obj.items():
            hits.extend(_walk(v, f"{path}.{k}" if path else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits.extend(_walk(v, f"{path}[{i}]"))
    elif isinstance(obj, str):
        low = obj.lower()
        for m in RAW_MARKERS + FAKE_MARKERS:
            if m in low and "configuracion" not in low:
                hits.append(f"{path}:{m[:30]}")
    return hits


def main() -> int:
    import requests
    from scripts.reports_regression_probe import login

    OUT.parent.mkdir(parents=True, exist_ok=True)
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=30)
    if r.status_code != 200:
        OUT.write_text(json.dumps({"pass": False, "error": "login_unreachable"}), encoding="utf-8")
        return 1
    login(s)
    report = {"modules": [], "pass": True, "monitoring_auto": None}
    for path, name, checks in MODULES:
        row = {"name": name, "path": path}
        try:
            resp = s.get(f"{BASE}{path}", timeout=120)
            row["http"] = resp.status_code
            body = resp.json() if "json" in (resp.headers.get("content-type") or "") else {}
            row["body_status"] = body.get("status")
            row["hits"] = _walk(body)
            row["pass"] = resp.status_code == 200 and not row["hits"]
            if name == "tenant_scope":
                report["monitoring_auto"] = body.get("monitoring_enabled")
            if name == "network":
                row["observed_count"] = body.get("count")
                row["not_blocked"] = body.get("status") != "monitoring_not_configured"
                row["pass"] = row["pass"] and row["not_blocked"]
            for key, typ in checks.items():
                if key in body and not isinstance(body.get(key), typ):
                    row["pass"] = False
                    row.setdefault("type_errors", []).append(key)
            if not row["pass"]:
                report["pass"] = False
        except Exception as exc:
            row["pass"] = False
            row["error"] = str(exc)[:200]
            report["pass"] = False
        report["modules"].append(row)
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"pass": report["pass"], "monitoring_auto": report["monitoring_auto"], "modules": len(report["modules"])}))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
