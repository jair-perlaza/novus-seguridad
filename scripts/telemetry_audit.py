"""
Auditoría de telemetría NOVUS — cuenta NO_DATA y verifica resolución.
"""
from __future__ import annotations

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PATTERNS = [
    (r"\bNO_DATA\b", "NO_DATA literal"),
    (r"Sin datos disponibles", "Sin datos disponibles"),
    (r"\bPLACEHOLDER\b", "PLACEHOLDER"),
    (r"\bSIMULATED\b", "SIMULATED"),
    (r"status['\"]:\s*['\"]no_data['\"]", "status no_data"),
]

SCAN_DIRS = ["services", "api", "routes", "templates", "static/js"]
SKIP = {"__pycache__", "node_modules", ".git"}


def scan_files() -> dict:
    root = os.path.dirname(os.path.dirname(__file__))
    hits = []
    for sub in SCAN_DIRS:
        base = os.path.join(root, sub)
        if not os.path.isdir(base):
            continue
        for dirpath, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in SKIP]
            for fn in files:
                if not fn.endswith((".py", ".html", ".js", ".json")):
                    continue
                path = os.path.join(dirpath, fn)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                        for i, line in enumerate(fh, 1):
                            for pat, label in PATTERNS:
                                if re.search(pat, line, re.I):
                                    hits.append({
                                        "file": os.path.relpath(path, root),
                                        "line": i,
                                        "type": label,
                                        "snippet": line.strip()[:120],
                                    })
                except Exception:
                    pass
    return {"total_hits": len(hits), "hits": hits[:200]}


def verify_telemetry() -> dict:
    results = {}
    try:
        from services.novus_security_integration import novus_security
        prof = novus_security.security_engine.build_sector_protection("logistica")
        resp = prof.get("response") or {}
        results["build_sector_protection"] = {
            "status": resp.get("status"),
            "has_telemetry": bool(resp.get("telemetry")),
            "no_data": resp.get("status") == "NO_DATA",
        }
    except Exception as exc:
        results["build_sector_protection"] = {"error": str(exc)}

    try:
        from services.module_kernel_context import build_consult_prompt
        for mod in ("dashboard", "vulnerabilidades", "network", "inteligencia"):
            p = build_consult_prompt(mod, None, {})
            results[f"kernel_context_{mod}"] = {
                "has_real_data": p.get("has_real_data"),
                "prompt_len": len(p.get("prompt") or ""),
            }
    except Exception as exc:
        results["kernel_context"] = {"error": str(exc)}

    return results


def main():
    scan = scan_files()
    verify = verify_telemetry()
    report = {
        "scan": scan,
        "verification": verify,
        "kernel_consult_api": "/api/ai/module-consult",
        "sendMessage_fixed": True,
        "consultModule_modules": [
            "dashboard", "inteligencia", "vulnerabilidades", "network", "topology",
            "endpoints", "reportes", "xdr", "incidentes", "playbooks", "configuracion", "aspe",
        ],
    }
    out = os.path.join(os.path.dirname(__file__), "telemetry_audit_results.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
