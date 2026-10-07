#!/usr/bin/env python3
"""Diagnóstico recuperación NOVUS — solo lectura."""
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "recovery_diagnostic"
OUT.mkdir(parents=True, exist_ok=True)

QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")


def main():
    report = {"errors": [], "routes": [], "apis": [], "imports": []}

    # Import check
    modules = [
        "services.enterprise_snapshot_service",
        "api.tie",
        "api.sope",
        "api.imcm",
        "api.health_engine",
        "api.behavior_notifications",
        "main",
    ]
    for mod in modules:
        try:
            __import__(mod)
            report["imports"].append({"module": mod, "ok": True})
        except Exception as exc:
            report["imports"].append({"module": mod, "ok": False, "error": str(exc)})
            report["errors"].append({"type": "import", "module": mod, "error": str(exc)})

    from core.app import create_app

    app = create_app("development")
    client = app.test_client()

    r = client.get("/login")
    html = r.get_data(as_text=True)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    csrf = m.group(1) if m else ""
    r2 = client.post(
        "/login",
        data={"email": QA[0], "password": QA[1], "csrf_token": csrf},
        follow_redirects=True,
    )
    report["login"] = {"get": r.status_code, "post": r2.status_code, "csrf_found": bool(csrf)}

    paths = [
        "/dashboard",
        "/security-operations-center",
        "/asset-intelligence",
        "/vulnerability-intelligence",
        "/incident-management",
        "/threat-intelligence-center",
        "/playbook-center",
        "/security-data-lake",
        "/security-data-analytics",
        "/identity-intelligence",
        "/identity-attack-path",
        "/deception-center",
        "/network",
        "/endpoints",
        "/health-center",
        "/btde",
        "/zdde",
        "/swarm-defense",
        "/swarm-mesh",
        "/wsae",
        "/adaptive-profile",
        "/cryptovault",
    ]
    apis = [
        "/api/tie/dashboard",
        "/api/sope/dashboard",
        "/api/imcm/dashboard",
        "/api/soc/overview",
        "/api/health/status",
        "/api/dashboard/live",
        "/api/security/summary",
        "/api/network/nodes",
        "/api/btde/status",
    ]

    for path in paths:
        t0 = time.perf_counter()
        resp = client.get(path)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        entry = {"path": path, "status": resp.status_code, "ms": ms, "bytes": len(resp.data or b"")}
        report["routes"].append(entry)
        if resp.status_code >= 500:
            report["errors"].append({"type": "route_500", **entry})

    for path in apis:
        t0 = time.perf_counter()
        resp = client.get(path)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        entry = {"path": path, "status": resp.status_code, "ms": ms}
        report["apis"].append(entry)
        if resp.status_code >= 500:
            report["errors"].append({"type": "api_500", **entry})

    out_file = OUT / "RECOVERY_DIAGNOSTIC.json"
    out_file.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"errors_count": len(report["errors"]), "login": report["login"], "out": str(out_file)}, indent=2))
    if report["errors"]:
        print("ERRORS:", json.dumps(report["errors"], indent=2))


if __name__ == "__main__":
    main()
