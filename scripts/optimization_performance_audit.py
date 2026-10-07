#!/usr/bin/env python3
"""Medición BEFORE/AFTER optimización integración NOVUS."""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "optimization_performance"
OUT.mkdir(parents=True, exist_ok=True)

QA_EMAIL = os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com")
QA_PASSWORD = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")

ROUTES = [
    ("login", "/login"),
    ("dashboard", "/dashboard"),
    ("soc", "/security-operations-center"),
    ("tie", "/threat-intelligence-center"),
    ("sope", "/playbook-center"),
    ("imcm", "/incident-management"),
    ("network", "/network"),
    ("health", "/health-center"),
    ("asm", "/asset-intelligence"),
    ("viem", "/vulnerability-intelligence"),
    ("sdace", "/security-data-analytics"),
    ("ueba", "/identity-intelligence"),
    ("iapa", "/identity-attack-path"),
    ("dpe", "/deception-center"),
]

API_ENDPOINTS = [
    "/api/tie/dashboard",
    "/api/sope/dashboard",
    "/api/imcm/dashboard",
    "/api/imcm/timeline",
    "/api/soc/overview",
    "/api/dashboard/live",
    "/api/security/summary",
    "/api/network/nodes",
    "/api/health/status",
    "/api/health/dashboard",
    "/api/asm/dashboard",
    "/api/viem/dashboard",
]


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bench_api(client, path: str, rounds: int = 3) -> dict:
    times = []
    status = 0
    nbytes = 0
    for _ in range(rounds):
        t0 = time.perf_counter()
        r = client.get(path)
        ms = (time.perf_counter() - t0) * 1000
        times.append(ms)
        status = r.status_code
        nbytes = len(r.data or b"")
    return {
        "path": path,
        "status": status,
        "ms_avg": round(sum(times) / len(times), 2),
        "ms_min": round(min(times), 2),
        "ms_max": round(max(times), 2),
        "bytes": nbytes,
        "rounds": rounds,
    }


def measure(phase: str) -> dict:
    from core.app import create_app

    app = create_app("development")
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["email"] = QA_EMAIL
        sess["user_email"] = QA_EMAIL

    nav = []
    for name, path in ROUTES:
        t0 = time.perf_counter()
        r = client.get(path)
        nav.append({
            "module": name,
            "path": path,
            "html_ms": round((time.perf_counter() - t0) * 1000, 2),
            "status": r.status_code,
            "bytes": len(r.data or b""),
        })

    apis = [_bench_api(client, ep) for ep in API_ENDPOINTS]
    apis.sort(key=lambda x: x["ms_avg"], reverse=True)

    return {
        "generated_at_utc": _utc(),
        "phase": phase,
        "navigation": nav,
        "apis": apis,
        "slowest_api": apis[0] if apis else None,
        "slowest_nav": max(nav, key=lambda x: x["html_ms"]) if nav else None,
    }


def main() -> None:
    phase = os.environ.get("NOVUS_OPT_PHASE", "AFTER").upper()
    result = measure(phase)
    out_file = OUT / f"{phase}_PERFORMANCE.json"
    out_file.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {out_file}")

    before_path = OUT / "BEFORE_PERFORMANCE.json"
    if phase == "AFTER":
        baseline = ROOT / "data" / "integration_performance_audit" / "NAVIGATION_LATENCY.json"
        perf_base = ROOT / "data" / "integration_performance_audit" / "PERFORMANCE_ENDPOINT_MATRIX.json"
        if not before_path.exists() and baseline.exists() and perf_base.exists():
            bl = json.loads(baseline.read_text(encoding="utf-8"))
            pe = json.loads(perf_base.read_text(encoding="utf-8"))
            before = {
                "generated_at_utc": bl.get("generated_at_utc"),
                "phase": "BEFORE",
                "navigation": [
                    {
                        "module": t["module"],
                        "path": t["path"],
                        "html_ms": t["html_ms"],
                        "status": t["status"],
                        "bytes": t.get("html_bytes", 0),
                    }
                    for t in bl.get("transitions", [])
                ],
                "apis": pe.get("endpoints", []),
                "slowest_api": pe.get("endpoints", [{}])[0] if pe.get("endpoints") else None,
            }
            before_path.write_text(json.dumps(before, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"Imported baseline -> {before_path}")

        if before_path.exists():
            before = json.loads(before_path.read_text(encoding="utf-8"))
            diff = {"generated_at_utc": _utc(), "navigation": [], "apis": []}
            bnav = {n["module"]: n for n in before.get("navigation", [])}
            for n in result["navigation"]:
                b = bnav.get(n["module"], {})
                diff["navigation"].append({
                    "module": n["module"],
                    "before_ms": b.get("html_ms"),
                    "after_ms": n["html_ms"],
                    "delta_ms": round(n["html_ms"] - (b.get("html_ms") or 0), 2),
                })
            bapi = {a["path"]: a for a in before.get("apis", [])}
            for a in result["apis"]:
                b = bapi.get(a["path"], {})
                diff["apis"].append({
                    "path": a["path"],
                    "before_avg_ms": b.get("ms_avg"),
                    "after_avg_ms": a["ms_avg"],
                    "delta_ms": round(a["ms_avg"] - (b.get("ms_avg") or 0), 2),
                    "improvement_pct": round(
                        100 * ((b.get("ms_avg") or a["ms_avg"]) - a["ms_avg"]) / max(b.get("ms_avg") or 1, 1),
                        1,
                    ) if b.get("ms_avg") else None,
                })
            (OUT / "PERFORMANCE_DIFF.json").write_text(
                json.dumps(diff, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            (OUT / "NAVIGATION_REGRESSION.json").write_text(
                json.dumps([x for x in diff["navigation"] if (x.get("delta_ms") or 0) > 50], indent=2),
                encoding="utf-8",
            )
            (OUT / "API_REGRESSION.json").write_text(
                json.dumps([x for x in diff["apis"] if (x.get("delta_ms") or 0) > 100], indent=2),
                encoding="utf-8",
            )
            print("Wrote PERFORMANCE_DIFF.json")


if __name__ == "__main__":
    main()
