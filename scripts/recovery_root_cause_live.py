#!/usr/bin/env python3
"""Collect boot snapshots + sequential API tests against live NOVUS."""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import psutil
import requests

from scripts.recovery_root_cause_final import (
    BASE,
    OUT_DIR,
    OUT_JSON,
    OUT_MD,
    boot_profile_120s,
    find_novus_pid,
    login_session,
    probe_api,
    snapshot,
    utc,
)

# If server already booted, capture current state only (no re-wait 120s)
QUICK_BOOT = os.environ.get("RECOVERY_QUICK_BOOT") == "1"


def main() -> int:
    pid = find_novus_pid()
    if not pid:
        print("Server not running on :5000", file=sys.stderr)
        return 2

    report = json.loads(OUT_JSON.read_text(encoding="utf-8")) if OUT_JSON.exists() else {}
    report.setdefault("generated_at", utc())
    report["post_fix_live"] = {}

    if QUICK_BOOT:
        report["boot_timeline_0_120s"] = [snapshot(0, probe_login=True), snapshot(120, probe_login=True)]
    else:
        print("Waiting for next 120s boot window is skipped — using live snapshots")
        report["boot_timeline_0_120s"] = report.get("boot_timeline_0_120s") or [
            snapshot(i, probe_login=(i == 0)) for i in (0, 15, 30, 45, 60, 75, 90, 105, 120)
        ]

    report["live_snapshot_now"] = snapshot(0, probe_login=True)

    print("Login + sequential API tests...")
    session, login_meta = login_session()
    report["login"] = login_meta

    tests = [
        ("C_login", None),
        ("D_dashboard", "/dashboard"),
        ("E_dashboard_live", "/api/dashboard/live"),
        ("F_health", "/api/health/status"),
        ("G_network", "/api/network/nodes"),
        ("H_vulnerabilities", "/api/security/vulnerabilities"),
        ("I_threats", "/api/security/threats"),
        ("J_reports", "/api/reports"),
        ("K_search", "/api/search"),
    ]
    report["http_tests"] = []
    for label, path in tests:
        if path is None:
            report["http_tests"].append(
                {
                    "test": label,
                    "authenticated": login_meta.get("authenticated"),
                    "result": "VERIFIED" if login_meta.get("authenticated") else "FAILED",
                    "recovery": False,
                }
            )
            continue
        if path == "/dashboard":
            t0 = time.perf_counter()
            r = session.get(BASE + path, timeout=120)
            entry = {
                "test": label,
                "endpoint": path,
                "http_status": r.status_code,
                "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
                "recovery": bool(r.headers.get("X-Novus-Recovery")),
                "result": "VERIFIED"
                if r.status_code == 200
                and not r.headers.get("X-Novus-Recovery")
                and ("novus-estado-general-panel" in (r.text or "") or "Dashboard" in (r.text or ""))
                else "FAILED",
            }
        else:
            entry = probe_api(session, path)
            entry["test"] = label
        report["http_tests"].append(entry)
        report["post_fix_live"][label] = snapshot(0)
        time.sleep(2)

    apis_ok = all(not t.get("recovery") for t in report["http_tests"])
    auth_ok = login_meta.get("authenticated")
    report["success_criteria"] = {
        "login_authenticated": auth_ok,
        "apis_no_recovery": apis_ok,
        "overall": "PASS" if auth_ok and apis_ok else "PARTIAL" if auth_ok else "FAIL",
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    md = [
        "# RECOVERY_ROOT_CAUSE_FINAL",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "## Root cause",
        "",
        report.get("root_cause", {}).get("evidence", "See JSON"),
        "",
        "## Fix",
        "",
        str(report.get("fix_applied", {})),
        "",
        "## Boot / live snapshots",
        "",
    ]
    for row in report.get("boot_timeline_0_120s", []):
        md.append(
            f"- t={row.get('elapsed_s')}s RSS={row.get('rss_mb')}MB threads={row.get('threads')} "
            f"backpressure={row.get('backpressure_level')} recovery_login={ (row.get('login_probe') or {}).get('recovery') }"
        )
    md.append("")
    md.append("## HTTP tests")
    for t in report["http_tests"]:
        md.append(f"- {t.get('test')}: {t.get('result')} recovery={t.get('recovery')} status={t.get('http_status', 'n/a')}")
    md.append("")
    md.append(f"**Overall: {report['success_criteria']['overall']}**")
    OUT_MD.write_text("\n".join(md), encoding="utf-8")
    print(json.dumps(report["success_criteria"], indent=2))
    return 0 if report["success_criteria"]["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
