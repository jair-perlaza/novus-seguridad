#!/usr/bin/env python3
"""Verificación LIVE post-integración NOVUS."""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "novus_full_integration_report"
OUT.mkdir(parents=True, exist_ok=True)
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def login():
    import re
    import requests

    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=20)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    csrf = csrf.group(1) if csrf else ""
    s.post(f"{BASE}/login", data={"email": QA[0], "password": QA[1], "csrf_token": csrf}, timeout=30)
    return s


def probe(s, path: str, timeout: float = 8.0) -> dict:
    t0 = time.perf_counter()
    try:
        r = s.get(BASE + path, timeout=timeout)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        body = {}
        try:
            body = r.json()
        except Exception:
            pass
        recovering = body.get("status") == "recovering" or body.get("_novusRecovery")
        ok = r.status_code == 200 and not recovering
        return {
            "path": path,
            "ms": ms,
            "status": r.status_code,
            "ok": ok,
            "recovering": recovering,
            "body_status": body.get("status") if isinstance(body.get("status"), str) else None,
            "keys": list(body.keys())[:10],
        }
    except Exception as exc:
        return {
            "path": path,
            "ms": round((time.perf_counter() - t0) * 1000, 1),
            "ok": False,
            "error": str(exc)[:120],
        }


CRITICAL = [
    "/api/security/summary",
    "/api/dashboard/live",
    "/api/network/info",
    "/api/network/nodes",
    "/api/network/ndr",
    "/api/network/topology",
    "/api/security/threats",
    "/api/tie/dashboard",
    "/api/asm/dashboard",
    "/api/soc/overview",
    "/api/imcm/dashboard",
    "/api/sope/dashboard",
    "/api/health/dashboard",
    "/api/ai/kernel/knowledge-status",
    "/api/network-security-history/summary",
    "/api/reports/list",
]


def main():
    s = login()
    results = [probe(s, p) for p in CRITICAL]
    ok_n = sum(1 for r in results if r.get("ok"))
    rec_n = sum(1 for r in results if r.get("recovering"))
    slow = [r for r in results if r.get("ms", 0) > 8000]

    payload = {
        "generated_at_utc": utc(),
        "critical_probes": results,
        "ok_count": ok_n,
        "recovering_count": rec_n,
        "slow_over_8s": slow,
        "total": len(results),
    }
    OUT.joinpath("API_STATUS.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({"ok": ok_n, "recovering": rec_n, "slow": len(slow), "total": len(results)}, indent=2))
    return 0 if rec_n == 0 and not slow else 1


if __name__ == "__main__":
    sys.exit(main())
