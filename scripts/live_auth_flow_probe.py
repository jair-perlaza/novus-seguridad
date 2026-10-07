#!/usr/bin/env python3
"""Flujo HTTP autenticado real: login → dashboard → APIs."""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:5000"
EMAIL = "operaciones@novapay-fintech.co"
PASSWORD = "NovaPay#Fintech2026"


def _pid() -> int | None:
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN" and c.pid:
            return c.pid
    return None


def main() -> int:
    pid = _pid()
    rss = None
    if pid:
        rss = round(psutil.Process(pid).memory_info().rss / 1024 / 1024, 1)

    s = requests.Session()
    out = {"pid": pid, "rss_mb": rss, "host_ram_pct": round(psutil.virtual_memory().percent, 1)}

    t0 = time.perf_counter()
    r = s.get(f"{BASE}/login", timeout=30)
    out["login_get_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    out["login_get_http"] = r.status_code

    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    csrf = m.group(1) if m else ""

    t0 = time.perf_counter()
    r = s.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PASSWORD, "csrf_token": csrf},
        allow_redirects=True,
        timeout=45,
    )
    out["login_post_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    out["login_post_http"] = r.status_code
    out["login_final_url"] = r.url

    t0 = time.perf_counter()
    r = s.get(f"{BASE}/dashboard", timeout=45)
    out["dashboard_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    out["dashboard_http"] = r.status_code

    apis = {}
    for path in (
        "/api/dashboard/live",
        "/api/security/summary",
        "/api/tenant/scope",
        "/api/monitoring/network-config",
        "/api/network/nodes?trigger_discovery=false",
        "/api/security/vulnerabilities",
        "/api/security/threats",
        "/api/notifications?kind=security",
        "/api/ai/status",
    ):
        t0 = time.perf_counter()
        ar = s.get(f"{BASE}{path}", timeout=45)
        body = {}
        try:
            body = ar.json()
        except Exception:
            pass
        apis[path] = {
            "http": ar.status_code,
            "ms": round((time.perf_counter() - t0) * 1000, 1),
            "status": body.get("status"),
            "analysis_state": body.get("analysis_state"),
            "monitoring_enabled": body.get("monitoring_enabled"),
        }
    out["apis"] = apis
    out["pass"] = (
        out["dashboard_http"] == 200
        and all(v["http"] == 200 for v in apis.values())
        and out["login_post_ms"] < 10000
        and out["dashboard_ms"] < 10000
    )

    path_out = ROOT / "data" / "novus_release_candidate" / "LIVE_AUTH_FLOW_PROBE.json"
    path_out.parent.mkdir(parents=True, exist_ok=True)
    path_out.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0 if out["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
