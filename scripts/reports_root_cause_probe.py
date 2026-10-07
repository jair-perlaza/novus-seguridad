#!/usr/bin/env python3
"""Reproduce /api/reports — Test A (solo reports) y Test B (tras otras APIs)."""
from __future__ import annotations

import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil
import pyotp
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
BASE = "http://127.0.0.1:5000"
QA_EMAIL = "novus.qa.jul2026@example.com"
QA_PASS = "NovusQA2026!"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_pid() -> int | None:
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN" and c.pid:
            return c.pid
    return None


def snap() -> dict:
    from services.resource_backpressure_service import get_status

    out = {"ts": utc(), "system_ram_pct": round(psutil.virtual_memory().percent, 1)}
    pid = find_pid()
    if pid:
        p = psutil.Process(pid)
        out["rss_mb"] = round(p.memory_info().rss / (1024 * 1024), 1)
        out["threads"] = p.num_threads()
    bp = get_status()
    out["backpressure"] = bp.get("level")
    return out


def login(s: requests.Session) -> dict:
    r = s.get(f"{BASE}/login", timeout=30)
    csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text).group(1)
    r1 = s.post(
        f"{BASE}/login",
        data={"email": QA_EMAIL, "password": QA_PASS, "csrf_token": csrf},
        timeout=60,
    )
    csrf2 = re.search(r'name="csrf_token"\s+value="([^"]+)"', r1.text).group(1)
    from services.web_security_auth_enterprise.mfa_totp import _dec, _load

    code = pyotp.TOTP(_dec(_load()[QA_EMAIL]["secret_enc"])).now()
    r2 = s.post(
        f"{BASE}/login",
        data={"email": QA_EMAIL, "password": QA_PASS, "csrf_token": csrf2, "mfa_code": code},
        timeout=60,
        allow_redirects=False,
    )
    return {"mfa_status": r2.status_code, "location": r2.headers.get("Location")}


def probe_reports(s: requests.Session, label: str) -> dict:
    before = snap()
    t0 = time.perf_counter()
    r = s.get(f"{BASE}/api/reports", timeout=120)
    ms = round((time.perf_counter() - t0) * 1000, 1)
    after = snap()
    body = {}
    try:
        body = r.json()
    except Exception:
        pass
    return {
        "test": label,
        "before": before,
        "after": after,
        "http_status": r.status_code,
        "original_status": r.headers.get("X-Novus-Original-Status"),
        "recovery": bool(r.headers.get("X-Novus-Recovery") or body.get("_novusRecovery")),
        "latency_ms": ms,
        "body_status": body.get("status"),
        "count": body.get("count"),
        "message": (body.get("message") or "")[:120],
    }


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "A"
    s = requests.Session()
    login_info = login(s)
    out = {"mode": mode, "login": login_info}

    if mode == "A":
        s.get(f"{BASE}/dashboard", timeout=60)
        out["reports"] = probe_reports(s, "A_reports_only")
    else:
        for ep in [
            "/dashboard",
            "/api/dashboard/live",
            "/api/health/status",
            "/api/network/nodes",
            "/api/security/vulnerabilities",
            "/api/security/threats",
            "/api/search",
        ]:
            s.get(BASE + ep, timeout=90)
            time.sleep(1)
        out["reports"] = probe_reports(s, "B_after_apis")

    print(json.dumps(out, indent=2))
    rec = out["reports"]["recovery"]
    return 0 if not rec and out["reports"]["body_status"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
