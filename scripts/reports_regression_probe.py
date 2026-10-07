#!/usr/bin/env python3
"""Post-fix regression: reports + verified APIs."""
from __future__ import annotations

import json
import re
import sys
import time

import pyotp
import requests

sys.path.insert(0, r"C:\NOVUS")
from scripts.reports_root_cause_probe import BASE, QA_EMAIL, QA_PASS, probe_reports, snap

ENDPOINTS = [
    ("/dashboard", "dashboard"),
    ("/api/dashboard/live", "dashboard_live"),
    ("/api/health/status", "health"),
    ("/api/network/nodes", "network"),
    ("/api/security/vulnerabilities", "vulnerabilities"),
    ("/api/security/threats", "threats"),
    ("/api/search", "search"),
]


def login(s):
    r = s.get(BASE + "/login", timeout=120)
    csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text).group(1)
    r1 = s.post(
        BASE + "/login",
        data={"email": QA_EMAIL, "password": QA_PASS, "csrf_token": csrf},
        timeout=120,
    )
    csrf2 = re.search(r'name="csrf_token"\s+value="([^"]+)"', r1.text).group(1)
    from services.web_security_auth_enterprise.mfa_totp import _dec, _load

    code = pyotp.TOTP(_dec(_load()[QA_EMAIL]["secret_enc"])).now()
    return s.post(
        BASE + "/login",
        data={"email": QA_EMAIL, "password": QA_PASS, "csrf_token": csrf2, "mfa_code": code},
        timeout=180,
        allow_redirects=False,
    )


def probe(s, path):
    t0 = time.perf_counter()
    r = s.get(BASE + path, timeout=120)
    ms = round((time.perf_counter() - t0) * 1000, 1)
    rec = bool(r.headers.get("X-Novus-Recovery"))
    body = {}
    try:
        body = r.json()
        rec = rec or bool(body.get("_novusRecovery"))
    except Exception:
        pass
    return {"path": path, "status": r.status_code, "recovery": rec, "latency_ms": ms, "ok": r.status_code == 200 and not rec}


def main():
    s = requests.Session()
    login(s)
    out = {"before": snap(), "tests": []}

    # Test B flow then reports
    for path, name in ENDPOINTS:
        out["tests"].append({"name": name, **probe(s, path)})
        time.sleep(1)
    out["reports"] = probe_reports(s, "B_then_reports")
    for path, name in ENDPOINTS:
        out["tests"].append({"name": f"post_{name}", **probe(s, path)})
        time.sleep(1)
    out["after"] = snap()
    out["pass"] = out["reports"]["recovery"] is False and out["reports"]["body_status"] == "success"
    out["pass"] = out["pass"] and all(t["ok"] for t in out["tests"])
    print(json.dumps(out, indent=2))
    return 0 if out["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
