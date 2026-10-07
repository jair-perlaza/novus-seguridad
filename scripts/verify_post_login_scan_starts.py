"""Verifica que tras login el escaneo automático arranca en <60s."""
from __future__ import annotations

import os
import re
import sys
import time

import requests

BASE = "http://127.0.0.1:5000"


def main() -> int:
    s = requests.Session()
    g = s.get(BASE + "/login", timeout=60)
    tok = re.search(r'name="csrf_token" value="([^"]+)"', g.text)
    token = tok.group(1) if tok else ""
    pwd = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")
    email = os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com")
    t_login = time.perf_counter()
    s.post(
        BASE + "/login",
        data={"email": email, "password": pwd, "csrf_token": token},
        timeout=120,
        allow_redirects=True,
    )
    login_sec = round(time.perf_counter() - t_login, 2)
    print("login_sec", login_sec)

    t0 = time.perf_counter()
    started = False
    last = {}
    while time.perf_counter() - t0 < 60:
        r = s.get(BASE + "/api/monitoring/status?poll=1", timeout=30)
        if r.ok:
            last = r.json()
            if last.get("scan_running") or last.get("status") in ("phase1_running", "phase2_running"):
                started = True
                break
            if last.get("status") in ("completed", "partial"):
                started = True
                break
        time.sleep(2)

    print("scan_started", started, "after_sec", round(time.perf_counter() - t0, 2))
    print("monitoring_status", last.get("status"), "progress", last.get("progress_pct"))
    print("session", last.get("session_audit_id"))
    t_mon = time.perf_counter()
    r2 = s.get(BASE + "/api/monitoring/status?poll=1", timeout=30)
    print("monitoring_poll_ms", round((time.perf_counter() - t_mon) * 1000, 1), "http", r2.status_code)
    return 0 if started and r2.status_code == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
