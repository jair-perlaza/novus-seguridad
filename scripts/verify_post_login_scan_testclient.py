"""Prueba post-login sin HTTP — misma app que main.py."""
from __future__ import annotations

import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def main() -> int:
    from main import app

    email = os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com")
    pwd = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")
    c = app.test_client()
    lg = c.get("/login")
    tok = re.search(r'name="csrf_token" value="([^"]+)"', lg.get_data(as_text=True))
    token = tok.group(1) if tok else ""
    t0 = time.perf_counter()
    c.post("/login", data={"email": email, "password": pwd, "csrf_token": token}, follow_redirects=True)
    login_ms = round((time.perf_counter() - t0) * 1000, 1)
    print("login_ms", login_ms)

    started = False
    t1 = time.perf_counter()
    last = {}
    for _ in range(30):
        r = c.get("/api/monitoring/status?poll=1")
        last = r.get_json() or {}
        if last.get("scan_running") or last.get("status") in ("phase1_running", "phase2_running", "completed", "partial"):
            started = True
            break
        time.sleep(2)
    print("scan_started", started, "wait_sec", round(time.perf_counter() - t1, 1))
    print("status", last.get("status"), "progress", last.get("progress_pct"), "session", last.get("session_audit_id"))

    t2 = time.perf_counter()
    r2 = c.get("/api/monitoring/status?poll=1")
    print("poll_ms", round((time.perf_counter() - t2) * 1000, 1), "http", r2.status_code)
    return 0 if started and r2.status_code == 200 and (time.perf_counter() - t2) < 5 else 1


if __name__ == "__main__":
    raise SystemExit(main())
