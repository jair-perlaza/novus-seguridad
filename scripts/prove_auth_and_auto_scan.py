#!/usr/bin/env python3
"""Prueba flujo auth + escaneo automático en http://127.0.0.1:5000."""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

BASE = os.environ.get("NOVUS_BASE", "http://127.0.0.1:5000").rstrip("/")
EMAIL = os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com")
PASSWORD = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")
OUT = Path(__file__).resolve().parents[1] / "data" / "motor_telemetry" / "LIVE_PROOF_AUTH_SCAN.json"


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""


def main() -> int:
    ev: dict = {"base": BASE, "started_at": datetime.now().isoformat(timespec="seconds")}
    s0 = requests.Session()
    r_root = s0.get(f"{BASE}/", allow_redirects=False, timeout=30)
    r_dash = s0.get(f"{BASE}/dashboard", allow_redirects=False, timeout=30)
    r_login = s0.get(f"{BASE}/login", allow_redirects=False, timeout=30)
    r_follow = s0.get(f"{BASE}/dashboard", allow_redirects=True, timeout=30)
    ev["unauth"] = {
        "GET_/": {"status": r_root.status_code, "location": r_root.headers.get("Location")},
        "GET_/dashboard": {"status": r_dash.status_code, "location": r_dash.headers.get("Location")},
        "GET_/login": {
            "status": r_login.status_code,
            "has_form": "csrf_token" in r_login.text,
            "no_panel": "novus-estado-general-panel" not in r_login.text,
        },
        "follow_dashboard": {
            "final_url": str(r_follow.url),
            "is_login": "/login" in str(r_follow.url),
            "has_panel": "novus-estado-general-panel" in r_follow.text,
        },
    }

    s = requests.Session()
    g = s.get(f"{BASE}/login", timeout=30)
    t0 = time.time()
    p = s.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PASSWORD, "csrf_token": _csrf(g.text)},
        timeout=60,
        allow_redirects=False,
    )
    login_dt = round(time.time() - t0, 2)
    loc = p.headers.get("Location") or ""
    dash = s.get(f"{BASE}/dashboard", timeout=120)
    ev["login"] = {
        "post_status": p.status_code,
        "post_location": loc,
        "post_seconds": login_dt,
        "dash_status": dash.status_code,
        "dash_url": str(dash.url),
        "has_panel": "novus-estado-general-panel" in dash.text,
        "session_cookie": "session" in s.cookies.get_dict(),
        "remember_cookie": any("remember" in k.lower() for k in s.cookies.get_dict()),
    }

    samples = []
    started = False
    reached_100 = False
    got_summary = False
    for _ in range(150):
        time.sleep(4)
        try:
            st = s.get(f"{BASE}/api/monitoring/status", timeout=90)
            data = st.json()
        except Exception as exc:
            samples.append({"t": datetime.now().isoformat(timespec="seconds"), "error": str(exc)[:120]})
            continue
        sample = {
            "t": datetime.now().isoformat(timespec="seconds"),
            "status": data.get("status"),
            "progress_pct": data.get("progress_pct"),
            "scan_running": data.get("scan_running"),
            "finished_count": data.get("finished_count"),
            "session": data.get("session_audit_id"),
            "has_summary": bool(data.get("executive_summary")),
            "report_id": data.get("report_id"),
        }
        samples.append(sample)
        if data.get("scan_running") or data.get("status") in (
            "phase1_running",
            "phase2_running",
            "completed",
            "partial",
        ):
            started = True
        if data.get("progress_pct") == 100 and data.get("status") in ("completed", "partial"):
            reached_100 = True
            got_summary = bool(data.get("executive_summary")) or bool(data.get("report_id"))
            break

    ev["scan_poll_tail"] = samples[-20:]
    ev["scan"] = {
        "started_automatically": started,
        "reached_100": reached_100,
        "has_summary_or_report": got_summary,
    }

    lo = s.get(f"{BASE}/logout", allow_redirects=True, timeout=30)
    s.cookies.clear()
    r_after_f = s.get(f"{BASE}/dashboard", allow_redirects=True, timeout=30)
    ev["after_logout"] = {
        "logout_url": str(lo.url),
        "dashboard_follow": {
            "final_url": str(r_after_f.url),
            "is_login": "/login" in str(r_after_f.url),
            "has_panel": "novus-estado-general-panel" in r_after_f.text,
        },
    }

    ev["checks"] = {
        "unauth_dashboard_not_panel": (not ev["unauth"]["follow_dashboard"]["has_panel"])
        and ev["unauth"]["follow_dashboard"]["is_login"],
        "login_fast": login_dt < 30,
        "login_opens_dashboard": ev["login"]["has_panel"] and p.status_code in (302, 303),
        "no_remember_cookie": not ev["login"]["remember_cookie"],
        "scan_started": started,
        "scan_100_and_report": reached_100 and got_summary,
        "after_logout_requires_login": ev["after_logout"]["dashboard_follow"]["is_login"]
        and not ev["after_logout"]["dashboard_follow"]["has_panel"],
    }
    ev["ok"] = all(ev["checks"].values())
    ev["finished_at"] = datetime.now().isoformat(timespec="seconds")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(ev, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(ev, indent=2, ensure_ascii=False))
    return 0 if ev["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
