#!/usr/bin/env python3
"""Prueba live :5000 — escaneo llega a 100% y Dashboard entrega informe."""
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
OUT = Path(__file__).resolve().parents[1] / "data" / "motor_telemetry" / "LIVE_PROOF_100PCT.json"
ROOT = Path(__file__).resolve().parents[1]


def login(s: requests.Session) -> dict:
    g = s.get(f"{BASE}/login", timeout=30)
    t = re.search(r'name="csrf_token" value="([^"]+)"', g.text)
    token = t.group(1) if t else ""
    p = s.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PASSWORD, "csrf_token": token},
        timeout=90,
        allow_redirects=True,
    )
    return {
        "status": p.status_code,
        "url": str(p.url),
        "js_fix": "fix-93pct-1" in p.text,
        "panel": "novus-estado-general-panel" in p.text,
    }


def status(s: requests.Session) -> dict:
    r = s.get(f"{BASE}/api/monitoring/status", timeout=60)
    return r.json()


def main() -> int:
    ev: dict = {"base": BASE, "started_at": datetime.now().isoformat(timespec="seconds")}
    s = requests.Session()
    ev["login"] = login(s)
    dash = s.get(f"{BASE}/dashboard", timeout=30)
    ev["dashboard_js"] = "novus-dashboard-estado-general.js?v=fix-93pct-1" in dash.text

    # Heal de sesión previa (si completed con report skipped)
    first = status(s)
    ev["first_status"] = {
        "status": first.get("status"),
        "progress_pct": first.get("progress_pct"),
        "finished_count": first.get("finished_count"),
        "completed_count": first.get("completed_count"),
        "failed_count": first.get("failed_count"),
        "report_stage": next(
            (x.get("status") for x in (first.get("stages") or []) if x.get("key") == "report"),
            None,
        ),
        "has_executive_summary": bool(first.get("executive_summary")),
        "report_id": first.get("report_id"),
        "scan_outcome": first.get("scan_outcome"),
        "progress_source": first.get("progress_source"),
    }

    # Poll hasta completed/partial con 100% o timeout
    samples = []
    reached_100 = False
    got_summary = False
    terminal = False
    deadline = time.time() + 900  # 15 min
    while time.time() < deadline:
        time.sleep(5)
        p = status(s)
        sample = {
            "t": datetime.now().isoformat(timespec="seconds"),
            "status": p.get("status"),
            "progress_pct": p.get("progress_pct"),
            "finished_count": p.get("finished_count"),
            "completed_count": p.get("completed_count"),
            "failed_count": p.get("failed_count"),
            "current_label": p.get("current_label"),
            "report_id": p.get("report_id"),
            "has_summary": bool(p.get("executive_summary")),
            "session": p.get("session_audit_id"),
            "stages": {
                x["key"]: x["status"]
                for x in (p.get("stages") or [])
                if x.get("status") not in ("completed",)
            },
        }
        samples.append(sample)
        if p.get("progress_pct") == 100:
            reached_100 = True
        if p.get("executive_summary"):
            got_summary = True
        if p.get("status") in ("completed", "partial"):
            terminal = True
            if reached_100 and (got_summary or p.get("report_id")):
                break
            # si completed pero aún no 100, una iteración más tras heal
            if p.get("progress_pct") == 100:
                break

    ev["poll_samples"] = samples[-20:]
    last = samples[-1] if samples else ev["first_status"]
    sid = last.get("session") or first.get("session_audit_id")
    disk = {}
    if sid:
        path = ROOT / "data" / "continuous_monitoring" / f"{sid}.json"
        if path.is_file():
            st = json.loads(path.read_text(encoding="utf-8"))
            disk = {
                "path": str(path),
                "status": st.get("status"),
                "stage_status": st.get("stage_status"),
                "report_id": st.get("report_id"),
            }
    ev["disk"] = disk
    ev["checks"] = {
        "js_fix_served": ev["dashboard_js"],
        "reached_100": reached_100 or (last.get("progress_pct") == 100),
        "terminal_status": terminal or last.get("status") in ("completed", "partial"),
        "has_report_or_summary": got_summary
        or bool(last.get("report_id"))
        or bool(last.get("has_summary")),
        "report_not_skipped": (disk.get("stage_status") or {}).get("report") != "skipped",
        "no_pending_running": not any(
            v in ("pending", "running") for v in (disk.get("stage_status") or {}).values()
        ),
    }
    # Si la sesión previa ya estaba completed, el heal debe dar 100% inmediato
    if ev["first_status"].get("status") in ("completed", "partial"):
        ev["checks"]["heal_first_read_100"] = ev["first_status"].get("progress_pct") == 100
        ev["checks"]["heal_first_summary"] = ev["first_status"].get("has_executive_summary") is True
    ev["ok"] = all(ev["checks"].values())
    ev["finished_at"] = datetime.now().isoformat(timespec="seconds")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(ev, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(ev, indent=2, ensure_ascii=False))
    return 0 if ev["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
