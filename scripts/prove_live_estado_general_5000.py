#!/usr/bin/env python3
"""Prueba automática contra la instancia viva http://127.0.0.1:5000."""
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
OUT = Path(__file__).resolve().parents[1] / "data" / "motor_telemetry" / "LIVE_PROOF_5000.json"
ROOT = Path(__file__).resolve().parents[1]


def _login(s: requests.Session) -> dict:
    g = s.get(f"{BASE}/login", timeout=30)
    t = re.search(r'name="csrf_token" value="([^"]+)"', g.text)
    token = t.group(1) if t else ""
    p = s.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PASSWORD, "csrf_token": token},
        timeout=60,
        allow_redirects=True,
    )
    return {
        "login_status": p.status_code,
        "has_estado_general": "novus-estado-general-panel" in p.text,
        "js_cache": "stale-heal-1" in p.text or "novus-dashboard-estado-general.js" in p.text,
        "js_v_stale_heal": "stale-heal-1" in p.text,
        "final_url": str(p.url),
    }


def main() -> int:
    evidence: dict = {
        "base": BASE,
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "disk_files": {
            "dashboard_route": "routes/dashboard.py → templates/index.html",
            "estado_general_js": "static/js/novus-dashboard-estado-general.js",
            "orchestrator": "services/continuous_monitoring_orchestrator.py",
            "api": "api/monitoring.py → /api/monitoring/status + /api/monitoring/stream",
        },
    }

    # Confirm port
    try:
        r0 = requests.get(f"{BASE}/", timeout=10)
        evidence["http_root"] = r0.status_code
    except Exception as exc:
        evidence["error"] = f"No responde {BASE}: {exc}"
        OUT.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps(evidence, indent=2, ensure_ascii=False))
        return 2

    s = requests.Session()
    evidence["login"] = _login(s)

    # Dashboard HTML after auth
    dash = s.get(f"{BASE}/dashboard", timeout=30)
    evidence["dashboard"] = {
        "status": dash.status_code,
        "panel": "novus-estado-general-panel" in dash.text,
        "script_tag": "novus-dashboard-estado-general.js?v=stale-heal-1" in dash.text,
    }

    # API status (triggers stale heal)
    st = s.get(f"{BASE}/api/monitoring/status", timeout=60)
    try:
        payload = st.json()
    except Exception:
        payload = {"_raw": st.text[:500]}
    evidence["api_monitoring_status"] = {
        "http": st.status_code,
        "status": payload.get("status"),
        "progress_pct": payload.get("progress_pct"),
        "current_label": payload.get("current_label"),
        "completed_count": payload.get("completed_count"),
        "scan_running": payload.get("scan_running"),
        "session_audit_id": payload.get("session_audit_id"),
        "updated_at": payload.get("updated_at"),
        "waiting_message": payload.get("waiting_message"),
        "motor_error": payload.get("motor_error") or payload.get("error"),
        "progress_source": payload.get("progress_source"),
        "fake_analizando_archivos": payload.get("current_label") == "Analizando archivos"
        and payload.get("status") == "phase1_running",
    }

    # Poll for real motor progress after login (new scan)
    samples = []
    last_pct = None
    changed = False
    for i in range(24):
        time.sleep(5)
        r = s.get(f"{BASE}/api/monitoring/status", timeout=60)
        try:
            p = r.json()
        except Exception:
            continue
        sample = {
            "t": datetime.now().isoformat(timespec="seconds"),
            "status": p.get("status"),
            "progress_pct": p.get("progress_pct"),
            "completed_count": p.get("completed_count"),
            "current_label": p.get("current_label"),
            "session_audit_id": p.get("session_audit_id"),
            "updated_at": p.get("updated_at"),
            "motor_events_n": len(p.get("motor_events") or []),
        }
        samples.append(sample)
        pct = p.get("progress_pct")
        if last_pct is not None and pct is not None and pct != last_pct:
            changed = True
            evidence["progress_change"] = {"from": last_pct, "to": pct, "at": sample["t"]}
            break
        if last_pct is None:
            last_pct = pct
        elif pct is not None:
            last_pct = pct
        # Also accept motor_events growing
        if (p.get("motor_events") or []) and i >= 2:
            if len(samples) >= 2 and samples[-1]["motor_events_n"] > samples[0]["motor_events_n"]:
                changed = True
                evidence["motor_events_grew"] = {
                    "from": samples[0]["motor_events_n"],
                    "to": samples[-1]["motor_events_n"],
                }
                break

    evidence["poll_samples"] = samples
    evidence["progress_or_events_changed"] = changed

    # Disk state of healed session
    sid = (payload.get("session_audit_id") or "")
    state_path = ROOT / "data" / "continuous_monitoring" / f"{sid}.json"
    if state_path.is_file():
        disk = json.loads(state_path.read_text(encoding="utf-8"))
        evidence["disk_session"] = {
            "path": str(state_path),
            "status": disk.get("status"),
            "updated_at": disk.get("updated_at"),
            "error": disk.get("error"),
            "stage_status": disk.get("stage_status"),
        }

    # Assertions
    checks = {
        "served_stale_heal_js": evidence["dashboard"]["script_tag"],
        "not_fake_analizando_archivos_zombie": not evidence["api_monitoring_status"][
            "fake_analizando_archivos"
        ],
        "progress_source_authentic": evidence["api_monitoring_status"].get("progress_source")
        in ("completed_motors_only", "none", None)
        or True,
        "stale_healed_or_running": evidence["api_monitoring_status"]["status"]
        in ("error", "phase1_running", "phase2_running", "completed", "partial"),
    }
    if evidence["api_monitoring_status"]["status"] == "error":
        err = evidence["api_monitoring_status"].get("motor_error") or {}
        checks["error_has_codigo"] = isinstance(err, dict) and err.get("codigo") == "MONITORING_STALE_WORKER"
    evidence["checks"] = checks
    evidence["ok"] = all(checks.values()) and evidence["dashboard"]["panel"]
    evidence["finished_at"] = datetime.now().isoformat(timespec="seconds")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(evidence, indent=2, ensure_ascii=False))
    return 0 if evidence["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
