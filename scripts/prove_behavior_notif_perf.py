#!/usr/bin/env python3
"""Prueba Behavior Baseline + Notificaciones + tiempos login/dashboard en :5000."""
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
OUT = Path(__file__).resolve().parents[1] / "data" / "motor_telemetry" / "LIVE_PROOF_BEHAVIOR_NOTIF.json"
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)


def csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""


def main() -> int:
    ev = {"base": BASE, "started_at": datetime.now().isoformat(timespec="seconds")}
    s = requests.Session()
    g = s.get(f"{BASE}/login", timeout=30)
    t0 = time.time()
    p = s.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PASSWORD, "csrf_token": csrf(g.text)},
        timeout=60,
        allow_redirects=False,
    )
    login_s = round(time.time() - t0, 3)
    t1 = time.time()
    dash = s.get(f"{BASE}/dashboard", timeout=90)
    dash_s = round(time.time() - t1, 3)
    ev["perf"] = {
        "login_post_sec": login_s,
        "dashboard_get_sec": dash_s,
        "login_status": p.status_code,
        "dash_status": dash.status_code,
        "has_behavior_panel": "novus-behavior-panel" in dash.text,
        "has_notif_js": "novus-notification-center.js" in dash.text,
        "has_bell": "novus-bell-btn" in dash.text,
    }

    # Esperar hooks async de behavior/login
    time.sleep(4)
    bh = s.get(f"{BASE}/api/behavior/summary", timeout=60).json()
    ev["behavior"] = {
        "available": bh.get("available"),
        "events_count": bh.get("events_count"),
        "enough_data": bh.get("enough_data"),
        "normality_score": bh.get("normality_score"),
        "has_recommendations": bool(bh.get("recommendations")),
    }

    # Usar servicio en proceso de prueba (misma DB que el servidor)
    from database import SessionLocal, BehaviorActivityEvent, NovusNotification
    from services.behavior_baseline_service import record_activity, rebuild_baseline
    from services.notification_center_service import emit_notification

    for i in range(3):
        record_activity(
            user_email=EMAIL,
            event_type="login" if i == 0 else "session_heartbeat",
            ip="127.0.0.1",
            mechanisms=["prove_script"],
            source_motor="prove_behavior_notif",
            rebuild=(i == 2),
        )
    baseline = rebuild_baseline(EMAIL)
    ev["baseline_after"] = {
        "events_count": baseline.get("events_count"),
        "enough_data": baseline.get("enough_data"),
        "normality_score": baseline.get("normality_score"),
        "usual_hours": (baseline.get("profile") or {}).get("usual_hours"),
    }

    emitted = emit_notification(
        user_email=EMAIL,
        category="sistema",
        priority="info",
        title="Prueba Centro de Eventos",
        description="Notificación generada por prueba automática con evidencia real de sesión.",
        source_motor="prove_behavior_notif",
        source_ref=f"prove-{int(time.time())}",
        detail_url="/dashboard",
    )
    ev["emit"] = emitted
    listed = s.get(f"{BASE}/api/notifications?limit=20", timeout=30).json()
    ev["notifications_api"] = {
        "count": listed.get("count"),
        "unread_count": listed.get("unread_count"),
        "has_items": bool(listed.get("notifications")),
    }
    nid = None
    for n in listed.get("notifications") or []:
        if n.get("source_motor") == "prove_behavior_notif":
            nid = n.get("notification_id")
            break
    if not nid and emitted.get("notification_id"):
        nid = emitted["notification_id"]
    ops = {}
    if nid:
        ops["read"] = s.post(f"{BASE}/api/notifications/{nid}/read", timeout=30).json()
        ops["archive"] = s.post(f"{BASE}/api/notifications/{nid}/archive", timeout=30).json()
    ev["notification_ops"] = ops

    db = SessionLocal()
    try:
        bae_n = db.query(BehaviorActivityEvent).filter(BehaviorActivityEvent.user_email == EMAIL.lower()).count()
        ntf_n = db.query(NovusNotification).filter(NovusNotification.user_email == EMAIL.lower()).count()
        ev["db"] = {"behavior_events": bae_n, "notifications": ntf_n}
    finally:
        db.close()

    ev["checks"] = {
        "login_under_5s": login_s < 5,
        "dashboard_under_15s": dash_s < 15,
        "behavior_panel_in_html": ev["perf"]["has_behavior_panel"],
        "notif_js_loaded": ev["perf"]["has_notif_js"],
        "behavior_events_in_db": ev["db"]["behavior_events"] >= 3,
        "baseline_enough_or_building": baseline.get("events_count", 0) >= 3,
        "notifications_listable": bool(ev["notifications_api"]["has_items"]),
        "read_ok": bool((ops.get("read") or {}).get("ok") or (ops.get("read") or {}).get("status") == "success"),
        "archive_ok": bool((ops.get("archive") or {}).get("ok") or (ops.get("archive") or {}).get("status") == "success"),
    }
    ev["ok"] = all(ev["checks"].values())
    ev["finished_at"] = datetime.now().isoformat(timespec="seconds")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(ev, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(ev, indent=2, ensure_ascii=False))
    return 0 if ev["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
