#!/usr/bin/env python3
"""Prueba Adaptive Profile Engine en :5000 — aprendizaje interno, sin panel UI."""
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
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "motor_telemetry" / "LIVE_PROOF_ADAPTIVE_PROFILE.json"
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)


def csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""


def main() -> int:
    ev: dict = {"base": BASE, "started_at": datetime.now().isoformat(timespec="seconds"), "email": EMAIL}
    s = requests.Session()

    g = s.get(f"{BASE}/login", timeout=30)
    p = s.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PASSWORD, "csrf_token": csrf(g.text)},
        timeout=90,
        allow_redirects=False,
    )
    dash = s.get(f"{BASE}/dashboard", timeout=90)
    html = dash.text
    ev["ui"] = {
        "login_status": p.status_code,
        "dash_status": dash.status_code,
        "has_behavior_panel": "novus-behavior-panel" in html,
        "has_comportamiento_cliente_title": "Comportamiento del Cliente" in html,
        "has_notif_js": "novus-notification-center.js" in html,
        "has_bell": "novus-bell-btn" in html or "layout-bell-btn" in html,
    }

    # Esperar observe async de login
    time.sleep(5)

    summary = s.get(f"{BASE}/api/behavior/summary", timeout=30).json()
    status = s.get(f"{BASE}/api/internal/adaptive-profile/status", timeout=30).json()
    ev["api_summary_opaque"] = {
        "status": summary.get("status"),
        "visible": summary.get("visible"),
        "exposes_patterns": "usual_hours" in summary or "patterns" in summary or "normality_score" in summary,
        "message": summary.get("message"),
    }
    st_dump = json.dumps(status)
    ev["api_status"] = {
        "status": status.get("status"),
        "visible_to_user": status.get("visible_to_user"),
        "kernel_context_available": status.get("kernel_context_available"),
        "enough_data": status.get("enough_data"),
        "events_count": status.get("events_count"),
        "engine_id": (status.get("engine") or {}).get("engine_id"),
        "anti_poisoning": (status.get("engine") or {}).get("anti_poisoning"),
        "exposes_baseline_dump": bool(re.search(r'"usual_(ips|hours|gateways)"\s*:', st_dump)),
    }

    # Aprendizaje real vía motor (misma DB que el servidor)
    from services.adaptive_profile_engine import (
        observe,
        rebuild_defense_profile,
        kernel_adaptive_context,
        engine_status,
        evaluate_against_profile,
    )
    from database import SessionLocal, BehaviorActivityEvent, BehaviorAnomaly, NovusNotification

    learn_ids = []
    for i in range(6):
        r = observe(
            user_email=EMAIL,
            event_type="session_heartbeat" if i else "login",
            ip="127.0.0.1",
            mechanisms=["prove_adaptive_profile"],
            source_motor="prove_adaptive_profile",
            evaluate=True,
        )
        learn_ids.append(r.get("event_id"))
    rebuilt = rebuild_defense_profile(EMAIL)
    kctx = kernel_adaptive_context(EMAIL)
    est = engine_status()

    # Anti-poisoning: señal con threat_flags no debe ser learnable
    poison = observe(
        user_email=EMAIL,
        event_type="defense_signal",
        ip="203.0.113.99",
        evidence={"threat_flags": ["malware"], "from_motor": "prove"},
        risk_level="critical",
        source_motor="prove_poison",
        evaluate=False,
    )

    # Anomalía inducida: IP no habitual tras baseline (si enough_data)
    anomaly_obs = observe(
        user_email=EMAIL,
        event_type="session_heartbeat",
        ip="198.51.100.77",
        mechanisms=["prove_anomaly"],
        source_motor="prove_anomaly",
        evaluate=True,
        evidence={"force_ip": "198.51.100.77"},
    )

    db = SessionLocal()
    try:
        events_n = (
            db.query(BehaviorActivityEvent)
            .filter(BehaviorActivityEvent.user_email == EMAIL.lower())
            .count()
        )
        ape_events = (
            db.query(BehaviorActivityEvent)
            .filter(
                BehaviorActivityEvent.user_email == EMAIL.lower(),
                BehaviorActivityEvent.source_motor.in_(
                    ["prove_adaptive_profile", "adaptive_profile_engine", "login_session_audit", "prove_poison", "prove_anomaly"]
                ),
            )
            .count()
        )
        anomalies_n = (
            db.query(BehaviorAnomaly)
            .filter(BehaviorAnomaly.user_email == EMAIL.lower())
            .count()
        )
        notif_rows = (
            db.query(NovusNotification)
            .filter(NovusNotification.user_email == EMAIL.lower())
            .order_by(NovusNotification.id.desc())
            .limit(15)
            .all()
        )
        notifs = [
            {
                "title": n.title,
                "category": n.category,
                "source_motor": n.source_motor,
                "exposes_engine_name": "adaptive_profile" in ((n.title or "") + (n.description or "")).lower()
                or "baseline" in ((n.title or "") + (n.description or "")).lower(),
            }
            for n in notif_rows
        ]
    finally:
        db.close()

    listed = s.get(f"{BASE}/api/notifications?limit=25", timeout=30).json()
    ape_notifs_api = [
        n
        for n in (listed.get("notifications") or [])
        if n.get("source_motor") == "adaptive_profile_engine"
    ]

    ev["learning"] = {
        "observe_ok": all(bool(x) for x in learn_ids),
        "events_in_db": events_n,
        "ape_related_events": ape_events,
        "rebuild_ok": rebuilt.get("ok"),
        "rebuild_events_count": rebuilt.get("events_count"),
        "enough_data": rebuilt.get("enough_data"),
        "poison_learnable": poison.get("learnable"),
        "anomaly_observe_anomalies_n": anomaly_obs.get("anomalies_n"),
        "anomalies_in_db": anomalies_n,
    }
    kdump = json.dumps(kctx)
    ev["kernel"] = {
        "adaptive_available": (kctx.get("adaptive_profile") or {}).get("available"),
        "enough_data": (kctx.get("adaptive_profile") or {}).get("enough_data"),
        "signals_keys": list(((kctx.get("adaptive_profile") or {}).get("signals") or {}).keys()),
        "exposes_usual_ips_list": bool(re.search(r'"usual_ips"\s*:', kdump)),
    }
    ev["engine_status"] = est
    ev["notifications"] = {
        "api_count": listed.get("count"),
        "ape_conclusion_notifs": len(ape_notifs_api),
        "sample_titles": [n.get("title") for n in ape_notifs_api[:5]],
        "recent_db": notifs[:8],
    }

    checks = {
        "no_behavior_panel": not ev["ui"]["has_behavior_panel"],
        "no_comportamiento_title": not ev["ui"]["has_comportamiento_cliente_title"],
        "summary_opaque": not ev["api_summary_opaque"]["exposes_patterns"] and ev["api_summary_opaque"]["visible"] is False,
        "status_no_baseline_dump": not ev["api_status"]["exposes_baseline_dump"],
        "learning_persisted": events_n >= 6,
        "poison_blocked": poison.get("learnable") is False,
        "kernel_gets_context": bool((kctx.get("adaptive_profile") or {}).get("available")),
        "kernel_no_ip_list_dump": not ev["kernel"]["exposes_usual_ips_list"],
        "notif_center_present": ev["ui"]["has_notif_js"],
    }
    ev["checks"] = checks
    ev["ok"] = all(checks.values())
    ev["finished_at"] = datetime.now().isoformat(timespec="seconds")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(ev, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"ok": ev["ok"], "checks": checks, "out": str(OUT)}, indent=2, ensure_ascii=False))
    return 0 if ev["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
