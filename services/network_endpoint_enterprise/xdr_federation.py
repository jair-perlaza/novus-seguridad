"""
XDR multi-sensor federado — agrega evidencias reales de NDR + Endpoint + Web + Mail + NEE.
No es un wrap del detector local: consulta múltiples motores/registry.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_federated_xdr_payload(*, limit_per_sensor: int = 25) -> Dict[str, Any]:
    sensors: Dict[str, Any] = {}
    findings: List[Dict[str, Any]] = []

    # NDR
    try:
        from services.network_ndr_service import build_ndr_payload

        ndr = build_ndr_payload() or {}
        alerts = ndr.get("alerts") or ndr.get("behavior_alerts") or []
        sensors["ndr"] = {
            "ok": True,
            "alert_count": len(alerts),
            "devices": ndr.get("device_count") or ndr.get("devices_count"),
        }
        for a in alerts[:limit_per_sensor]:
            findings.append({"sensor": "ndr", "finding": a})
    except Exception as exc:
        sensors["ndr"] = {"ok": False, "error": str(exc)[:160]}

    # Endpoint monitor
    try:
        from services.endpoint_realtime_monitor import get_monitor_status, list_monitor_events

        st = get_monitor_status()
        evs = list_monitor_events(limit=limit_per_sensor)
        sensors["endpoint"] = {
            "ok": True,
            "active": st.get("active"),
            "events_total": st.get("events_total"),
            "recent": len(evs),
        }
        for e in evs:
            if (e.get("severity") or "").lower() in ("medium", "high", "critical"):
                findings.append({"sensor": "endpoint", "finding": e})
    except Exception as exc:
        sensors["endpoint"] = {"ok": False, "error": str(exc)[:160]}

    # Defense registry (web/mail/security)
    try:
        from services.defense_evidence_registry import list_recent_events

        events = list_recent_events(limit=80) or []
        by_motor: Dict[str, int] = {}
        for ev in events:
            motor = str(ev.get("motor") or "unknown")
            by_motor[motor] = by_motor.get(motor, 0) + 1
            mlow = motor.lower()
            if any(x in mlow for x in ("web", "mail", "ndr", "endpoint", "network_endpoint", "security", "xdr")):
                findings.append({"sensor": "defense_registry", "finding": {
                    "motor": motor,
                    "action": ev.get("action"),
                    "threat_type": ev.get("threat_type"),
                    "ts": ev.get("ts") or ev.get("timestamp"),
                    "finding_id": ev.get("finding_id") or ev.get("event_id"),
                }})
        sensors["defense_registry"] = {"ok": True, "by_motor": by_motor, "sampled": len(events)}
    except Exception as exc:
        sensors["defense_registry"] = {"ok": False, "error": str(exc)[:160]}

    # Enterprise sensor status
    try:
        from services.network_endpoint_enterprise.orchestrator import get_enterprise_status

        sensors["network_endpoint_enterprise"] = get_enterprise_status()
    except Exception as exc:
        sensors["network_endpoint_enterprise"] = {"ok": False, "error": str(exc)[:120]}

    active = sum(1 for s in sensors.values() if isinstance(s, dict) and s.get("ok"))
    return {
        "ok": active >= 2,
        "federated": True,
        "collected_at_utc": _utc(),
        "sensors_active": active,
        "sensors": sensors,
        "findings_count": len(findings),
        "findings": findings[:80],
        "source": "network_endpoint_enterprise.xdr_federation",
    }
