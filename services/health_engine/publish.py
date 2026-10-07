#!/usr/bin/env python3
"""Publicación Health Engine → defense_coordinator / Swarm. Sin acciones destructivas."""
from __future__ import annotations

import socket
import os
from typing import Any, Dict, List, Optional

from utils.logger import logger


def host_profile_email() -> str:
    return f"host@{socket.gethostname()}.novus.internal"


def publish_health_event(
    *,
    action: str,
    evidence: dict,
    threat_type: Optional[str] = None,
    confidence: str = "medium",
    finding_id: Optional[str] = None,
    risk_level: Optional[str] = None,
    outcome: str = "observed",
    async_swarm: bool = True,
) -> Dict[str, Any]:
    ev = dict(evidence or {})
    ev.setdefault("verified", True)
    ev.setdefault("equipment", socket.gethostname())
    ev.setdefault("source", "health_engine")
    ev.setdefault("invented", False)
    ev.setdefault("fake_telemetry", False)
    if risk_level:
        ev.setdefault("risk_level", risk_level)

    def _do_publish() -> Dict[str, Any]:
        try:
            from services.defense_coordinator import record_detection

            return record_detection(
                motor="health_engine",
                action=action,
                evidence=ev,
                phase="monitor",
                outcome=outcome,
                threat_type=threat_type or action,
                finding_id=finding_id,
                detail=action,
                confidence=confidence,
                user_email=None,
            )
        except Exception as exc:
            logger.warning("health publish: %s", exc)
            return {"status": "error", "error": str(exc)}

    if async_swarm:
        # Permite pruebas sin saturar Swarm/ARP
        if os.environ.get("NOVUS_HEALTH_SWARM_ASYNC", "1") in ("0", "false", "False"):
            return {
                "status": "outbox_only",
                "finding_id": finding_id,
                "action": action,
                "swarm_async_disabled": True,
            }
        import threading

        holder: Dict[str, Any] = {"status": "queued_async", "finding_id": finding_id, "action": action}

        def _worker() -> None:
            try:
                _do_publish()
            except Exception as exc:
                logger.debug("health async publish: %s", exc)

        threading.Thread(target=_worker, daemon=True, name="HealthPublishSwarm").start()
        return holder
    return _do_publish()


def publish_cycle_to_swarm(
    *,
    issues: List[Dict[str, Any]],
    alerts: List[Dict[str, Any]],
    summary: Dict[str, Any],
    cycle_id: str,
) -> Dict[str, Any]:
    elevate = any(i.get("elevate_swarm_risk") for i in issues)
    failed = int(summary.get("services_down") or 0)
    risk = "low"
    if elevate or failed >= 3:
        risk = "critical"
    elif failed >= 1 or any(a.get("severity") == "critical" for a in alerts):
        risk = "high"
    elif alerts:
        risk = "medium"

    payload = {
        "cycle_id": cycle_id,
        "overall_status": summary.get("overall_status"),
        "services_active": summary.get("services_active"),
        "services_down": summary.get("services_down"),
        "availability_pct": summary.get("availability_pct"),
        "issue_codes": [i.get("code") for i in (issues or [])[:30]],
        "alert_count": len(alerts or []),
        "multi_component_failure": elevate,
        "swarm_risk_internal": risk,
        "elevate_internal_risk": elevate or failed >= 2,
    }

    # Outbox local — evidencia objetiva de entrega a Swarm (además del publish async)
    try:
        from services.health_engine.store import append_jsonl, DATA_DIR
        import os

        outbox = os.path.join(DATA_DIR, "swarm_outbox.jsonl")
        append_jsonl(
            outbox,
            {
                "destination": "swarm_defense",
                "motor": "health_engine",
                "action": "health_anomaly_detected" if issues else "health_heartbeat",
                "payload": payload,
            },
        )
        payload["outbox"] = outbox
    except Exception as exc:
        logger.debug("health swarm outbox: %s", exc)

    if not issues and not alerts:
        pub = publish_health_event(
            action="health_heartbeat",
            evidence=payload,
            threat_type="platform_health",
            confidence="high",
            finding_id=cycle_id,
            risk_level=risk,
            outcome="observed",
            async_swarm=True,
        )
        pub["swarm_outbox"] = True
        return pub

    pub = publish_health_event(
        action="health_anomaly_detected" if issues else "health_alert",
        evidence=payload,
        threat_type="platform_health_failure" if failed else "platform_health_degraded",
        confidence="high",
        finding_id=cycle_id,
        risk_level=risk,
        outcome="detected" if issues else "observed",
        async_swarm=True,
    )
    pub["swarm_outbox"] = True
    return pub
