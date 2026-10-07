#!/usr/bin/env python3
"""Publicación ZDDE → defense_coordinator + sello forense. Sin acciones destructivas."""
from __future__ import annotations

import socket
from typing import Any, Dict, Optional

from utils.logger import logger


def host_profile_email() -> str:
    return f"host@{socket.gethostname()}.novus.internal"


def publish_zdde(
    *,
    action: str,
    evidence: dict,
    threat_type: Optional[str] = None,
    confidence: str = "medium",
    finding_id: Optional[str] = None,
    risk_level: Optional[str] = None,
) -> Dict[str, Any]:
    ev = dict(evidence or {})
    ev.setdefault("verified", True)
    ev.setdefault("equipment", socket.gethostname())
    ev.setdefault("source", "zero_day_detection_engine")
    ev.setdefault("signature_based", False)
    ev.setdefault("zero_day_cve_confirmed", False)
    ev.setdefault("static_rules_primary", False)
    if risk_level:
        ev.setdefault("risk_level", risk_level)
    try:
        from services.defense_coordinator import record_detection

        return record_detection(
            motor="zero_day_detection_engine",
            action=action,
            evidence=ev,
            phase="detect",
            outcome="detected" if ev.get("classification") != "EVIDENCIA_INSUFICIENTE" else "observed",
            threat_type=threat_type or action,
            finding_id=finding_id,
            detail=action,
            confidence=confidence,
            user_email=None,
        )
    except Exception as exc:
        logger.warning("zdde publish: %s", exc)
        return {"status": "error", "error": str(exc)}


def seal_zdde(
    *,
    finding_id: str,
    action: str,
    evidence: dict,
    risk_level: str,
) -> Optional[Dict[str, Any]]:
    try:
        from services.forensic_evidence_integrity_service import seal_evidence

        return seal_evidence(
            source_id=finding_id,
            source_type="zero_day_detection_engine",
            motor="zero_day_detection_engine",
            evidence_type=action,
            payload={
                "action": action,
                "risk_level": risk_level,
                "evidence": evidence,
                "zero_day_cve_confirmed": False,
                "signature_based": False,
                "static_rules_primary": False,
                "custody_chain": True,
            },
            equipment=socket.gethostname(),
        )
    except Exception as exc:
        logger.debug("zdde seal: %s", exc)
        return None


def notify_proposals(proposals: list, classification: str) -> Dict[str, Any]:
    """Eleva / notifica; nunca ejecuta isolate/kill sin aprobación."""
    notified = []
    for p in proposals or []:
        act = str((p or {}).get("action") or "")
        if (p or {}).get("requires_approval"):
            notified.append({"action": act, "status": "pending_approval", "executed": False})
            continue
        if act in ("elevate_alert", "notify_defense_center", "preserve_evidence", "increase_monitoring"):
            notified.append({"action": act, "status": "recorded", "executed": False, "destructive": False})
        else:
            notified.append({"action": act, "status": "skipped_policy", "executed": False})
    return {
        "classification": classification,
        "notifications": notified,
        "destructive_auto": False,
    }
