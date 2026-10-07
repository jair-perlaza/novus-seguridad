"""Publicación canónica BTDE → defense_coordinator → Swarm / Forense / APE."""
from __future__ import annotations

import socket
from typing import Any, Dict, Optional

from utils.logger import logger


def host_profile_email() -> str:
    return f"host@{socket.gethostname()}.novus.internal"


def publish_btde(
    *,
    action: str,
    evidence: dict,
    threat_type: Optional[str] = None,
    confidence: str = "medium",
    finding_id: Optional[str] = None,
    risk_level: Optional[str] = None,
    feed_ape: bool = False,
) -> Dict[str, Any]:
    ev = dict(evidence or {})
    ev.setdefault("verified", True)
    ev.setdefault("equipment", socket.gethostname())
    ev.setdefault("source", "behavioral_threat_detection")
    ev.setdefault("signature_based", False)
    if risk_level:
        ev.setdefault("risk_level", risk_level)
    try:
        from services.defense_coordinator import record_detection

        return record_detection(
            motor="behavioral_threat_detection",
            action=action,
            evidence=ev,
            phase="detect",
            outcome="detected",
            threat_type=threat_type or action,
            finding_id=finding_id,
            detail=action,
            confidence=confidence,
            user_email=host_profile_email() if feed_ape else None,
        )
    except Exception as exc:
        logger.warning("btde publish: %s", exc)
        return {"status": "error", "error": str(exc)}


def seal_btde(
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
            source_type="behavioral_threat_detection",
            motor="behavioral_threat_detection",
            evidence_type=action,
            payload={
                "action": action,
                "risk_level": risk_level,
                "evidence": evidence,
                "zero_day_claimed": False,
                "ml_classifier_claimed": False,
                "signature_based": False,
            },
            equipment=socket.gethostname(),
        )
    except Exception as exc:
        logger.debug("btde seal: %s", exc)
        return None
