"""Publicación canónica WSAE → defense_coordinator → Swarm / Forense."""
from __future__ import annotations

from typing import Any, Dict, Optional

from utils.logger import logger


def publish_wsae(
    *,
    action: str,
    evidence: dict,
    threat_type: Optional[str] = None,
    confidence: str = "medium",
    finding_id: Optional[str] = None,
    risk_level: Optional[str] = None,
    user_email: Optional[str] = None,
) -> Dict[str, Any]:
    ev = dict(evidence or {})
    ev.setdefault("verified", True)
    ev.setdefault("source", "web_security_auth_enterprise")
    if risk_level:
        ev.setdefault("risk_level", risk_level)
    try:
        from services.defense_coordinator import record_detection

        return record_detection(
            motor="web_security_auth_enterprise",
            action=action,
            evidence=ev,
            phase="detect" if risk_level and risk_level not in ("info", "low") else "audit",
            outcome="detected",
            threat_type=threat_type or action,
            finding_id=finding_id,
            detail=action,
            confidence=confidence,
            user_email=user_email,
        )
    except Exception as exc:
        logger.warning("wsae publish: %s", exc)
        return {"status": "error", "error": str(exc)}


def seal_wsae(*, finding_id: str, action: str, evidence: dict, risk_level: str = "info") -> Optional[Dict[str, Any]]:
    try:
        import socket
        from services.forensic_evidence_integrity_service import seal_evidence

        return seal_evidence(
            source_id=finding_id,
            source_type="web_security_auth_enterprise",
            motor="web_security_auth_enterprise",
            evidence_type=action,
            payload={"action": action, "risk_level": risk_level, "evidence": evidence},
            equipment=socket.gethostname(),
            user_email=(evidence or {}).get("user_email"),
        )
    except Exception as exc:
        logger.debug("wsae seal: %s", exc)
        return None
