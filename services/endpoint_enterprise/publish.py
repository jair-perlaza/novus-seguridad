"""Publicación canónica Endpoint Enterprise → defense_coordinator → Swarm/Forense/APE."""
from __future__ import annotations

import socket
from typing import Any, Dict, List, Optional

from utils.logger import logger


def host_profile_email() -> str:
    return f"host@{socket.gethostname()}.novus.internal"


def publish_finding(
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
    ev.setdefault("source", "endpoint_enterprise")
    if risk_level:
        ev.setdefault("risk_level", risk_level)
    try:
        from services.defense_coordinator import record_detection

        return record_detection(
            motor="endpoint_enterprise",
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
        logger.warning("endpoint_enterprise publish: %s", exc)
        return {"status": "error", "error": str(exc)}


def publish_findings(findings: List[Dict[str, Any]], *, prefix: str) -> int:
    n = 0
    for f in findings or []:
        sev = str(f.get("severity") or "low").lower()
        if sev in ("info",):
            continue
        # Anti-poison: no APE learn on high/critical threats
        feed = sev in ("low", "medium") and f.get("finding_type") not in (
            "anomalous_powershell",
            "lolbin_network_fetch",
        )
        fid = f"EEP-{prefix}-{f.get('finding_type') or f.get('rule')}-{abs(hash(str(f))) % 10**10}"
        publish_finding(
            action=f"eep_{f.get('finding_type') or f.get('rule') or prefix}",
            evidence=f,
            threat_type=str(f.get("finding_type") or f.get("category") or "endpoint_threat"),
            confidence=str(f.get("confidence") or "medium"),
            finding_id=fid,
            risk_level=sev,
            feed_ape=feed and sev == "low",
        )
        n += 1
    return n
