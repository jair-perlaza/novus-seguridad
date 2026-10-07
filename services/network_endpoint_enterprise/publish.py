"""
Publicación canónica → defense_coordinator → Swarm / Forense / APE / historial.
"""
from __future__ import annotations

import socket
from typing import Any, Dict, List, Optional

from utils.logger import logger

HOST_PROFILE_EMAIL = None  # lazy


def host_profile_email() -> str:
    global HOST_PROFILE_EMAIL
    if not HOST_PROFILE_EMAIL:
        HOST_PROFILE_EMAIL = f"host@{socket.gethostname()}.novus.internal"
    return HOST_PROFILE_EMAIL


def publish_event(
    *,
    motor: str,
    action: str,
    evidence: dict,
    threat_type: Optional[str] = None,
    confidence: str = "medium",
    detail: Optional[str] = None,
    finding_id: Optional[str] = None,
    outcome: str = "detected",
    feed_ape: bool = True,
    risk_level: Optional[str] = None,
) -> Dict[str, Any]:
    """Registra detección real; el coordinador dispara Swarm/Forense/historial."""
    ev = dict(evidence or {})
    ev.setdefault("equipment", socket.gethostname())
    ev.setdefault("verified", True)
    ev.setdefault("source", "network_endpoint_enterprise")
    if risk_level:
        ev.setdefault("risk_level", risk_level)

    try:
        from services.defense_coordinator import record_detection

        result = record_detection(
            motor=motor,
            action=action,
            evidence=ev,
            phase="detect",
            outcome=outcome,
            threat_type=threat_type or action,
            finding_id=finding_id,
            detail=detail,
            confidence=confidence,
            user_email=host_profile_email() if feed_ape else None,
        )
        return result if isinstance(result, dict) else {"status": "ok", "raw": result}
    except Exception as exc:
        logger.warning("nee publish_event: %s", exc)
        return {"status": "error", "error": str(exc)}


def publish_changes(
    changes: List[Dict[str, Any]],
    *,
    motor: str,
    category: str,
) -> List[Dict[str, Any]]:
    """Publica solo cambios relevantes (no el snapshot completo)."""
    results = []
    for ch in changes or []:
        ctype = ch.get("change_type") or "change"
        sev_map = {
            "gateway_change": ("high", "infrastructure_change"),
            "dhcp_change": ("high", "rogue_dhcp"),
            "dns_change": ("medium", "dns_change"),
            "ip_change": ("high", "host_ip_change"),
            "mac_change": ("critical", "mac_change"),
            "route_change": ("medium", "route_change"),
            "dns_resolution_new": ("low", "dns_resolution"),
            "new_or_stopped_service": ("medium", "service_change"),
            "listening_port_change": ("medium", "port_change"),
            "possible_dll_injection": ("high", "dll_injection"),
            "driver_change": ("medium", "driver_change"),
            "scheduled_task_change": ("medium", "persistence_change"),
            "user_session_change": ("low", "user_change"),
            "new_device": ("medium", "new_device"),
            "device_ip_change": ("medium", "device_ip_change"),
        }
        risk, threat = sev_map.get(ctype, ("low", ctype))
        # Skip low DNS noise floods unless many
        if ctype == "dns_resolution_new" and len(ch.get("added") or []) < 3:
            continue
        if ctype == "dns_resolution_expired":
            continue
        fid = f"NEE-{category}-{ctype}-{abs(hash(str(ch))) % 10**10}"
        results.append(
            publish_event(
                motor=motor,
                action=f"nee_{ctype}",
                evidence=ch,
                threat_type=threat,
                confidence="high" if risk in ("high", "critical") else "medium",
                detail=f"{category}:{ctype}",
                finding_id=fid,
                risk_level=risk,
                feed_ape=(risk not in ("high", "critical")),  # anti-poison: no aprender amenazas
            )
        )
    return results


def publish_alert(alert: Dict[str, Any], *, motor: str) -> Dict[str, Any]:
    return publish_event(
        motor=motor,
        action=alert.get("type") or "nee_alert",
        evidence=alert,
        threat_type=alert.get("type") or "anomaly",
        confidence="high",
        detail=alert.get("evidence") or alert.get("type"),
        finding_id=alert.get("alert_id"),
        risk_level=alert.get("severity") or "high",
        feed_ape=False,
    )
