"""
Coordinador central de defensa NOVUS — evidencia unificada y notificación al Kernel IA.
No sustituye motores existentes; conecta detección → registro → kernel.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional

from utils.logger import logger

_dedupe_lock = threading.Lock()
_recent_detection_fps: Dict[str, float] = {}
_DEDUPE_TTL_SEC = 120.0
_DEDUPE_MAX = 512


def record_detection(
    motor: str,
    action: str,
    evidence: dict,
    *,
    phase: str = "detect",
    outcome: str = "detected",
    threat_type: Optional[str] = None,
    finding_id: Optional[str] = None,
    detail: Optional[str] = None,
    confidence: Optional[str] = None,
    user_email: Optional[str] = None,
    tenant_id: Optional[str] = None,
    scope: Optional[str] = None,
    event_id: Optional[str] = None,
    severity: Optional[str] = None,
) -> Dict[str, Any]:
    """Registra detección en defense_registry con contrato canónico (si aplica)."""
    try:
        from services.platform_event_contract import (
            SCOPE_HOST,
            detection_fingerprint,
            normalize_detection,
        )
        from services.defense_evidence_registry import record_defense_event

        ev = dict(evidence or {})
        # Propagar scope/tenant sin inventar atribución host→tenant
        resolved_scope = scope or ev.get("scope")
        resolved_tenant = tenant_id if tenant_id is not None else ev.get("tenant_id")
        if (resolved_scope or "").upper() == SCOPE_HOST:
            resolved_tenant = None

        detection = normalize_detection(
            source=motor,
            detection_type=str(threat_type or action or "detection"),
            evidence=ev,
            severity=severity or ev.get("severity"),
            confidence=confidence if confidence is not None else ev.get("confidence"),
            status="DETECTED" if outcome == "detected" else (outcome or "UNKNOWN").upper(),
            tenant_id=resolved_tenant,
            scope=resolved_scope or SCOPE_HOST,
            event_id=event_id or finding_id or ev.get("event_id"),
            correlation_id=ev.get("correlation_id"),
            ip=ev.get("ip"),
        )

        fp = detection_fingerprint(detection)
        now = time.time()
        with _dedupe_lock:
            last = _recent_detection_fps.get(fp)
            if last and (now - last) < _DEDUPE_TTL_SEC:
                return {
                    "status": "deduplicated",
                    "event_id": detection.get("event_id"),
                    "fingerprint": fp,
                    "reason": "same_detection_within_ttl",
                    "severity": detection.get("severity"),
                    "confidence": detection.get("confidence"),
                    "decision": detection.get("decision"),
                    "scope": detection.get("scope"),
                    "tenant_id": detection.get("tenant_id"),
                }
            _recent_detection_fps[fp] = now
            if len(_recent_detection_fps) > _DEDUPE_MAX:
                cutoff = now - _DEDUPE_TTL_SEC
                stale = [k for k, t in _recent_detection_fps.items() if t < cutoff]
                for k in stale:
                    _recent_detection_fps.pop(k, None)

        evidence_out = {
            **ev,
            "event_id": detection.get("event_id"),
            "correlation_id": detection.get("correlation_id"),
            "scope": detection.get("scope"),
            "tenant_id": detection.get("tenant_id"),
            "detection_type": detection.get("detection_type"),
            "canonical": True,
            "decision": detection.get("decision"),
            "response_status": detection.get("response_status") or "PENDING",
            "verification_status": detection.get("verification_status") or "NOT_VERIFIED",
        }

        result = record_defense_event(
            phase=phase,
            action=action,
            motor=motor,
            outcome=outcome,
            threat_type=threat_type or detection.get("detection_type"),
            evidence=evidence_out,
            finding_id=finding_id or detection.get("event_id"),
            detail=detail,
            confidence=confidence if confidence is not None else detection.get("confidence"),
            user_email=user_email,
        )
        payload = {
            "motor": motor,
            "action": action,
            "phase": phase,
            "outcome": outcome,
            "threat_type": threat_type or detection.get("detection_type"),
            "detail": detail,
            "evidence": evidence_out,
            "finding_id": finding_id or detection.get("event_id"),
            "user_email": user_email,
            "event_id": detection.get("event_id"),
            "correlation_id": detection.get("correlation_id"),
            "tenant_id": detection.get("tenant_id"),
            "scope": detection.get("scope"),
            "severity": detection.get("severity"),
            "confidence": detection.get("confidence"),
            "decision": detection.get("decision"),
            "response_status": detection.get("response_status"),
            "verification_status": detection.get("verification_status"),
        }
        if result.get("status") != "skipped":
            _maybe_network_history(payload)
            _maybe_forensic_pcap(payload)
            _maybe_swarm_defense(payload)
            _maybe_adaptive_profile(payload)
        result["event_id"] = detection.get("event_id")
        result["scope"] = detection.get("scope")
        result["tenant_id"] = detection.get("tenant_id")
        result["severity"] = detection.get("severity")
        result["confidence"] = detection.get("confidence")
        result["decision"] = detection.get("decision")
        result["response_status"] = detection.get("response_status")
        result["verification_status"] = detection.get("verification_status")
        result["fingerprint"] = fp
        if result.get("status") != "skipped" and "status" not in result:
            result["status"] = "ok"
        return result
    except Exception as exc:
        logger.debug("defense_coordinator record_detection: %s", exc)
        return {"status": "error", "error": str(exc)}


def _maybe_adaptive_profile(event_payload: Dict[str, Any]) -> None:
    """
    Alimenta el Adaptive Profile Engine con señales de otros motores.
    No aprende amenazas (anti-poisoning); evita bucle si el origen ya es APE.
    """
    try:
        motor = str(event_payload.get("motor") or "")
        if motor in ("adaptive_profile_engine", "behavior_baseline"):
            return
        email = event_payload.get("user_email")
        if not email:
            return
        from services.adaptive_profile_engine import observe_async

        threat = event_payload.get("threat_type") or event_payload.get("action") or "defense_signal"
        evidence = dict(event_payload.get("evidence") or {})
        evidence["from_motor"] = motor
        evidence["threat_flags"] = list(
            {
                *(evidence.get("threat_flags") or []),
                str(threat).lower(),
            }
        )
        # evaluate=False: no re-disparar anomalías; learnable bloqueado por threat_flags
        observe_async(
            str(email),
            event_type="defense_signal",
            evidence=evidence,
            risk_level="high",
            mechanisms=[motor, "defense_coordinator"],
            source_motor=motor or "defense_coordinator",
            evaluate=False,
        )
    except Exception as exc:
        logger.debug("adaptive profile from defense: %s", exc)


def _maybe_network_history(event_payload: Dict[str, Any]) -> None:
    try:
        from services.network_security_history_service import try_append_from_defense_event

        try_append_from_defense_event(event_payload)
    except Exception as exc:
        logger.debug("network history from defense: %s", exc)


def _maybe_forensic_pcap(event_payload: Dict[str, Any]) -> None:
    try:
        from services.forensic_pcap_capture_service import maybe_auto_capture_from_defense

        maybe_auto_capture_from_defense(event_payload)
    except Exception as exc:
        logger.debug("forensic pcap auto: %s", exc)


def _maybe_swarm_defense(event_payload: Dict[str, Any]) -> None:
    """Publica detección al Swarm Defense Engine (capa aditiva, no bloqueante)."""
    try:
        from services.swarm_defense import notify_detection

        notify_detection(event_payload)
    except Exception as exc:
        logger.debug("swarm defense notify: %s", exc)


def notify_kernel_incident(
    motor: str,
    evento: str,
    detail: str,
    *,
    incident_id: Optional[str] = None,
    severity: str = "medium",
    evidence: Optional[dict] = None,
) -> None:
    """Notifica incidente al Kernel IA (log operativo + auditoría DB)."""
    try:
        from services.kernel_memory import kernel_memory

        kernel_memory.log_operation({
            "type": "security_incident",
            "motor": motor,
            "evento": evento,
            "incident_id": incident_id,
            "severity": severity,
            "detail": detail[:500],
            "evidence": evidence or {},
        })
    except Exception as exc:
        logger.debug("defense_coordinator kernel_memory: %s", exc)

    try:
        from database import SessionLocal, registrar_log_seguridad

        db = SessionLocal()
        try:
            msg = detail[:400]
            if incident_id:
                msg = f"incident_id={incident_id} {msg}"
            registrar_log_seguridad(db, evento, msg)
            db.commit()
        finally:
            db.close()
    except Exception as exc:
        logger.debug("defense_coordinator registrar_log: %s", exc)


def publish_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Publicación de eventos meta/lote desde motores (p.ej. TIE IOC batch).
    Alias sobre record_detection — no duplica bus de eventos.
    """
    if not isinstance(event, dict):
        return {"status": "error", "error": "invalid_event"}
    motor = str(event.get("source") or event.get("motor") or event.get("source_engine") or "unknown")
    action = str(event.get("type") or event.get("action") or event.get("event_type") or "publish_event")
    evidence = dict(event)
    evidence.setdefault("correlation_id", event.get("correlation_id") or event.get("id"))
    return record_detection(
        motor=motor,
        action=action,
        evidence=evidence,
        phase=str(event.get("phase") or "detect"),
        outcome=str(event.get("outcome") or "detected"),
        threat_type=event.get("threat_type"),
        finding_id=event.get("finding_id") or event.get("event_id"),
        detail=event.get("detail"),
        confidence=event.get("confidence"),
        user_email=event.get("user_email"),
    )


class DefenseCoordinator:
    record_detection = staticmethod(record_detection)
    publish_event = staticmethod(publish_event)
    notify_kernel_incident = staticmethod(notify_kernel_incident)


defense_coordinator = DefenseCoordinator()
