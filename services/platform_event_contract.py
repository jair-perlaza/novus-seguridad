#!/usr/bin/env python3
"""
Contrato de eventos NOVUS — Single Source of Truth (campos canónicos).

No es un motor independiente. Define el esquema mínimo que los registros
de defensa y SDL deben respetar cuando exista evidencia.
"""
from __future__ import annotations
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

NA = "NO DISPONIBLE"

REQUIRED_WHEN_PRESENT = (
    "event_id",
    "timestamp_utc",
    "source_engine",
    "event_type",
    "severity",
    "confidence",
    "correlation_id",
)

OPTIONAL_CONTEXT = (
    "asset_id",
    "user_id",
    "ip",
    "hostname",
    "ioc",
    "incident_id",
    "evidence_id",
    "integrity_hash",
)

# Scopes reales — no fabricar tenant_id para telemetría de host.
SCOPE_HOST = "HOST"
SCOPE_TENANT = "TENANT"
SCOPE_PLATFORM = "PLATFORM"

DETECTION_STATUS = (
    "DETECTED",
    "PENDING",
    "NOT_AVAILABLE",
    "UNKNOWN",
)

SEVERITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL", "NOT_AVAILABLE")
CONFIDENCE_LEVELS = ("LOW", "MEDIUM", "HIGH", "NOT_AVAILABLE")
DECISION_ACTIONS = (
    "MONITOR",
    "ALERT",
    "INVESTIGATE",
    "REMEDIATE",
    "CONTAIN",
    "ESCALATE",
    "BLOCK",
)
VERIFICATION_STATUS = (
    "SUCCESS",
    "FAILED",
    "PARTIAL",
    "NOT_VERIFIED",
    "NOT_IMPLEMENTED",
)


def normalize_severity_label(raw: Any) -> str:
    """Canonical severity vocabulary. Does not invent — missing → NOT_AVAILABLE."""
    if raw is None or raw == "" or raw == NA:
        return "NOT_AVAILABLE"
    s = str(raw).strip().upper()
    aliases = {
        "CRIT": "CRITICAL",
        "CRITICAL": "CRITICAL",
        "ALTA": "HIGH",
        "HIGH": "HIGH",
        "MED": "MEDIUM",
        "MEDIUM": "MEDIUM",
        "MEDIA": "MEDIUM",
        "LOW": "LOW",
        "BAJA": "LOW",
        "INFO": "LOW",
        "INFORMATIONAL": "LOW",
    }
    out = aliases.get(s, s)
    return out if out in SEVERITY_LEVELS else "NOT_AVAILABLE"


def normalize_confidence_label(raw: Any) -> str:
    """Canonical confidence — independent from severity. Missing → NOT_AVAILABLE."""
    if raw is None or raw == "" or raw == NA:
        return "NOT_AVAILABLE"
    if isinstance(raw, (int, float)):
        v = float(raw)
        if v >= 75:
            return "HIGH"
        if v >= 40:
            return "MEDIUM"
        if v > 0:
            return "LOW"
        return "NOT_AVAILABLE"
    s = str(raw).strip().upper()
    aliases = {
        "ALTA": "HIGH",
        "HIGH": "HIGH",
        "MEDIA": "MEDIUM",
        "MEDIUM": "MEDIUM",
        "MED": "MEDIUM",
        "BAJA": "LOW",
        "LOW": "LOW",
        "INSUFFICIENT_EVIDENCE": "LOW",
        "INSUFFICIENT": "LOW",
    }
    # Spanish display from alerts_canonical
    if s in ("ALTA", "MEDIA", "BAJA"):
        return aliases[s]
    out = aliases.get(s, s)
    return out if out in CONFIDENCE_LEVELS else "NOT_AVAILABLE"


def decide_response_action(
    *,
    severity: Any,
    confidence: Any,
    evidence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Explicit decision tier from severity+confidence.
    Does NOT execute — only recommends an action the existing motors may honor.
    Honest about unimplemented containment.
    """
    sev = normalize_severity_label(severity)
    conf = normalize_confidence_label(confidence)
    ev = evidence if isinstance(evidence, dict) else {}
    action = "MONITOR"
    reason = "default_monitor"
    executable = True
    capability = "alerts_canonical_service / defense_coordinator"

    if sev == "NOT_AVAILABLE" and conf == "NOT_AVAILABLE":
        action, reason = "MONITOR", "insufficient_labels"
    elif sev == "LOW":
        action, reason = "MONITOR", "low_severity"
    elif sev == "MEDIUM":
        action, reason = ("ALERT" if conf in ("MEDIUM", "HIGH") else "INVESTIGATE"), "medium_severity"
    elif sev == "HIGH":
        if conf == "HIGH":
            action, reason = "REMEDIATE", "high_severity_high_confidence"
            capability = "remediation_orchestrator"
        elif conf == "MEDIUM":
            action, reason = "INVESTIGATE", "high_severity_medium_confidence"
        else:
            action, reason = "ALERT", "high_severity_low_confidence"
    elif sev == "CRITICAL":
        if conf == "HIGH":
            # Containment only when evidence already names a real target the swarm can block
            if ev.get("ip") or (isinstance(ev.get("ips"), list) and ev.get("ips")):
                action, reason = "BLOCK", "critical_with_ip_target"
                capability = "swarm_defense.response_policy block_ip (approval)"
            else:
                action, reason = "ESCALATE", "critical_no_auto_contain_without_target"
                capability = "swarm_defense / kernel notify"
        else:
            action, reason = "ESCALATE", "critical_requires_review"
            capability = "swarm_defense create_incident"

    if action == "CONTAIN":
        executable = False  # host isolation not claimed unless wired
        capability = "NOT_IMPLEMENTED"

    return {
        "action": action,
        "severity": sev,
        "confidence": conf,
        "reason": reason,
        "executable": executable and action not in ("CONTAIN",),
        "capability": capability,
        "verification_status": "NOT_VERIFIED",
        "response_status": "PENDING",
    }


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_event(
    *,
    source_engine: str,
    event_type: str,
    payload: Dict[str, Any],
    severity: Optional[str] = None,
    confidence: Optional[str] = None,
    correlation_id: Optional[str] = None,
    event_id: Optional[str] = None,
    **context: Any,
) -> Dict[str, Any]:
    """Normaliza un evento antes de persistirlo. No inventa campos ausentes."""
    eid = event_id or f"EVT-{uuid.uuid4().hex[:12].upper()}"
    cid = correlation_id or eid
    core = {
        "event_id": eid,
        "timestamp_utc": _utc(),
        "source_engine": source_engine or NA,
        "event_type": event_type or NA,
        "severity": severity if severity else NA,
        "confidence": confidence if confidence else NA,
        "correlation_id": cid,
        "payload": payload or {},
        "invented": False,
    }
    for key in OPTIONAL_CONTEXT:
        val = context.get(key)
        if val is not None and val != "" and val != NA:
            core[key] = val
    digest_src = json.dumps(
        {k: core[k] for k in sorted(core) if k != "integrity_hash"},
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    core["integrity_hash"] = hashlib.sha256(digest_src.encode()).hexdigest()
    return core


def normalize_detection(
    *,
    source: str,
    detection_type: str,
    evidence: Optional[Dict[str, Any]] = None,
    severity: Optional[str] = None,
    confidence: Optional[str] = None,
    status: Optional[str] = None,
    tenant_id: Optional[str] = None,
    scope: Optional[str] = None,
    event_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    **context: Any,
) -> Dict[str, Any]:
    """
    Contrato canónico de detección — reutiliza normalize_event.
    No inventa tenant_id ni confidence/severity.
    """
    ev = evidence if isinstance(evidence, dict) else ({"raw": evidence} if evidence is not None else {})
    resolved_scope = (scope or "").strip().upper() or None
    if tenant_id and str(tenant_id).strip():
        if not resolved_scope:
            resolved_scope = SCOPE_TENANT
    elif not resolved_scope:
        resolved_scope = SCOPE_HOST

    if resolved_scope == SCOPE_HOST:
        # Host-scoped: no fabricar atribución tenant
        tenant_out: Any = None
    else:
        tenant_out = str(tenant_id).strip() if tenant_id and str(tenant_id).strip() else None

    sev = normalize_severity_label(severity if severity not in (None, "") else None)
    conf = normalize_confidence_label(confidence if confidence not in (None, "") else None)
    st = (status or "DETECTED").strip().upper()
    if st not in DETECTION_STATUS:
        st = "UNKNOWN"

    base = normalize_event(
        source_engine=source,
        event_type=detection_type,
        payload=ev,
        severity=sev if sev != "NOT_AVAILABLE" else None,
        confidence=conf if conf != "NOT_AVAILABLE" else None,
        correlation_id=correlation_id,
        event_id=event_id,
        **{k: v for k, v in context.items() if v is not None and v != ""},
    )
    base["source"] = source or NA
    base["detection_type"] = detection_type or NA
    base["status"] = st
    base["scope"] = resolved_scope
    base["tenant_id"] = tenant_out
    base["evidence"] = ev
    base["severity"] = sev
    base["confidence"] = conf
    decision = decide_response_action(severity=sev, confidence=conf, evidence=ev)
    base["decision"] = decision
    base["response_status"] = decision.get("response_status") or "PENDING"
    base["verification_status"] = decision.get("verification_status") or "NOT_VERIFIED"
    return base


def detection_fingerprint(detection: Dict[str, Any]) -> str:
    """Huella estable para deduplicación — no fusiona eventos distintos del mismo tipo."""
    parts = [
        str(detection.get("scope") or ""),
        str(detection.get("tenant_id") or ""),
        str(detection.get("source") or detection.get("source_engine") or ""),
        str(detection.get("detection_type") or detection.get("event_type") or ""),
        str(detection.get("ip") or (detection.get("evidence") or {}).get("ip") or ""),
        str(
            (detection.get("evidence") or {}).get("evidence")
            or (detection.get("evidence") or {}).get("message")
            or ""
        )[:160],
    ]
    raw = "|".join(p.lower() for p in parts)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:24]
