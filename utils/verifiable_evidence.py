"""
Validación central de evidencia verificable NOVUS.

Un dato solo es publicable si cumple simultáneamente:
  - Origen identificado (motor/módulo NOVUS)
  - Marca temporal
  - Evidencia verificable (verified=True o evidencia estructurada trazable)
  - Sin IPs de documentación RFC 5737 ni fuentes lab/test/demo
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from utils.ip_validation import is_documentation_ip, text_contains_documentation_ip
from services.auth_anomaly_evidence_service import auth_details_pass_gate

LAB_SOURCES = frozenset({
    "test_harness", "test", "lab", "demo", "simulated", "placeholder", "mock", "fake", "dummy",
})
AGGREGATE_IPS = frozenset({"auth", "segment", "unknown", "n/d", "red local"})


def _motor(payload: dict) -> str:
    return str(
        payload.get("motor")
        or payload.get("source")
        or payload.get("fuente")
        or payload.get("source_channel")
        or ""
    ).strip().lower()


def _timestamp(payload: dict) -> str:
    return str(
        payload.get("timestamp")
        or payload.get("time")
        or payload.get("fecha")
        or ""
    ).strip()


def _evidence_text(payload: dict) -> str:
    parts = [
        payload.get("evidence_summary"),
        payload.get("evidence"),
        payload.get("descripcion"),
        payload.get("description"),
    ]
    details = payload.get("details") or payload.get("technical_detail")
    if isinstance(details, dict):
        parts.extend([
            details.get("evidence"),
            details.get("message"),
            details.get("summary"),
        ])
    for item in payload.get("evidence_items") or []:
        if isinstance(item, dict):
            parts.append(item.get("value"))
    return " ".join(str(p) for p in parts if p)


def _origin_ip(payload: dict) -> Optional[str]:
    ip = payload.get("origin_ip") or payload.get("ip") or payload.get("ip_afectada")
    if not ip and isinstance(payload.get("details"), dict):
        ip = payload["details"].get("ip")
    return str(ip).strip() if ip else None


def passes_evidence_gate(payload: dict) -> Tuple[bool, str]:
    """
    Retorna (True, '') si el payload es publicable; (False, motivo) si no.
    """
    if not isinstance(payload, dict):
        return False, "payload inválido"

    motor = _motor(payload)
    if not motor or motor in LAB_SOURCES:
        return False, "sin motor/origen NOVUS identificado"

    if any(lab in motor for lab in LAB_SOURCES):
        return False, "fuente lab/test/demo"

    ts = _timestamp(payload)
    if not ts:
        return False, "sin marca temporal"

    ev_text = _evidence_text(payload)
    if text_contains_documentation_ip(ev_text):
        return False, "evidencia contiene IP RFC 5737"

    ip = _origin_ip(payload)
    if ip and is_documentation_ip(ip):
        return False, "IP de documentación RFC 5737"

    verified = payload.get("verified")
    details = payload.get("details")
    if isinstance(details, dict):
        if details.get("verified") is True:
            verified = True
        if not ev_text:
            ev_text = str(details.get("evidence") or details.get("message") or "")

    has_items = bool(payload.get("evidence_items"))
    has_summary = bool(payload.get("evidence_summary")) and payload.get("evidence_summary") != "Sin evidencia estructurada disponible."

    if verified is not True and not has_items and not has_summary and len(ev_text.strip()) < 12:
        return False, "sin evidencia verificable"

    if verified is False:
        return False, "marcado como no verificado"

    tech = payload.get("technical_detail")
    detail_blob = tech if isinstance(tech, dict) else {}
    if not detail_blob and isinstance(payload.get("details"), dict):
        detail_blob = payload.get("details")
    if isinstance(detail_blob, dict):
        threat_label = str(payload.get("threat_type") or "").lower()
        if "brute" in threat_label and payload.get("origin_ip") and not detail_blob.get("ip"):
            detail_blob = {
                **detail_blob,
                "ip": payload.get("origin_ip"),
                "source": detail_blob.get("source") or "audit_logs",
                "verified": payload.get("verified"),
                "event_type": "brute_force",
            }
        src = str(detail_blob.get("source") or _motor(payload)).lower()
        event_type = str(detail_blob.get("event_type") or "").lower()
        is_auth_ip_threat = (
            detail_blob.get("ip")
            and (
                "brute" in threat_label
                or event_type == "brute_force"
                or src in ("audit_logs", "auth_access_audit")
            )
        )
        is_auth_aggregate = event_type in ("password_spraying", "credential_stuffing") or src in (
            "audit_logs",
            "auth_access_audit",
        )
        if is_auth_ip_threat or is_auth_aggregate:
            ok_auth, reason_auth = auth_details_pass_gate(detail_blob)
            if not ok_auth:
                return False, reason_auth

    # IP como amenaza: exigir contexto de detección en la evidencia
    if ip and ip.lower() not in AGGREGATE_IPS and not is_documentation_ip(ip):
        if verified is not True and not has_items:
            return False, "IP sin evidencia de clasificación"

    return True, ""


def passes_runtime_threat_gate(threat: dict) -> Tuple[bool, str]:
    """Valida entrada del motor runtime antes de registrar o exponer."""
    if not isinstance(threat, dict):
        return False, "threat inválido"

    details = threat.get("details") or {}
    if not isinstance(details, dict):
        return False, "details inválidos"

    if details.get("verified") is not True:
        return False, "threat sin verified=True"

    ip = details.get("ip")
    if is_documentation_ip(ip) or text_contains_documentation_ip(str(details.get("evidence", ""))):
        return False, "IP/evidencia RFC 5737"

    source = str(threat.get("source") or details.get("source") or "").lower()
    if source in LAB_SOURCES:
        return False, "fuente lab"

    if not (details.get("evidence") or details.get("message")):
        return False, "sin texto de evidencia"

    if not threat.get("type"):
        return False, "sin tipo de amenaza"

    ok_auth, reason = auth_details_pass_gate(details)
    ttype = str(threat.get("type") or details.get("event_type") or "").lower()
    if ttype in ("brute_force", "password_spraying", "credential_stuffing") or details.get("ip"):
        if not ok_auth:
            return False, reason

    return True, ""


def passes_defense_event_gate(evidence: Optional[dict]) -> Tuple[bool, str]:
    """Valida evidencia antes de persistir en defense_registry / evidence center."""
    if not evidence:
        return True, ""
    if not isinstance(evidence, dict):
        return False, "evidencia no estructurada"
    ip = evidence.get("ip")
    if is_documentation_ip(ip):
        return False, "IP RFC 5737 en evento de defensa"
    blob = str(evidence)
    if text_contains_documentation_ip(blob):
        return False, "texto con IP RFC 5737"
    return True, ""
