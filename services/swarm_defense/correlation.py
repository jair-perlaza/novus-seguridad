"""
Correlación Swarm — confidence solo por evidencias reales de colaboradores.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


def _dedupe_contributions(contributions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for c in contributions:
        mid = c.get("module_id")
        if mid in seen:
            continue
        seen.add(mid)
        out.append(c)
    return out


def classify_incident(
    event_payload: Dict[str, Any],
    indicators: Dict[str, List[str]],
    contributions: List[Dict[str, Any]],
) -> Dict[str, Any]:
    threat = str(event_payload.get("threat_type") or "").lower()
    action = str(event_payload.get("action") or "").lower()
    motor = str(event_payload.get("motor") or "").lower()
    blob = f"{threat} {action} {motor}"

    category = "anomaly_unclassified"
    if any(k in blob for k in ("ransom", "encrypt")):
        category = "ransomware"
    elif any(k in blob for k in ("phish", "bec", "mail")):
        category = "email_threat"
    elif any(k in blob for k in ("malware", "trojan", "virus")):
        category = "malware"
    elif any(k in blob for k in ("brute", "auth", "login", "credential")):
        category = "auth_abuse"
    elif any(k in blob for k in ("port_scan", "scan", "recon")):
        category = "network_recon"
    elif any(k in blob for k in ("cve", "vuln")):
        category = "vulnerability_exploitation"
    elif indicators.get("ips") or indicators.get("domains"):
        category = "network_indicator"
    elif indicators.get("pids") or indicators.get("processes"):
        category = "endpoint_indicator"

    supporting = [c["module_id"] for c in contributions if c.get("found")]
    return {
        "category": category,
        "origin_motor": event_payload.get("motor"),
        "origin_action": event_payload.get("action"),
        "threat_type": event_payload.get("threat_type"),
        "supporting_modules": supporting,
        "indicator_types_present": [k for k, v in indicators.items() if v],
    }


def compute_confidence(
    contributions: List[Dict[str, Any]],
    indicators: Dict[str, List[str]],
) -> Dict[str, Any]:
    """
    Confianza basada únicamente en:
    - Nº de módulos con found=True
    - Presencia de indicadores estructurados
    Nunca inventa score externo.
    """
    found = [c for c in contributions if c.get("found")]
    total = len(contributions) or 1
    indicator_count = sum(1 for v in indicators.values() if v)
    # Escala discreta verificable
    if len(found) >= 4 and indicator_count >= 1:
        level = "high"
        score = min(95, 50 + len(found) * 8 + indicator_count * 3)
    elif len(found) >= 2:
        level = "medium"
        score = min(75, 35 + len(found) * 8 + indicator_count * 2)
    elif len(found) == 1:
        level = "low"
        score = 20 + indicator_count * 2
    else:
        level = "insufficient_evidence"
        score = 0

    return {
        "level": level,
        "score": score,
        "modules_with_evidence": len(found),
        "modules_consulted": total,
        "indicator_groups": indicator_count,
        "basis": "conteo de colaboradores con hechos reales + indicadores extraídos del evento",
    }


def recommend_actions(
    classification: Dict[str, Any],
    confidence: Dict[str, Any],
    indicators: Dict[str, List[str]],
) -> List[Dict[str, Any]]:
    """Recomendaciones; la política decide auto vs aprobación."""
    recs: List[Dict[str, Any]] = []
    recs.append(
        {
            "action_id": "preserve_evidence",
            "label": "Preservar evidencias / correlato swarm",
            "reason": "Mantener cadena de custodia del evento correlacionado",
        }
    )
    recs.append(
        {
            "action_id": "increase_monitoring",
            "label": "Incrementar monitoreo",
            "reason": "Ampliar vigilancia sobre indicadores presentes",
        }
    )
    if confidence.get("level") in ("medium", "high"):
        recs.append(
            {
                "action_id": "create_incident",
                "label": "Crear/notificar incidente al Kernel",
                "reason": f"Confianza {confidence.get('level')} con {confidence.get('modules_with_evidence')} módulos",
            }
        )
        recs.append(
            {
                "action_id": "generate_report",
                "label": "Generar informe de correlación",
                "reason": "Documentar colaboración del enjambre",
            }
        )
    if indicators.get("ips") and confidence.get("level") in ("medium", "high"):
        recs.append(
            {
                "action_id": "block_ip",
                "label": "Bloquear IP",
                "reason": "IP presente en indicadores con correlación multi-módulo",
                "targets": list(indicators.get("ips") or [])[:5],
            }
        )
    if indicators.get("domains") and confidence.get("level") == "high":
        recs.append(
            {
                "action_id": "block_domain",
                "label": "Bloquear dominio",
                "reason": "Dominio correlacionado con alta confianza",
                "targets": list(indicators.get("domains") or [])[:5],
            }
        )
    if indicators.get("pids") and classification.get("category") in ("malware", "ransomware", "endpoint_indicator"):
        recs.append(
            {
                "action_id": "kill_process",
                "label": "Finalizar proceso",
                "reason": "PID presente en evidencia de endpoint",
                "targets": list(indicators.get("pids") or [])[:5],
            }
        )
    if classification.get("category") == "auth_abuse":
        recs.append(
            {
                "action_id": "revoke_sessions",
                "label": "Revocar sesiones",
                "reason": "Amenaza de abuso de autenticación",
            }
        )
    if confidence.get("level") == "high":
        recs.append(
            {
                "action_id": "isolate_host",
                "label": "Aislar equipo",
                "reason": "Alta correlación multi-módulo",
            }
        )
        recs.append(
            {
                "action_id": "trigger_playbook",
                "label": "Activar playbook",
                "reason": "Respuesta orquestada cuando exista playbook_id autorizado",
            }
        )
    return recs


def correlate(
    event_payload: Dict[str, Any],
    indicators: Dict[str, List[str]],
    contributions: List[Dict[str, Any]],
) -> Dict[str, Any]:
    contributions = _dedupe_contributions(contributions)
    # Tenant isolation: drop contribution facts tagged with a foreign tenant_id
    scope = str(event_payload.get("scope") or "").upper()
    tenant = event_payload.get("tenant_id")
    if scope == "TENANT" and tenant:
        safe = []
        for c in contributions:
            ct = c.get("tenant_id")
            if ct is not None and str(ct) != str(tenant):
                continue
            safe.append(c)
        contributions = safe

    classification = classify_incident(event_payload, indicators, contributions)
    confidence = compute_confidence(contributions, indicators)
    recommendations = recommend_actions(classification, confidence, indicators)

    # Multi-signal summary (L3) — only when ≥2 real modules found OR ≥2 indicator groups
    found_modules = [c.get("module_id") for c in contributions if c.get("found")]
    indicator_groups = [k for k, v in indicators.items() if v]
    multi_signal = {
        "is_multi_signal": len(found_modules) >= 2 or len(indicator_groups) >= 2,
        "supporting_modules": found_modules,
        "indicator_groups": indicator_groups,
        "correlated_incident_candidate": bool(
            len(found_modules) >= 2 and confidence.get("level") in ("medium", "high")
        ),
        "tenant_id": tenant if scope == "TENANT" else None,
        "scope": scope or "HOST",
        "policy": "no_cross_tenant_correlation",
    }

    # Map swarm confidence → decision action vocabulary (reuse contract; no new engine)
    decision = None
    try:
        from services.platform_event_contract import decide_response_action, normalize_severity_label

        sev = normalize_severity_label(
            event_payload.get("severity")
            or (event_payload.get("evidence") or {}).get("severity")
        )
        decision = decide_response_action(
            severity=sev,
            confidence=confidence.get("level"),
            evidence=event_payload.get("evidence") if isinstance(event_payload.get("evidence"), dict) else {},
        )
    except Exception:
        decision = None

    gaps = []
    for c in contributions:
        if not c.get("found"):
            gaps.extend(c.get("gaps") or [])
    return {
        "indicators": indicators,
        "contributions": contributions,
        "classification": classification,
        "confidence": confidence,
        "recommendations": recommendations,
        "gaps": gaps[:30],
        "sufficient_evidence": confidence.get("level") not in ("insufficient_evidence",),
        "policy": "real_evidence_only",
        "multi_signal": multi_signal,
        "decision": decision,
    }
