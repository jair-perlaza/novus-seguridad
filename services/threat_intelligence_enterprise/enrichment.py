#!/usr/bin/env python3
"""
Enriquecimiento de indicadores para decisiones del Kernel IA.
Calcula un confidence_score explicable correlacionando múltiples fuentes.
El Kernel NO toma decisiones solo por una fuente.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.threat_intelligence_enterprise.connectors import enrich_indicator, FEED_CONNECTORS
from services.threat_intelligence_enterprise.store import (
    load_iocs,
    load_internal_intel,
    store_enrichment,
    NA,
)
from utils.logger import logger


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def enrich_for_kernel(
    indicator: str,
    indicator_type: str = "hash",
    btde_context: Optional[Dict[str, Any]] = None,
    swarm_context: Optional[Dict[str, Any]] = None,
    network_context: Optional[Dict[str, Any]] = None,
    endpoint_context: Optional[Dict[str, Any]] = None,
    forensic_context: Optional[Dict[str, Any]] = None,
    adaptive_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Enriquece un indicador correlacionando:
    - Threat Intelligence externa
    - Inteligencia interna NOVUS
    - BTDE, Swarm, Red, Endpoint, Forense, Adaptive Profile
    Devuelve un confidence_score explicable.
    """
    factors: List[Dict[str, Any]] = []
    score_parts: List[float] = []

    # 1. External TI
    ext = enrich_indicator(indicator, indicator_type)
    for src_name, src_data in ext.get("sources", {}).items():
        if src_data.get("status") == "ok":
            mal = src_data.get("malicious", 0) or 0
            total = mal + (src_data.get("harmless", 0) or 0) + (src_data.get("undetected", 0) or 0)
            factor_score = min(1.0, mal / max(1, total)) if total > 0 else 0
            factors.append({
                "source": src_name,
                "type": "external_ti",
                "score": factor_score,
                "detail": f"malicious={mal}, total_engines={total}",
            })
            score_parts.append(factor_score)
        else:
            factors.append({
                "source": src_name,
                "type": "external_ti",
                "score": None,
                "detail": src_data.get("reason") or NA,
            })

    # 2. Local IOC matches
    local_iocs = [i for i in load_iocs(limit=1000) if i.get("value") == indicator]
    if local_iocs:
        avg_conf = sum(float(i.get("confidence") or 0) for i in local_iocs) / len(local_iocs)
        factors.append({
            "source": "novus_ioc_store",
            "type": "internal_ti",
            "score": avg_conf,
            "detail": f"{len(local_iocs)} local matches, avg_confidence={avg_conf:.2f}",
        })
        score_parts.append(avg_conf)

    # 3. Internal detections
    internal = [
        i for i in load_internal_intel(limit=500)
        if i.get("ioc_value") == indicator
    ]
    if internal:
        freq = len(internal)
        sev_scores = {"CRITICO": 1.0, "ALTO": 0.75, "MEDIO": 0.5, "BAJO": 0.25}
        max_sev = max(
            (sev_scores.get(i.get("severity", "MEDIO"), 0.5) for i in internal),
            default=0.5,
        )
        int_score = min(1.0, (freq / 5.0) * max_sev)
        factors.append({
            "source": "novus_internal_detections",
            "type": "internal_ti",
            "score": int_score,
            "detail": f"frequency={freq}, max_severity={max_sev}",
        })
        score_parts.append(int_score)

    # 4. Contextual factors from other engines
    ctx_sources = {
        "btde": btde_context,
        "swarm": swarm_context,
        "network": network_context,
        "endpoint": endpoint_context,
        "forensic": forensic_context,
        "adaptive_profile": adaptive_context,
    }
    for name, ctx in ctx_sources.items():
        if not ctx:
            continue
        ctx_score = float(ctx.get("risk_score") or ctx.get("score") or ctx.get("confidence") or 0)
        if ctx_score > 0:
            factors.append({
                "source": name,
                "type": "engine_context",
                "score": min(1.0, ctx_score),
                "detail": str(ctx)[:200],
            })
            score_parts.append(min(1.0, ctx_score))

    # Composite confidence score
    if score_parts:
        confidence_score = round(sum(score_parts) / len(score_parts), 4)
    else:
        confidence_score = 0.0

    result = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "confidence_score": confidence_score,
        "factors": factors,
        "factors_count": len(factors),
        "sources_consulted": len(factors),
        "recommendation": _recommendation(confidence_score),
        "kernel_decision_note": "Este score es UN FACTOR. Kernel IA debe correlacionar con BTDE, Swarm, Red, Endpoint, Forense, Adaptive Profile.",
        "enriched_at_utc": _utc(),
        "invented": False,
    }
    store_enrichment(result)
    return result


def _recommendation(score: float) -> str:
    if score >= 0.8:
        return "ALTO RIESGO — Bloquear/investigar inmediatamente."
    if score >= 0.5:
        return "RIESGO MEDIO — Investigar con prioridad."
    if score >= 0.2:
        return "RIESGO BAJO — Monitorear."
    return "SIN EVIDENCIA SUFICIENTE — No actuar solo por TI."
