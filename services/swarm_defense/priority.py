"""Priorización automática de amenazas Swarm — factores reales, no inventados."""
from __future__ import annotations

from typing import Any, Dict, List, Optional


_CRIT_MAP = {
    "ransomware": 95,
    "malware": 85,
    "auth_abuse": 80,
    "email_threat": 75,
    "vulnerability_exploitation": 70,
    "endpoint_indicator": 65,
    "network_recon": 55,
    "network_indicator": 50,
    "anomaly_unclassified": 40,
}

_CONF_MAP = {
    "high": 30,
    "medium": 18,
    "low": 8,
    "insufficient_evidence": 0,
}


def compute_priority(
    *,
    classification: Dict[str, Any],
    confidence: Dict[str, Any],
    indicators: Dict[str, List[str]],
    origin_event: Optional[Dict[str, Any]] = None,
    memory_hit: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Prioridad 0–100 a partir de:
    criticidad categoría, confianza, activos/indicadores, reincidencia (memoria),
    usuarios afectados (si el evento los trae), tipo de ataque.
    """
    origin_event = origin_event or {}
    category = classification.get("category") or "anomaly_unclassified"
    base = int(_CRIT_MAP.get(category, 40))
    conf_boost = int(_CONF_MAP.get((confidence or {}).get("level"), 0))

    indicator_boost = min(15, sum(2 for v in (indicators or {}).values() if v))
    modules = int((confidence or {}).get("modules_with_evidence") or 0)
    module_boost = min(12, modules * 2)

    # Activos / usuarios si vienen en el evento (no inventar)
    users = origin_event.get("affected_users") or origin_event.get("user_email")
    user_boost = 5 if users else 0
    assets = origin_event.get("affected_assets") or (indicators or {}).get("ips") or (indicators or {}).get("hosts")
    asset_boost = 5 if assets else 0

    recidivism = 0
    if memory_hit and memory_hit.get("seen_before"):
        recidivism = min(15, 5 + int(memory_hit.get("frequency") or 1) * 2)

    raw = base + conf_boost + indicator_boost + module_boost + user_boost + asset_boost + recidivism
    score = max(0, min(100, raw))
    if score >= 85:
        level = "critical"
    elif score >= 70:
        level = "high"
    elif score >= 50:
        level = "medium"
    elif score >= 25:
        level = "low"
    else:
        level = "info"

    return {
        "score": score,
        "level": level,
        "factors": {
            "category_criticality": base,
            "confidence_boost": conf_boost,
            "indicator_boost": indicator_boost,
            "module_boost": module_boost,
            "user_boost": user_boost,
            "asset_boost": asset_boost,
            "recidivism_boost": recidivism,
            "category": category,
            "confidence_level": (confidence or {}).get("level"),
        },
        "basis": "factores medibles del evento/correlación/memoria — sin scores inventados",
    }
