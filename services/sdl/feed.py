#!/usr/bin/env python3
"""
Alimentacion de consumidores — SDL expone lecturas; no fuerza escrituras destructivas.
Los motores pueden consultar via get_feed_for(consumer).
"""
from __future__ import annotations
from typing import Any, Dict, Optional

from services.sdl.limitations import NA
from services.sdl.search import search


CONSUMERS = [
    "kernel_ia", "adaptive_profile", "threat_intelligence_enterprise",
    "swarm_mesh", "sope", "imcm", "soc", "viem", "asm", "reportes",
]


def get_feed_for(consumer: str, limit: int = 50) -> Dict[str, Any]:
    """
    Feed tipado por consumidor. Solo registros reales ya ingeridos.
    PARCIAL: push automatico a motores externos no muta sus stores
    (evita efectos colaterales); ellos deben pull via API.
    """
    c = (consumer or "").lower()
    if c not in CONSUMERS and c not in ("tie", "threat_intelligence"):
        return {"ok": False, "consumer": consumer, "message": NA, "records": [], "invented": False}

    mapping = {
        "kernel_ia": {"limit": limit},
        "adaptive_profile": {"record_type": "event", "limit": limit},
        "threat_intelligence_enterprise": {"record_type": "ioc", "limit": limit},
        "tie": {"record_type": "ioc", "limit": limit},
        "threat_intelligence": {"record_type": "ioc", "limit": limit},
        "swarm_mesh": {"engine": "swarm_mesh", "limit": limit},
        "sope": {"engine": "sope", "limit": limit},
        "imcm": {"record_type": "incident", "limit": limit},
        "soc": {"limit": limit},
        "viem": {"engine": "viem", "limit": limit},
        "asm": {"engine": "asm", "limit": limit},
        "reportes": {"record_type": "report", "limit": limit},
    }
    filters = mapping.get(c, {"limit": limit})
    result = search(**filters)
    return {
        "ok": True,
        "consumer": c,
        "mode": "pull",
        "push_automatico": False,
        "note": "Consumidores leen via pull. Push mutante a stores ajenos no implementado a proposito.",
        "total": result.get("total"),
        "records": result.get("records"),
        "invented": False,
    }
