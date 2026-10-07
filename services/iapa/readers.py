#!/usr/bin/env python3
"""Lectores de solo lectura — no mutan motores."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from services.iapa.limitations import NA


def _safe(label: str, fn) -> Dict[str, Any]:
    try:
        data = fn()
        if data is None:
            return {"source": label, "available": False, "status": NA}
        return {"source": label, "available": True, "status": "ok", "data": data}
    except Exception as exc:
        return {"source": label, "available": False, "status": NA, "error": str(exc)[:160]}


def sdl_search(**kwargs) -> Dict[str, Any]:
    try:
        from services.sdl import search
        return search(**kwargs)
    except Exception as exc:
        return {"ok": False, "records": [], "total": 0, "message": NA, "error": str(exc)[:160], "invented": False}


def peek_sources() -> Dict[str, Dict[str, Any]]:
    out = {}
    out["asm"] = _safe("asm", lambda: __import__("services.asm", fromlist=["stats"]).stats())
    out["viem"] = _safe("viem", lambda: __import__("services.viem", fromlist=["stats"]).stats())
    out["imcm"] = _safe("imcm", lambda: __import__("services.imcm", fromlist=["stats"]).stats())
    out["tie"] = _safe("tie", lambda: __import__("services.threat_intelligence_enterprise", fromlist=["stats"]).stats())
    out["sope"] = _safe("sope", lambda: __import__("services.sope", fromlist=["stats"]).stats())
    out["sdl"] = _safe("sdl", lambda: __import__("services.sdl", fromlist=["stats"]).stats())
    out["sdace"] = _safe("sdace", lambda: __import__("services.sdace", fromlist=["analytics_summary"]).analytics_summary())
    out["ueba"] = _safe("ueba", lambda: {
        "identity_count": len(__import__("services.identity_intelligence", fromlist=["list_identities"]).list_identities()),
    })
    out["health"] = _safe("health", lambda: __import__("services.health_engine", fromlist=["get_health_status"]).get_health_status())
    out["cryptovault"] = _safe("cryptovault", lambda: __import__("crypto_vault", fromlist=["CryptoVault"]).CryptoVault().verify_health())
    try:
        from services.swarm_defense import swarm_defense_engine
        out["swarm_defense"] = _safe("swarm_defense", swarm_defense_engine.status)
    except Exception:
        out["swarm_defense"] = {"source": "swarm_defense", "available": False, "status": NA}
    try:
        from services.swarm_defense.mesh import mesh_status
        out["swarm_mesh"] = _safe("swarm_mesh", mesh_status)
    except Exception:
        out["swarm_mesh"] = {"source": "swarm_mesh", "available": False, "status": NA}
    try:
        from services.zero_day_detection.engine import get_zdde_status
        out["zdde"] = _safe("zdde", get_zdde_status)
    except Exception:
        out["zdde"] = {"source": "zdde", "available": False, "status": NA}
    return out


def val(r: Dict, *keys) -> Optional[str]:
    for k in keys:
        v = r.get(k) if isinstance(r, dict) else None
        if v is not None and str(v).strip() and str(v) != NA:
            return str(v)
    return None
