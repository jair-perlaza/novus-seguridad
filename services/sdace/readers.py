#!/usr/bin/env python3
"""Lectores de solo lectura — SDL y motores. Sin mutaciones."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from services.sdace.limitations import NA


def sdl_search(**kwargs) -> Dict[str, Any]:
    try:
        from services.sdl import search
        return search(**kwargs)
    except Exception as exc:
        return {"ok": False, "total": 0, "count": 0, "records": [], "message": NA, "error": str(exc)[:200], "invented": False}


def sdl_stats() -> Dict[str, Any]:
    try:
        from services.sdl import stats
        return stats()
    except Exception:
        return {"status": NA, "invented": False}


def _safe(label: str, fn) -> Dict[str, Any]:
    try:
        data = fn()
        if data is None:
            return {"source": label, "available": False, "status": NA}
        return {"source": label, "available": True, "status": "ok", "data": data}
    except Exception as exc:
        return {"source": label, "available": False, "status": NA, "error": str(exc)[:160]}


def peek_engines() -> Dict[str, Dict[str, Any]]:
    """Estado/snapshot de lectura; no modifica motores."""
    out = {}
    out["asm"] = _safe("asm", lambda: __import__("services.asm", fromlist=["stats"]).stats())
    out["viem"] = _safe("viem", lambda: __import__("services.viem", fromlist=["stats"]).stats())
    out["tie"] = _safe("tie", lambda: __import__("services.threat_intelligence_enterprise", fromlist=["stats"]).stats())
    out["imcm"] = _safe("imcm", lambda: __import__("services.imcm", fromlist=["stats"]).stats())
    out["sope"] = _safe("sope", lambda: __import__("services.sope", fromlist=["stats"]).stats())
    out["health"] = _safe("health", lambda: __import__("services.health_engine", fromlist=["get_health_status"]).get_health_status())
    out["cryptovault"] = _safe("cryptovault", lambda: __import__("crypto_vault", fromlist=["CryptoVault"]).CryptoVault().verify_health())
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


def parse_ts(ts: Optional[str]):
    from datetime import datetime, timezone
    if not ts or ts == NA:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts[:19].replace("Z", ""), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            try:
                return datetime.strptime(ts[:19], fmt.replace("Z", "")).replace(tzinfo=timezone.utc)
            except Exception:
                continue
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None
