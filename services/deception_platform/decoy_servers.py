#!/usr/bin/env python3
"""Decoy servers DPE — framework; todos deshabilitados por defecto."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict

from services.deception_platform.limitations import DECOY_SERVER_TYPES, NC, CFG, ACT, NI, NAMESPACE
from services.deception_platform.store import load_json, save_json, DECOYS_PATH, ensure_dir


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default() -> Dict[str, Any]:
    servers = {}
    for t in DECOY_SERVER_TYPES:
        servers[t] = {
            "type": t,
            "status": NC,
            "enabled": False,
            "configured": False,
            "namespace": NAMESPACE,
            "note": "Deshabilitado por defecto. No se inicia servidor senuelo automaticamente.",
            "updated_at_utc": None,
        }
    return {"servers": servers}


def list_decoy_servers() -> Dict[str, Any]:
    ensure_dir()
    data = load_json(DECOYS_PATH, None) or _default()
    for t in DECOY_SERVER_TYPES:
        data.setdefault("servers", {}).setdefault(t, _default()["servers"][t])
    # Never claim ACTIVO without real process — we never start them here
    for t, e in data["servers"].items():
        if e.get("enabled") and not e.get("process_verified"):
            e["status"] = CFG
            e["note"] = f"Habilitacion logica registrada; proceso no verificado. {NI} listener por defecto."
        elif not e.get("configured"):
            e["status"] = NC
            e["enabled"] = False
    save_json(DECOYS_PATH, data)
    enabled = [k for k, v in data["servers"].items() if v.get("status") == ACT]
    return {
        "servers": data["servers"],
        "activo": enabled,
        "all_disabled_by_default": True,
        "invented": False,
    }


def configure_decoy_server(stype: str) -> Dict[str, Any]:
    stype = (stype or "").lower().strip()
    if stype not in DECOY_SERVER_TYPES:
        return {"ok": False, "error": f"tipo no soportado: {stype}", "supported": DECOY_SERVER_TYPES}
    data = load_json(DECOYS_PATH, None) or _default()
    entry = data["servers"].get(stype, _default()["servers"][stype])
    entry.update({
        "configured": True,
        "enabled": False,
        "status": CFG,
        "process_verified": False,
        "note": f"{CFG}. Arranque deshabilitado por defecto.",
        "updated_at_utc": _utc(),
        "namespace": NAMESPACE,
    })
    data["servers"][stype] = entry
    save_json(DECOYS_PATH, data)
    return {"ok": True, "server": entry}
