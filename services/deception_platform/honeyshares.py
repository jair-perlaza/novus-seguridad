#!/usr/bin/env python3
"""Honeyshares DPE — framework SMB/NAS/FTP/WebDAV; solo si configurados."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from services.deception_platform.limitations import HONEYSHARE_TYPES, NC, CFG, NI, NAMESPACE
from services.deception_platform.store import load_json, save_json, SHARES_PATH, ensure_dir


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default() -> Dict[str, Any]:
    shares = {}
    for t in HONEYSHARE_TYPES:
        shares[t] = {
            "type": t,
            "status": NC,
            "configured": False,
            "path": None,
            "namespace": NAMESPACE,
            "note": "Sin configuracion. No se publica share real automaticamente.",
            "updated_at_utc": None,
        }
    return {"shares": shares}


def list_honeyshares() -> Dict[str, Any]:
    ensure_dir()
    data = load_json(SHARES_PATH, None) or _default()
    for t in HONEYSHARE_TYPES:
        data.setdefault("shares", {}).setdefault(t, _default()["shares"][t])
    save_json(SHARES_PATH, data)
    configured = [k for k, v in data["shares"].items() if v.get("configured")]
    return {
        "shares": data["shares"],
        "configured": configured,
        "no_configurado": [t for t in HONEYSHARE_TYPES if t not in configured],
        "invented": False,
    }


def configure_honeyshare(stype: str, path: Optional[str] = None) -> Dict[str, Any]:
    stype = (stype or "").lower().strip()
    if stype not in HONEYSHARE_TYPES:
        return {"ok": False, "error": f"tipo no soportado: {stype}", "supported": HONEYSHARE_TYPES}
    data = load_json(SHARES_PATH, None) or _default()
    entry = data["shares"].get(stype, _default()["shares"][stype])
    entry.update({
        "configured": True,
        "status": CFG,
        "path": path or f"dpe://decoy/{stype}/{NAMESPACE}",
        "note": f"{CFG}. Publicacion de share de red: {NI} (sin exponer SMB/NAS reales por defecto).",
        "updated_at_utc": _utc(),
        "namespace": NAMESPACE,
    })
    data["shares"][stype] = entry
    save_json(SHARES_PATH, data)
    return {"ok": True, "share": entry}
