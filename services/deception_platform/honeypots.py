#!/usr/bin/env python3
"""Honeypots DPE — framework modular; sin auto-arranque de listeners inseguros."""
from __future__ import annotations
import socket
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from services.deception_platform.limitations import (
    HONEYPOT_PROTOCOLS, NC, CFG, ACT, NI, NA, POLICY, NAMESPACE,
)
from services.deception_platform.store import load_json, save_json, HONEYPOTS_PATH, ensure_dir


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_registry() -> Dict[str, Any]:
    pots = {}
    for proto in HONEYPOT_PROTOCOLS:
        pots[proto] = {
            "protocol": proto,
            "status": NC,
            "configured": False,
            "active": False,
            "bind_host": None,
            "bind_port": None,
            "listener_verified": False,
            "auto_start": False,
            "namespace": NAMESPACE,
            "note": "Sin configuracion. No se inicia listener automaticamente.",
            "updated_at_utc": None,
        }
    return {"honeypots": pots, "policy_auto_start": POLICY["auto_start_listeners"]}


def _load() -> Dict[str, Any]:
    ensure_dir()
    data = load_json(HONEYPOTS_PATH, None)
    if not data or "honeypots" not in data:
        data = _default_registry()
        save_json(HONEYPOTS_PATH, data)
    # ensure all protocols present
    for proto in HONEYPOT_PROTOCOLS:
        data["honeypots"].setdefault(proto, _default_registry()["honeypots"][proto])
    return data


def _port_open(host: str, port: int, timeout: float = 0.35) -> bool:
    if not host or not port:
        return False
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def _resolve_status(entry: Dict[str, Any]) -> str:
    if not entry.get("configured"):
        return NC
    host = entry.get("bind_host")
    port = entry.get("bind_port")
    verified = False
    if entry.get("active") and host and port:
        verified = _port_open(str(host), int(port))
    entry["listener_verified"] = verified
    if verified:
        return ACT
    # Never claim ACTIVO without verified listener
    return CFG


def list_honeypots() -> Dict[str, Any]:
    data = _load()
    out = {}
    for proto, entry in data["honeypots"].items():
        e = dict(entry)
        e["status"] = _resolve_status(e)
        if e["status"] != ACT and e.get("active"):
            e["note"] = (
                "Intent de activacion registrado pero listener NO verificado. "
                f"Estado={e['status']}. {NI} arranque de servicios inseguros por defecto."
            )
        out[proto] = e
    save_json(HONEYPOTS_PATH, {"honeypots": out, "policy_auto_start": False})
    active = [p for p, e in out.items() if e["status"] == ACT]
    configured = [p for p, e in out.items() if e["status"] == CFG]
    unconfigured = [p for p, e in out.items() if e["status"] == NC]
    return {
        "honeypots": out,
        "counts": {
            "activo": len(active),
            "configurado": len(configured),
            "no_configurado": len(unconfigured),
        },
        "active_protocols": active,
        "auto_start": False,
        "invented": False,
    }


def configure_honeypot(protocol: str, bind_host: Optional[str] = "127.0.0.1", bind_port: Optional[int] = None) -> Dict[str, Any]:
    protocol = (protocol or "").lower().strip()
    if protocol not in HONEYPOT_PROTOCOLS:
        return {"ok": False, "error": f"protocolo no soportado: {protocol}", "supported": HONEYPOT_PROTOCOLS}
    data = _load()
    entry = data["honeypots"][protocol]
    entry.update({
        "configured": True,
        "active": False,
        "bind_host": bind_host,
        "bind_port": bind_port,
        "listener_verified": False,
        "status": CFG,
        "auto_start": False,
        "note": "CONFIGURADO. Listener no iniciado (politica: no auto-start servicios inseguros).",
        "updated_at_utc": _utc(),
    })
    data["honeypots"][protocol] = entry
    save_json(HONEYPOTS_PATH, data)
    return {"ok": True, "honeypot": entry, "status": CFG, "listener_started": False}


def activate_honeypot(protocol: str) -> Dict[str, Any]:
    """
    Intento explicito de activacion.
    Por politica NO arranca listeners inseguros; deja CONFIGURADO salvo verificacion real.
    """
    protocol = (protocol or "").lower().strip()
    if protocol not in HONEYPOT_PROTOCOLS:
        return {"ok": False, "error": f"protocolo no soportado: {protocol}"}
    data = _load()
    entry = data["honeypots"][protocol]
    if not entry.get("configured"):
        return {"ok": False, "error": NC, "message": "Debe configurarse antes de activar."}
    # Explicit refusal to start insecure listeners by default
    entry["active"] = True  # intent flag
    entry["listener_started"] = False
    entry["note"] = (
        f"{NI}: arranque de listener {protocol} deshabilitado por politica "
        "(no aumentar superficie de ataque). Estado no sera ACTIVO sin listener verificado."
    )
    entry["updated_at_utc"] = _utc()
    entry["status"] = _resolve_status(entry)
    data["honeypots"][protocol] = entry
    save_json(HONEYPOTS_PATH, data)
    return {
        "ok": True,
        "honeypot": entry,
        "status": entry["status"],
        "listener_started": False,
        "limitation": NI,
    }


def status_summary() -> Dict[str, Any]:
    return list_honeypots()
