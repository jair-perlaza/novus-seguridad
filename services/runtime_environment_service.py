"""
Huella del entorno de ejecución NOVUS — evita reutilizar caché de otra red o sesión de host.

Al cambiar nodo, gateway o segmento de red se invalidan cachés en memoria para forzar
telemetría fresca del entorno actual.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
from datetime import datetime
from typing import Any, Dict, Optional

import psutil

from core.config import Config
from utils.logger import logger

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FINGERPRINT_PATH = os.path.join(_PROJECT_ROOT, "data", "runtime_environment_fingerprint.json")


def _now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def compute_runtime_fingerprint() -> Dict[str, Any]:
    from services.tenant_scope_service import get_platform_tenant_id
    from utils.host_data import get_local_ip
    from utils.network_helpers import get_default_gateway, get_network_range

    gateway = get_default_gateway()
    cidr = get_network_range(gateway)
    local_ip = get_local_ip()
    return {
        "node_id": Config.NODE_ID or socket.gethostname(),
        "hostname": socket.gethostname(),
        "local_ip": local_ip or "",
        "gateway": gateway or "",
        "network_range": cidr or "",
        "boot_time": psutil.boot_time(),
        "platform_tenant_id": get_platform_tenant_id(),
    }


def fingerprint_hash(payload: Dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def _load_stored() -> Optional[Dict[str, Any]]:
    if not os.path.isfile(_FINGERPRINT_PATH):
        return None
    try:
        with open(_FINGERPRINT_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        logger.warning("runtime_environment: no se pudo leer huella: %s", exc)
        return None


def _save_stored(payload: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(_FINGERPRINT_PATH), exist_ok=True)
    with open(_FINGERPRINT_PATH, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def _invalidate_runtime_caches(reason: str) -> None:
    from services.performance_cache import invalidate
    from services.network_scanner import network_scanner
    from services.novus_security_integration import novus_security

    invalidate()
    network_scanner.clear_cache()
    try:
        novus_security.reset_runtime_telemetry_cache(reason=reason)
    except Exception as exc:
        logger.debug("reset_runtime_telemetry_cache: %s", exc)

    global _scope_cache
    _scope_cache = None
    logger.warning("Entorno de ejecución cambió — cachés invalidados (%s)", reason)


_scope_cache: Optional[Dict[str, Any]] = None


def get_telemetry_scope_payload() -> Dict[str, Any]:
    """Metadatos de alcance para APIs (origen + actualización)."""
    global _scope_cache
    if _scope_cache is not None:
        return dict(_scope_cache)

    fp = compute_runtime_fingerprint()
    stored = _load_stored() or {}
    payload = {
        "scope": "platform_node",
        "definition": (
            "Telemetría del host donde corre NOVUS y de la red local autorizada "
            "(ARP/gateway detectados en este arranque)."
        ),
        "node_id": fp["node_id"],
        "hostname": fp["hostname"],
        "local_ip": fp["local_ip"] or "Sin datos disponibles",
        "gateway": fp["gateway"] or "Sin datos disponibles",
        "network_range": fp["network_range"] or "Sin datos disponibles",
        "environment_hash": fingerprint_hash(fp),
        "platform_tenant_id": fp.get("platform_tenant_id"),
        "boot_time": fp.get("boot_time"),
        "fingerprint_updated_at": stored.get("updated_at") or _now_iso(),
        "source": "runtime_environment_service",
    }
    _scope_cache = payload
    return dict(payload)


def get_telemetry_scope_payload_cached() -> Dict[str, Any]:
    """Solo devuelve alcance ya precalentado — nunca computa huella en request HTTP."""
    global _scope_cache
    if _scope_cache is not None:
        return dict(_scope_cache)
    stored = _load_stored() or {}
    if stored:
        return {
            "scope": "platform_node",
            "environment_hash": stored.get("environment_hash"),
            "fingerprint_updated_at": stored.get("updated_at") or _now_iso(),
            "source": "runtime_environment_service",
            "pending": False,
        }
    return {
        "scope": "platform_node",
        "pending": True,
        "source": "runtime_environment_service",
        "message": "Huella de entorno en refresh background",
    }


def reconcile_runtime_environment_on_startup() -> Dict[str, Any]:
    """
    Compara huella actual con la persistida; invalida caché si el entorno cambió.
    """
    fp = compute_runtime_fingerprint()
    new_hash = fingerprint_hash(fp)
    stored = _load_stored()
    result = {
        "environment_hash": new_hash,
        "changed": False,
        "invalidated": False,
        "previous_hash": (stored or {}).get("hash"),
    }

    if stored and stored.get("hash") and stored.get("hash") != new_hash:
        result["changed"] = True
        _invalidate_runtime_caches("network_or_node_changed")
        result["invalidated"] = True

    record = {
        "hash": new_hash,
        "fingerprint": fp,
        "updated_at": _now_iso(),
    }
    _save_stored(record)
    get_telemetry_scope_payload()
    result["saved_at"] = record["updated_at"]
    return result
