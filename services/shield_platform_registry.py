"""Registro modular de escudos NOVUS — arquitectura extensible."""
from __future__ import annotations

from typing import Any, Dict, List

SHIELD_MODULES: List[Dict[str, Any]] = [
    {
        "id": "novus_core",
        "name": "NOVUS CORE",
        "status": "active",
        "description": "Motor central, métricas canónicas y tenant scope.",
    },
    {
        "id": "web_shield",
        "name": "NOVUS WEB SHIELD",
        "status": "active",
        "engine": "services.web_shield_engine",
        "api_prefix": "/api/web-shield",
    },
    {
        "id": "mail_shield",
        "name": "NOVUS MAIL SHIELD",
        "status": "active",
        "engine": "services.mail_shield_engine",
        "api_prefix": "/api/mail-shield",
        "providers": ["google_workspace", "microsoft365"],
    },
    {
        "id": "network_shield",
        "name": "NETWORK SHIELD",
        "status": "active",
        "engine": "services.network_monitor_engine",
        "api_prefix": "/api/network",
    },
    {
        "id": "endpoint_shield",
        "name": "ENDPOINT SHIELD",
        "status": "active",
        "engine": "services.endpoint_scan_engine",
        "monitor": "services.endpoint_realtime_monitor",
        "deep_scan": "services.deep_scan_engine",
        "api_prefix": "/api/endpoint-scan",
    },
    {
        "id": "mobile_shield",
        "name": "NOVUS MOBILE SHIELD",
        "status": "planned",
        "description": "Arquitectura reservada — agente móvil futuro.",
    },
    {
        "id": "cloud_shield",
        "name": "NOVUS CLOUD SHIELD",
        "status": "planned",
        "description": "Arquitectura reservada — CSPM/API cloud futuras.",
    },
]


def list_shields() -> List[Dict[str, Any]]:
    return list(SHIELD_MODULES)
