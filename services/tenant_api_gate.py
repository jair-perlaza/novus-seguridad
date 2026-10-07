"""
Respuestas canónicas cuando un tenant no tiene monitoreo configurado.
Evita filtrar datos de otro cliente en la interfaz — la API no expone telemetría ajena.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from flask import jsonify

from services.tenant_scope_service import (
    MONITORING_NOT_CONFIGURED_MSG,
    get_tenant_context,
    tenant_may_read_platform_telemetry,
)


def build_monitoring_not_configured_payload(
    ctx: Dict[str, Any],
    scope: str = "network",
) -> Dict[str, Any]:
    base = {
        "status": "monitoring_not_configured",
        "scope": scope,
        "tenant_id": ctx.get("tenant_id"),
        "monitoring_enabled": False,
        "message": ctx.get("message") or MONITORING_NOT_CONFIGURED_MSG,
        "timestamp": datetime.now().isoformat(),
    }
    if scope == "network":
        base.update({
            "nodes": [],
            "count": 0,
            "local_ip": "Sin datos disponibles",
            "gateway": "Sin datos disponibles",
            "netmask": "Sin datos disponibles",
            "network_range": "Sin datos disponibles",
            "hostname": "Sin datos disponibles",
            "node_count": 0,
            "events": [],
        })
    elif scope == "dashboard":
        base.update({
            "cpu": "Sin datos disponibles",
            "ram": "Sin datos disponibles",
            "disk": "Sin datos disponibles",
            "traffic_recv": "Sin datos disponibles",
            "traffic_sent": "Sin datos disponibles",
            "procesos": "Sin datos disponibles",
            "usuarios": "Sin datos disponibles",
            "conexiones": "Sin datos disponibles",
            "amenazas": "Sin datos disponibles",
            "nodos_red": "Sin datos disponibles",
            "endpoints_total": None,
            "vulnerabilities_total": None,
            "threats_total": None,
            "ransomware_active_count": None,
        })
    elif scope == "security":
        base.update({
            "system_health": {},
            "threats": {},
            "total_threats": None,
            "vulnerabilities": [],
            "endpoints": {},
            "counters": {},
            "endpoint_inventory": [],
            "ransomware_active": [],
            "has_active_ransomware": False,
            "alerts_active": 0,
            "alerts": [],
        })
    elif scope == "topology":
        base.update({
            "nodes": [],
            "connections": [],
            "categories": {},
            "meta": {},
            "alerts": [],
        })
    elif scope == "ndr":
        base.update({
            "nodes": [],
            "alerts": [],
            "meta": {},
            "device_count": 0,
            "pending_count": 0,
            "alert_count": 0,
            "executive_summary": {},
        })
    return base


def check_tenant_monitoring_or_response(user, scope: str = "network"):
    """
    Devuelve (ctx, None) si el tenant puede leer telemetría.
    Devuelve (ctx, flask_response) si debe bloquearse con payload vacío.
    """
    ctx = get_tenant_context(user)
    if tenant_may_read_platform_telemetry(ctx):
        return ctx, None
    payload = build_monitoring_not_configured_payload(ctx, scope=scope)
    return ctx, jsonify(payload)
