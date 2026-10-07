"""
Guardia SSR/API — solo expone telemetría del nodo autorizado al tenant del usuario.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from services.tenant_scope_service import (
    MONITORING_NOT_CONFIGURED_MSG,
    get_tenant_context,
    resolve_tenant_id,
    tenant_may_read_platform_telemetry,
)


def user_may_read_live_telemetry(user) -> bool:
    if user is None:
        return False
    ctx = get_tenant_context(user)
    return tenant_may_read_platform_telemetry(ctx)


def assert_telemetry_access(user) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    Devuelve (tenant_context, None) si puede leer telemetría del nodo.
    Si no, (ctx, mensaje) — no usar psutil/motores en la ruta.
    """
    ctx = get_tenant_context(user)
    if tenant_may_read_platform_telemetry(ctx):
        return ctx, None
    return ctx, ctx.get("message") or MONITORING_NOT_CONFIGURED_MSG


def tenant_id_for_user(user) -> Optional[str]:
    return resolve_tenant_id(user)


def empty_host_resumen() -> Dict[str, Any]:
    from datetime import datetime

    return {
        "total_eventos": "Sin datos disponibles",
        "conexiones_activas": "Sin datos disponibles",
        "conexiones_meta": {"available": False},
        "procesos_activos": "Sin datos disponibles",
        "cpu_actual": "Sin datos disponibles",
        "memoria_usada": "Sin datos disponibles",
        "memoria_disponible": "Sin datos disponibles",
        "disco_usado": "Sin datos disponibles",
        "disco_libre": "Sin datos disponibles",
        "nivel_critico": 0,
        "nivel_critico_texto": "Sin datos disponibles",
        "estado": "Monitoreo no configurado",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "salud_nodo": "Sin datos disponibles",
        "amenazas_detectadas": "Sin datos disponibles",
    }
