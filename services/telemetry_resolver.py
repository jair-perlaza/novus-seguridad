"""
Resolución de telemetría NOVUS — valores reales o explicación verificable de ausencia.
Nunca inventa datos ni oculta la falta de información.
"""
from __future__ import annotations

from typing import Any, Optional, Union

# Valores que indican ausencia de telemetría (no datos reales)
_ABSENT = frozenset({
    "", "n/d", "n/a", "null", "none", "unknown", "no_data",
    "sin datos disponibles", "sin datos", "cargando...", "—", "-",
    "no data", "placeholder", "simulated", "static", "default",
})

REASONS = {
    "endpoints_inventory_empty": (
        "No hay endpoints registrados en el inventario NOVUS. "
        "El inventario se alimenta del escáner de red en background y del módulo Endpoints."
    ),
    "network_scan_pending": (
        "El escáner de red aún no ha completado un ciclo ARP. "
        "Los nodos aparecerán tras el primer escaneo (normalmente en los primeros 30–60 segundos tras el arranque)."
    ),
    "threat_scan_pending": (
        "No se ha completado un escaneo de amenazas reciente. "
        "El threat scanner en background actualiza los indicadores automáticamente."
    ),
    "vuln_scan_pending": (
        "No se detectaron vulnerabilidades activas en el último escaneo. "
        "Esto puede indicar un entorno limpio o que el escaneo aún no finalizó."
    ),
    "no_critical_findings": (
        "No se detectó actividad crítica en el último ciclo de motores NOVUS. "
        "El monitoreo continúa en background."
    ),
    "no_incidents": (
        "No existen incidentes documentados en la base de datos para este componente."
    ),
    "no_playbook_runs": (
        "No se han ejecutado playbooks registrados en el historial reciente."
    ),
    "sector_confidence_pending": (
        "ASPE aún no ha calculado el nivel de confianza sectorial. "
        "Se actualiza tras la detección UCE y la evaluación de incidentes."
    ),
    "adaptive_defense_idle": (
        "Adaptive Defense no ha registrado contenciones recientes. "
        "Estado normal cuando no hay amenazas que requieran respuesta adaptativa."
    ),
    "cryptovault_status_unknown": (
        "No se pudo leer el estado de CryptoVault. Verifique que el motor de seguridad esté inicializado."
    ),
    "metrics_unavailable": (
        "No existen datos suficientes para evaluar este elemento en este momento. "
        "El monitor de sistema no pudo recopilar métricas."
    ),
    "bandwidth_unmeasured": (
        "El ancho de banda por dispositivo no está disponible sin captura de tráfico activa. "
        "NOVUS reporta contadores agregados de red del sistema operativo."
    ),
    "generic": (
        "No existen datos suficientes para evaluar este elemento en este momento."
    ),
}


def is_absent(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, (int, float)):
        return False
    text = str(value).strip().lower()
    return not text or text in _ABSENT or text.startswith("sin datos")


def explain(reason_key: str = "generic") -> str:
    return REASONS.get(reason_key, REASONS["generic"])


def resolve(
    value: Any,
    reason_key: str = "generic",
    *,
    allow_zero: bool = False,
) -> Union[str, int, float]:
    """Devuelve el valor real o una explicación verificable."""
    if isinstance(value, (int, float)):
        if value == 0 and not allow_zero:
            return explain(reason_key)
        return value
    if not is_absent(value):
        return value
    return explain(reason_key)


def count(value: Any, reason_key: str = "generic") -> Union[int, str]:
    if isinstance(value, int) and value >= 0:
        if value == 0:
            return f"0 — {explain(reason_key)}"
        return value
    if isinstance(value, float) and value >= 0:
        iv = int(value)
        if iv == 0:
            return f"0 — {explain(reason_key)}"
        return iv
    return explain(reason_key)


def text(value: Any, reason_key: str = "generic") -> str:
    return str(resolve(value, reason_key))


def endpoints_monitored(count_val: Optional[int]) -> Union[int, str]:
    return count(count_val, "endpoints_inventory_empty")


def network_nodes(count_val: Optional[int]) -> Union[int, str]:
    return count(count_val, "network_scan_pending")
