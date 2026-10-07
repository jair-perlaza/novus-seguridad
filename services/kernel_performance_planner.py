"""
Planificador de rendimiento del Kernel IA — clasifica solicitudes y define política de ejecución.

Niveles:
  1 — Consulta rápida (<2s): caché, respuesta síncrona
  2 — Análisis rápido (5–15s): motores en paralelo cuando sea seguro
  3 — Análisis profundo (20–45s): Deep Scan / escaneo integral
  4 — Análisis forense: SIEM, resumen diario, investigación prolongada
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from services.kernel_planner import ExecutionPlan, GREETING

# Palabras que fuerzan re-ejecución completa (ignorar caché)
FRESH_REQUEST = re.compile(
    r"\b(de\s+nuevo|otra\s+vez|actualizar|refrescar|forzar|re-?escane|desde\s+cero|"
    r"completo|integral|nuevo\s+an[aá]lisis|volver\s+a\s+escanear)\b",
    re.I,
)

# Consultas rápidas — solo lectura de caché / métricas ligeras
QUICK_QUERY_PATTERNS: List[Tuple[re.Pattern, str, List[str]]] = [
    (re.compile(r"\b(cpu|ram|memoria|disco|rendimiento\s+del\s+sistema)\b", re.I), "system_metrics", ["system.metrics"]),
    (re.compile(r"estado\s+del\s+sistema|c[oó]mo\s+est[aá]\s+el\s+sistema|salud\s+del\s+sistema", re.I), "system_status", ["system.metrics"]),
    (re.compile(r"estado\s+del\s+firewall|firewall|puertos\s+abiertos\s+ahora", re.I), "firewall_status", ["firewall.ports"]),
    (re.compile(r"conexiones\s+activas|conexiones\s+ahora|qu[eé]\s+conexiones", re.I), "connections", ["connections.active"]),
    (re.compile(r"estado\s+de\s+la\s+red|estado\s+red|c[oó]mo\s+est[aá]\s+la\s+red", re.I), "network_status", ["network.scanner", "connections.active"]),
]

SCAN_VERBS = re.compile(
    r"\b(escanea|escanear|escaneo|busca|buscar|analiza|analizar|inspecciona|deep\s*scan)\b",
    re.I,
)

FORENSIC_PATTERNS = re.compile(
    r"\b(forense|forensic|investigaci[oó]n|auditor[ií]a\s+completa|"
    r"resumen\s+de\s+hoy|qu[eé]\s+pas[oó]\s+hoy|eventos\s+de\s+hoy|"
    r"actividad\s+de\s+hoy|informe\s+del\s+d[ií]a|siem|cadena\s+de\s+custodia)\b",
    re.I,
)

# Servicios con lock interno — capacidades del mismo servicio no van en paralelo
CAP_SERVICE = {
    "network.scanner": "network_scanner",
    "network.radar": "network_scanner",
    "network.events": "network_event_log",
    "topology.view": "network_scanner",
    "security.threats": "novus_security",
    "security.vulnerabilities": "novus_security",
    "security.system_health": "novus_security",
    "system.metrics": "system_monitor",
    "process.scanner": "system_monitor",
    "dashboard.metrics": "system_monitor",
    "traffic.stats": "system_monitor",
    "endpoints.live": "system_monitor",
    "advanced_detector.ports": "advanced_detector",
    "advanced_detector.processes": "advanced_detector",
    "advanced_detector.malware": "advanced_detector",
    "firewall.ports": "advanced_detector",
    "connections.active": "psutil",
    "gmail.analyzer": "gmail",
    "deep_scan.engine": "deep_scan",
    "siem.logs": "database",
    "incidents.manager": "database",
    "reports.manager": "reports",
    "playbooks.manager": "playbooks",
    "vulnerability.scanner": "vulnerability_scanner",
    "security.sector_shield": "security_engine",
    "security.vault": "crypto_vault",
    "remediation.engine": "remediation",
}


@dataclass
class PerformanceProfile:
    level: int
    label: str
    target_min_sec: float
    target_max_sec: float
    eta_message: str
    force_refresh: bool
    cache_ttl_sec: int
    sync_fast_path: bool = False
    parallel_groups: List[List[str]] = field(default_factory=list)
    quick_capabilities: List[str] = field(default_factory=list)


LEVEL_META = {
    1: ("Consulta rápida", 0.5, 2.0, "Consulta instantánea — reutilizando datos recientes"),
    2: ("Análisis rápido", 5.0, 15.0, "Análisis en curso — estimado 5–15 segundos"),
    3: ("Análisis profundo", 20.0, 45.0, "Deep Scan en curso — estimado 20–45 segundos"),
    4: ("Análisis forense", 45.0, 180.0, "Análisis forense — puede tardar varios minutos"),
}


def user_requested_fresh_scan(message: str) -> bool:
    return bool(FRESH_REQUEST.search(message or ""))


def classify_performance_level(plan: ExecutionPlan, message: str) -> PerformanceProfile:
    """Determina nivel de rendimiento y política de ejecución."""
    msg = (message or "").strip()
    fresh = user_requested_fresh_scan(msg)

    if plan.skip_engines or GREETING.match(msg):
        meta = LEVEL_META[1]
        return PerformanceProfile(
            level=1,
            label=meta[0],
            target_min_sec=meta[1],
            target_max_sec=meta[2],
            eta_message=meta[3],
            force_refresh=False,
            cache_ttl_sec=120,
            sync_fast_path=True,
        )

    # Nivel 3 — Deep Scan / escaneo integral (solo perfil full)
    if plan.workflow_profile == "full" or plan.intent_id in ("deep_scan", "full_computer_analysis"):
        meta = LEVEL_META[3]
        caps = _unique_caps(plan.capabilities)
        return PerformanceProfile(
            level=3,
            label=meta[0],
            target_min_sec=meta[1],
            target_max_sec=meta[2],
            eta_message=meta[3] if not fresh else "Escaneo completo forzado — estimado 20–45 segundos",
            force_refresh=True,
            cache_ttl_sec=0,
            parallel_groups=partition_parallel(caps) if caps else [],
        )

    # Nivel 4 — Forense / SIEM / resumen diario
    if FORENSIC_PATTERNS.search(msg) or plan.intent_id in ("daily_summary", "enterprise_security"):
        meta = LEVEL_META[4]
        caps = _unique_caps(plan.capabilities)
        return PerformanceProfile(
            level=4,
            label=meta[0],
            target_min_sec=meta[1],
            target_max_sec=meta[2],
            eta_message=meta[3],
            force_refresh=fresh or plan.intent_id == "daily_summary",
            cache_ttl_sec=0 if fresh else 60,
            parallel_groups=partition_parallel(caps),
        )

    # Nivel 1 — consultas puntuales de estado (sin escaneo activo)
    if not fresh and plan.request_type == "query":
        for pattern, _qid, caps in QUICK_QUERY_PATTERNS:
            if pattern.search(msg) and not SCAN_VERBS.search(msg):
                meta = LEVEL_META[1]
                return PerformanceProfile(
                    level=1,
                    label=meta[0],
                    target_min_sec=meta[1],
                    target_max_sec=meta[2],
                    eta_message=meta[3],
                    force_refresh=False,
                    cache_ttl_sec=60,
                    sync_fast_path=True,
                    quick_capabilities=caps,
                )

    # Nivel 2 — análisis operativo estándar
    meta = LEVEL_META[2]
    caps = _unique_caps(plan.capabilities)
    return PerformanceProfile(
        level=2,
        label=meta[0],
        target_min_sec=meta[1],
        target_max_sec=meta[2],
        eta_message=meta[3] if not fresh else "Re-análisis completo — estimado 5–15 segundos",
        force_refresh=fresh,
        cache_ttl_sec=30 if not fresh else 0,
        parallel_groups=partition_parallel(caps),
    )


def partition_parallel(capability_ids: List[str]) -> List[List[str]]:
    """
    Agrupa capacidades: mismo servicio → secuencial; servicios distintos → paralelo.
    """
    caps = _unique_caps(capability_ids)
    if not caps:
        return []

    groups: Dict[str, List[str]] = {}
    for cap in caps:
        svc = CAP_SERVICE.get(cap, cap.split(".")[0])
        groups.setdefault(svc, []).append(cap)

    return list(groups.values())


def _unique_caps(caps: List[str]) -> List[str]:
    seen = set()
    out = []
    for c in caps or []:
        if c and c not in seen and c != "deep_scan.engine":
            seen.add(c)
            out.append(c)
    return out


def apply_performance_to_plan(plan: ExecutionPlan, profile: PerformanceProfile) -> None:
    """Adjunta metadatos de rendimiento al plan de ejecución."""
    plan.performance_level = profile.level
    plan.performance_label = profile.label
    plan.target_seconds_min = profile.target_min_sec
    plan.target_seconds_max = profile.target_max_sec
    plan.eta_message = profile.eta_message
    plan.force_refresh_policy = profile.force_refresh
    plan.cache_ttl_sec = profile.cache_ttl_sec
    plan.sync_fast_path = profile.sync_fast_path
    plan.parallel_groups = profile.parallel_groups
    if profile.quick_capabilities:
        plan.quick_capabilities = profile.quick_capabilities
