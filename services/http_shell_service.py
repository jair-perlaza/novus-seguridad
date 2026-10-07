"""
Helpers para respuestas HTTP inmediatas — nunca disparan escaneos pesados en el hilo de request.

Los motores siguen ejecutándose en background (start_background_threat_scanner, post-login, etc.).
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional

from utils.logger import logger

_counters_warm_inflight = False
_counters_warm_last_at = 0.0
_COUNTERS_WARM_MIN_INTERVAL_SEC = 120.0

STATUS_LOADING = "LOADING"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_NOT_AVAILABLE = "NOT_AVAILABLE"


def get_threat_cache_snapshot() -> Dict[str, Any]:
    """Solo lectura del caché del motor — sin detect_threats_realtime."""
    from services.novus_security_integration import novus_security

    return dict(novus_security._threat_cache or {})


def get_cached_vulnerabilities_snapshot() -> List[Dict[str, Any]]:
    from services.novus_security_integration import novus_security

    try:
        return list(novus_security.get_cached_vulnerabilities())
    except Exception as exc:
        logger.debug("vuln snapshot: %s", exc)
        return []


def schedule_threat_scan_if_stale(*, force: bool = False) -> None:
    """Encola escaneo de amenazas en background si no hay caché reciente."""
    from services.novus_security_integration import novus_security

    try:
        from services.resource_backpressure_service import CAT_HEAVY_AGG, should_run_background

        if not should_run_background(CAT_HEAVY_AGG):
            return
    except Exception:
        pass

    cache = novus_security._threat_cache or {}
    if cache.get("last_scan") and not force:
        return
    if getattr(novus_security, "_threat_scanning", False):
        return

    def _worker():
        try:
            novus_security.detect_threats_realtime(force=force)
        except Exception as exc:
            logger.debug("background threat scan: %s", exc)

    threading.Thread(
        target=_worker,
        daemon=True,
        name="HttpShellThreatScan",
    ).start()


_vuln_scan_lock = threading.Lock()
_vuln_scan_inflight = False


def schedule_vulnerability_scan_if_stale(*, force: bool = False) -> None:
    global _vuln_scan_inflight
    from services.novus_security_integration import novus_security

    try:
        from services.resource_backpressure_service import CAT_HEAVY_AGG, should_run_background

        if not should_run_background(CAT_HEAVY_AGG):
            return
    except Exception:
        pass

    cache = novus_security._threat_cache or {}
    if cache.get("vulnerabilities") is not None and not force:
        return

    with _vuln_scan_lock:
        if _vuln_scan_inflight and not force:
            return
        _vuln_scan_inflight = True

    def _worker():
        global _vuln_scan_inflight
        try:
            novus_security.scan_vulnerabilities(force=force)
        except Exception as exc:
            logger.debug("background vuln scan: %s", exc)
        finally:
            with _vuln_scan_lock:
                _vuln_scan_inflight = False

    threading.Thread(
        target=_worker,
        daemon=True,
        name="HttpShellVulnScan",
    ).start()


def counters_warm_pending() -> bool:
    """True si hay warmup en curso o reciente (HTTP puede devolver pending/stale)."""
    if _counters_warm_inflight:
        return True
    return (time.time() - _counters_warm_last_at) < _COUNTERS_WARM_MIN_INTERVAL_SEC


def schedule_platform_counters_warmup() -> None:
    """Precalienta contadores pesados sin bloquear HTTP — single-flight + intervalo mínimo."""
    global _counters_warm_inflight, _counters_warm_last_at
    if _counters_warm_inflight:
        return
    if (time.time() - _counters_warm_last_at) < _COUNTERS_WARM_MIN_INTERVAL_SEC:
        return
    try:
        from services.resource_backpressure_service import CAT_HEAVY_AGG, should_run_background

        if not should_run_background(CAT_HEAVY_AGG):
            return
    except Exception:
        pass
    _counters_warm_inflight = True
    _counters_warm_last_at = time.time()

    def _worker():
        global _counters_warm_inflight
        try:
            from services.platform_metrics_service import get_platform_counters

            get_platform_counters()
        except Exception as exc:
            logger.debug("platform counters warmup: %s", exc)
        finally:
            _counters_warm_inflight = False

    threading.Thread(
        target=_worker,
        daemon=True,
        name="HttpShellCountersWarm",
    ).start()


def dashboard_shell_metrics(*, monitoring_ok: bool = True) -> Dict[str, Any]:
    """
    Contexto mínimo para render HTML del dashboard — sin psutil pesado ni scans.
    Métricas numéricas se cargan vía /api/dashboard/live y /api/security/summary.
    """
    loading = STATUS_LOADING if monitoring_ok else "Sin datos disponibles"
    return {
        "cpu_load": loading,
        "ram_load": loading,
        "disk_load": loading,
        "nodos_activos": loading,
        "endpoints_total": loading,
        "status_ia": loading,
        "ram_total": loading,
        "ram_usada": loading,
        "ram_disponible": loading,
        "disk_total": loading,
        "disk_usado": loading,
        "disk_free": loading,
        "network_bytes_sent": loading,
        "network_bytes_recv": loading,
        "procesos_activos": loading,
        "usuarios_conectados": loading,
        "uptime_horas": loading,
        "uptime_dias": loading,
        "cpu_cores": loading,
        "frecuencia_cpu": loading,
        "timestamp_actual": loading,
        "threats_count": loading,
        "vulnerabilities_count": loading,
        "endpoint_status": loading,
        "open_port_count": loading,
        "suspicious_process_count": loading,
        "shell_mode": True,
        "data_status": "progressive_loading",
    }


def network_shell_stats() -> Dict[str, Any]:
    return {
        "total_nodos": STATUS_LOADING,
        "nodos_activos": STATUS_LOADING,
        "nodos_comprometidos": STATUS_LOADING,
        "conexiones_sospechosas": STATUS_LOADING,
        "procesos_peligrosos": STATUS_LOADING,
        "ancho_banda": STATUS_LOADING,
        "trafico_total": STATUS_LOADING,
        "conexiones_activas": STATUS_LOADING,
        "hallazgos_seguridad": STATUS_LOADING,
    }
