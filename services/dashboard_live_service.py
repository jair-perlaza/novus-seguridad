"""
Fast path para /api/dashboard/live — nunca bloquea en inventario ni psutil.connections.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from utils.logger import logger


def _metric(value, decimals: int = 1):
    if value is None:
        return "Sin datos disponibles"
    try:
        return round(float(value), decimals)
    except (TypeError, ValueError):
        return "Sin datos disponibles"


def get_dashboard_live_payload(*, tenant_id: Optional[int] = None) -> Dict[str, Any]:
    from services.http_shell_service import schedule_platform_counters_warmup
    from services.novus_security_integration import novus_security
    from services.performance_cache import peek_cached
    from services.system_monitor import system_monitor

    cache_key = "platform_counters:platform"
    counters = peek_cached(cache_key)
    counters_pending = counters is None
    if counters_pending:
        schedule_platform_counters_warmup()
        counters = {}

    status = system_monitor.get_system_status()

    try:
        threats_count = novus_security.get_cached_threat_count()
    except Exception as exc:
        logger.debug("cached threat count: %s", exc)
        threats_count = None

    threat_cache = dict(novus_security._threat_cache or {})
    last_threat_scan = threat_cache.get("last_scan")
    vuln_audit = threat_cache.get("vulnerabilities_audit") or {}
    last_vuln_scan = vuln_audit.get("timestamp")
    vulns_total = counters.get("vulnerabilities_total")
    if vulns_total is None and last_vuln_scan:
        cached_vulns = threat_cache.get("vulnerabilities")
        if cached_vulns is not None:
            vulns_total = len(cached_vulns)

    from utils.data_provenance import analysis_display

    threats_analysis = analysis_display(
        count=threats_count if last_threat_scan else None,
        last_scan=last_threat_scan,
        empty_label="No se detectaron amenazas en el último análisis.",
    )
    vulns_analysis = analysis_display(
        count=vulns_total if last_vuln_scan else None,
        last_scan=last_vuln_scan,
    )

    nodes_total = counters.get("nodes_total")
    nodes_meta = counters.get("nodes_meta") or {}
    # Hot path HTTP: NUNCA resolver snapshot desde disco bajo 600 concurrentes.
    # Solo peek de counters; si faltan, marcar pending (warmup en background).
    if nodes_total is None:
        nodes_meta = {
            **nodes_meta,
            "data_freshness": nodes_meta.get("data_freshness") or "pending",
            "source": nodes_meta.get("source") or "platform_counters_warmup",
        }
        if not counters_pending:
            try:
                schedule_platform_counters_warmup()
            except Exception:
                pass
    if nodes_total == 0 and nodes_meta.get("data_freshness") not in ("live",):
        nodes_total = "Sin datos disponibles"

    conn_count = peek_cached("proc_conn_count")
    if counters_pending and conn_count is None:
        schedule_platform_counters_warmup()

    # Deltas reales entre muestras (background + peeks). No inventar; PENDING hasta 2º tick.
    traffic_sample = system_monitor.sample_traffic_rates()
    traffic_recv = traffic_sample.get("traffic_recv_mb")
    traffic_sent = traffic_sample.get("traffic_sent_mb")
    traffic_meta = {
        "measured": bool(traffic_sample.get("measured")),
        "pending": bool(traffic_sample.get("pending")),
        "data_state": traffic_sample.get("data_state") or "UNKNOWN",
        "display": traffic_sample.get("display"),
        "source": traffic_sample.get("source") or "psutil.net_io_counters",
        "unit": traffic_sample.get("unit") or "MB/s",
        "window_sec": traffic_sample.get("window_sec"),
        "recv_mbps": traffic_sample.get("recv_mbps"),
        "sent_mbps": traffic_sample.get("sent_mbps"),
        "packets_recv_delta": traffic_sample.get("packets_recv_delta"),
        "packets_sent_delta": traffic_sample.get("packets_sent_delta"),
        "interfaces": traffic_sample.get("interfaces") or [],
        "aggregation": traffic_sample.get("aggregation"),
        "cumulative_recv_bytes": traffic_sample.get("cumulative_recv_bytes"),
        "cumulative_sent_bytes": traffic_sample.get("cumulative_sent_bytes"),
        "scope": "HOST_GLOBAL",
        "scope_note": "Host-global traffic; not attributed to a single tenant",
    }

    try:
        from services.runtime_environment_service import get_telemetry_scope_payload_cached

        telemetry_scope = get_telemetry_scope_payload_cached()
    except Exception:
        telemetry_scope = {"scope": "platform_node", "pending": True, "source": "runtime_environment_service"}

    return {
        "status": "success",
        "cpu": _metric(status.get("cpu")),
        "ram": _metric(status.get("ram")),
        "disk": _metric(status.get("disk")),
        "traffic_recv": traffic_recv,
        "traffic_sent": traffic_sent,
        "traffic_meta": traffic_meta,
        "procesos": status.get("procesos_activos") if status.get("procesos_activos") is not None else "Sin datos disponibles",
        "usuarios": status.get("usuarios_conectados") if status.get("usuarios_conectados") is not None else "Sin datos disponibles",
        "conexiones": conn_count if conn_count is not None else "Sin datos disponibles",
        "conexiones_meta": {
            "available": conn_count is not None,
            "pending": conn_count is None,
            "source": "performance_cache.proc_conn_count",
        },
        "amenazas": threats_analysis["display"] if threats_analysis["value"] is None else threats_analysis["value"],
        "amenazas_meta": {
            "analysis_state": threats_analysis["analysis_state"],
            "last_scan": last_threat_scan,
            "source": "novus_security.get_cached_threat_count",
        },
        "nodos_red": nodes_total if nodes_total is not None else "Sin datos disponibles",
        "nodos_red_meta": nodes_meta,
        "endpoints_total": counters.get("endpoints_total"),
        "vulnerabilities_total": (
            vulns_analysis["display"] if vulns_analysis["value"] is None else vulns_analysis["value"]
        ),
        "vulnerabilities_meta": {
            "analysis_state": vulns_analysis["analysis_state"],
            "last_scan": last_vuln_scan,
            "source": "novus_security.scan_vulnerabilities",
        },
        "threats_total": (
            threats_analysis["display"] if threats_analysis["value"] is None else threats_analysis["value"]
        ),
        "threats_meta": {
            "analysis_state": threats_analysis["analysis_state"],
            "last_scan": last_threat_scan,
        },
        "ransomware_active_count": counters.get("ransomware_active_count"),
        "counters_pending": counters_pending,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "telemetry_scope": telemetry_scope,
        "source_type": "dashboard_live_fast",
    }
