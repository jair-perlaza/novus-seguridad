"""
Métricas canónicas de NOVUS — una sola fuente para Dashboard, Endpoints, XDR, etc.
Ningún módulo debe calcular contadores por su cuenta.
"""
from __future__ import annotations

import platform
import socket
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import psutil

from utils.host_data import format_ip_or_unavailable, get_local_ip
from utils.logger import logger
from utils.security_helpers import count_node_findings


def _local_mac() -> str:
    try:
        return ":".join(
            f"{(uuid.getnode() >> elements) & 0xff:02x}"
            for elements in range(0, 8 * 6, 8)
        )[::-1]
    except Exception:
        return "Sin datos disponibles"


def _hallazgos_from_threat_cache(cache: dict) -> Optional[int]:
    if not cache.get("last_scan"):
        return None
    from services.novus_security_integration import NovusSecurityIntegration
    return NovusSecurityIntegration._count_verified_threats(
        cache.get("threats") or [],
        [],
    )


def build_endpoint_inventory(tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Inventario unificado: host local + dispositivos ARP (sin duplicar IP local).
    Usado por Dashboard, Endpoints, Security Summary y APIs.
    """
    from services.tenant_scope_service import get_platform_tenant_id

    platform_tid = get_platform_tenant_id()
    if tenant_id and platform_tid and tenant_id != platform_tid:
        return []

    from services.network_scanner import network_scanner
    from services.novus_security_integration import novus_security
    from utils.endpoint_status import arp_node_status, local_host_status

    cache = dict(novus_security._threat_cache or {})
    hallazgos_local = _hallazgos_from_threat_cache(cache)

    local_ip = format_ip_or_unavailable(get_local_ip())
    nombre_equipo = socket.gethostname()
    sistema_op = platform.system()

    try:
        cpu_actual = psutil.cpu_percent(interval=0)
        ram_pct = psutil.virtual_memory().percent
    except Exception:
        cpu_actual = None
        ram_pct = None

    items: List[Dict[str, Any]] = [{
        "nombre": nombre_equipo,
        "name": nombre_equipo,
        "ip": local_ip,
        "mac": _local_mac(),
        "tipo": sistema_op,
        "type": sistema_op,
        "hallazgos": hallazgos_local if hallazgos_local is not None else "Sin datos disponibles",
        "findings": hallazgos_local,
        "estado": local_host_status(),
        "status": local_host_status(),
        "icono": "fa-desktop",
        "source": "local_host",
        "cpu": f"{cpu_actual:.1f}%" if cpu_actual is not None else "Sin datos disponibles",
        "ram": f"{ram_pct:.1f}%" if ram_pct is not None else "Sin datos disponibles",
    }]

    for node in network_scanner.get_cached_nodes():
        node_ip = node.get("ip")
        if node_ip and node_ip == local_ip:
            continue
        findings = count_node_findings(node)
        items.append({
            "nombre": node.get("name") or "Dispositivo de red",
            "name": node.get("name") or "Dispositivo de red",
            "ip": node_ip or "Sin datos disponibles",
            "mac": node.get("mac") or "Sin datos disponibles",
            "tipo": node.get("type") or "dispositivo",
            "type": node.get("type") or "dispositivo",
            "hallazgos": findings,
            "findings": findings if isinstance(findings, int) else None,
            "estado": node.get("status") or arp_node_status(node.get("response_time_ms")),
            "status": node.get("status") or arp_node_status(node.get("response_time_ms")),
            "icono": "fa-network-wired",
            "source": "network_scanner",
        })

    return items


def get_active_ransomware_findings(threat_cache: Optional[dict] = None) -> List[Dict[str, Any]]:
    """
    Ransomware solo si hay evidencia activa en el caché del motor (escaneo actual).
    No usa threat_registry histórico ni reportes antiguos.
    """
    from services.novus_security_integration import novus_security

    cache = dict(threat_cache or novus_security._threat_cache or {})
    if not cache.get("last_scan"):
        return []

    findings: List[Dict[str, Any]] = []
    scan_ts = cache.get("last_scan")

    for threat in cache.get("threats") or []:
        ttype = str(threat.get("type") or "").lower()
        details = threat.get("details") or {}
        if not details.get("verified"):
            continue
        label = str(details.get("threat") or details.get("incident") or "").lower()
        if "ransomware" not in ttype and "ransomware" not in label and "ransom" not in label:
            continue
        findings.append({
            "id": f"THR-RANSOM-{len(findings) + 1}",
            "engine": details.get("source") or "security_engine",
            "detected_at": details.get("timestamp") or scan_ts,
            "process": details.get("process") or details.get("process_name"),
            "file": details.get("file") or details.get("path"),
            "status": details.get("status") or threat.get("severity") or "DETECTADO",
            "evidence": details,
            "motor": "Threat Engine / security_engine",
        })

    for proc in cache.get("suspicious_processes") or []:
        desc = " ".join(
            str(proc.get(k) or "")
            for k in ("description", "command_line", "path", "name")
        ).lower()
        if "ransom" not in desc and "cryptolocker" not in desc:
            continue
        findings.append({
            "id": f"PROC-RANSOM-{proc.get('pid')}",
            "engine": "advanced_detector",
            "detected_at": scan_ts,
            "process": proc.get("name"),
            "file": proc.get("path"),
            "status": "DETECTADO",
            "evidence": {
                "pid": proc.get("pid"),
                "command_line": proc.get("command_line"),
                "description": proc.get("description"),
            },
            "motor": "advanced_detector.scan_running_processes",
        })

    return findings


def _count_processes_with_connections() -> Optional[int]:
    """Conteo de PIDs con conexiones — omitir bajo presión RAM extrema."""
    from services.performance_cache import get_or_compute, peek_cached
    from core.config import Config

    try:
        import psutil

        if psutil.virtual_memory().percent >= 90:
            cached = peek_cached("proc_conn_count")
            if cached is not None:
                return cached
            return None
    except Exception:
        pass

    def _compute() -> Optional[int]:
        try:
            conns = psutil.net_connections(kind="inet")
            pids = {c.pid for c in conns if getattr(c, "pid", None)}
            return len(pids)
        except Exception:
            try:
                count = 0
                for proc in psutil.process_iter(["pid"]):
                    try:
                        if proc.connections():
                            count += 1
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                return count
            except Exception:
                return None

    return get_or_compute("proc_conn_count", Config.PROCESS_CONN_CACHE_TTL, _compute)


def get_platform_counters(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """Contadores canónicos derivados de los mismos motores para todos los módulos."""
    from services.performance_cache import get_or_compute
    from core.config import Config

    cache_key = f"platform_counters:{tenant_id or 'default'}"
    return get_or_compute(
        cache_key,
        Config.COUNTERS_CACHE_TTL,
        lambda: _get_platform_counters_uncached(tenant_id=tenant_id),
    )


def _get_platform_counters_uncached(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    from services.tenant_scope_service import get_platform_tenant_id
    from services.performance_cache import peek_cached

    platform_tid = get_platform_tenant_id()
    if tenant_id and platform_tid and tenant_id != platform_tid:
        return {
            "endpoints_total": None,
            "nodes_total": None,
            "threats_total": None,
            "vulnerabilities_total": None,
            "processes_with_connections": None,
            "ransomware_active_count": None,
            "last_threat_scan": None,
            "sources": {"tenant_isolated": True},
        }

    from services.network_scanner import network_scanner
    from services.novus_security_integration import novus_security

    cache = dict(novus_security._threat_cache or {})
    inventory = build_endpoint_inventory(tenant_id=tenant_id)
    nodes = network_scanner.get_cached_nodes()
    vulnerabilities = cache.get("vulnerabilities")
    if vulnerabilities is None:
        try:
            summary = novus_security.get_cached_security_summary()
            vulnerabilities = summary.get("vulnerabilities") or []
        except Exception:
            vulnerabilities = []

    threats_total = cache.get("total_threats")
    if threats_total is None and cache.get("last_scan"):
        threats_total = novus_security._count_verified_threats(
            cache.get("threats"),
            cache.get("suspicious_processes"),
        )

    vuln_audit = cache.get("vulnerabilities_audit") or {}
    last_vuln_scan = vuln_audit.get("timestamp")
    if not last_vuln_scan:
        vulnerabilities_total = None
    elif vulnerabilities is None:
        vulnerabilities_total = None
    else:
        vulnerabilities_total = len(vulnerabilities)

    try:
        from services.network_snapshot_service import resolve_network_device_counts

        net_counts = resolve_network_device_counts()
        nodes_observed = net_counts.get("observed_device_count")
        nodes_historical = net_counts.get("historical_device_count")
        nodes_freshness = net_counts.get("data_freshness")
    except Exception:
        nodes_observed = len(nodes) if nodes else None
        nodes_historical = len(nodes) if nodes else 0
        nodes_freshness = "not_verifiable"
        if nodes_observed == 0:
            nodes_observed = None

    try:
        processes_with_connections = peek_cached("proc_conn_count")
        if processes_with_connections is None:
            from services.http_shell_service import schedule_platform_counters_warmup

            schedule_platform_counters_warmup()
    except Exception:
        processes_with_connections = None

    return {
        "endpoints_total": len(inventory),
        "nodes_total": nodes_observed,
        "nodes_meta": {
            "observed_device_count": nodes_observed,
            "historical_device_count": nodes_historical,
            "data_freshness": nodes_freshness,
            "source": "network_snapshot_service.resolve_network_device_counts",
            "source_engine": "network_scan_coordinator",
        },
        "threats_total": threats_total,
        "vulnerabilities_total": vulnerabilities_total,
        "last_vuln_scan": last_vuln_scan,
        "processes_with_connections": processes_with_connections,
        "ransomware_active_count": len(get_active_ransomware_findings(cache)),
        "last_threat_scan": cache.get("last_scan"),
        "sources": {
            "endpoints_total": "platform_metrics.build_endpoint_inventory",
            "nodes_total": "network_snapshot_service.resolve_network_device_counts",
            "threats_total": "novus_security._threat_cache",
            "vulnerabilities_total": "novus_security._threat_cache.vulnerabilities",
            "processes_with_connections": "psutil.process_iter.connections",
        },
    }


def get_fast_security_payload(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """Datos rápidos desde caché — sin inventario profundo ni agregación pesada."""
    from services.novus_security_integration import novus_security
    from services.network_scanner import network_scanner

    summary = novus_security.get_cached_security_summary()
    cache = dict(summary.get("threats") or novus_security._threat_cache or {})
    nodes = network_scanner.get_cached_nodes() or []
    vulns = summary.get("vulnerabilities") if summary.get("vulnerabilities") is not None else cache.get("vulnerabilities")
    last_scan = cache.get("last_scan") or summary.get("last_scan")
    vuln_audit = cache.get("vulnerabilities_audit") or {}
    last_vuln_scan = vuln_audit.get("timestamp")
    threats_total = cache.get("total_threats")
    if threats_total is None and last_scan:
        threats_total = novus_security._count_verified_threats(
            cache.get("threats"),
            cache.get("suspicious_processes"),
        )

    try:
        from services.network_snapshot_service import resolve_network_device_counts

        net_counts = resolve_network_device_counts()
        nodes_kpi = net_counts.get("observed_device_count")
    except Exception:
        nodes_kpi = len(nodes) if nodes else None

    return {
        "status": "degraded",
        "system_health": summary.get("system_health", {}),
        "threats": cache,
        "total_threats": threats_total,
        "vulnerabilities": vulns if isinstance(vulns, list) else [],
        "analysis_available": bool(last_scan),
        "vuln_analysis_available": bool(last_vuln_scan),
        "last_scan": last_scan,
        "last_vuln_scan": last_vuln_scan,
        "endpoints": summary.get("endpoints", {}),
        "counters": {
            "nodes_total": nodes_kpi,
            "nodes_meta": {
                "observed_device_count": nodes_kpi,
                "source": "network_snapshot_service.resolve_network_device_counts",
            },
            "threats_total": threats_total,
            "vulnerabilities_total": (
                len(vulns) if isinstance(vulns, list) and last_vuln_scan else None
            ),
            "endpoints_total": summary.get("endpoints", {}).get("total"),
            "sources": {"mode": "fast_cache"},
        },
        "endpoint_inventory": [],
        "ransomware_active": get_active_ransomware_findings(cache),
        "has_active_ransomware": len(get_active_ransomware_findings(cache)) > 0,
        "alerts_active": None,
        "alerts": [],
        "component_status": {
            "endpoint_inventory": "pending",
            "alerts": "pending",
            "network_discovery": "ready" if nodes else "pending",
        },
        "source": "services.platform_metrics_service.get_fast_security_payload",
        "source_type": "fast_cache",
        "confidence": "partial",
    }


def get_unified_security_payload(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """Payload completo para Security Summary — fuente única de verdad."""
    from services.tenant_scope_service import get_platform_tenant_id

    platform_tid = get_platform_tenant_id()
    if tenant_id and platform_tid and tenant_id != platform_tid:
        return {
            "system_health": {},
            "threats": {},
            "total_threats": None,
            "vulnerabilities": [],
            "endpoints": {},
            "counters": get_platform_counters(tenant_id=tenant_id),
            "endpoint_inventory": [],
            "ransomware_active": [],
            "has_active_ransomware": False,
            "alerts_active": _safe_active_alerts_count(tenant_id=tenant_id),
            "alerts": _safe_canonical_alerts(limit=50, tenant_id=tenant_id),
        }

    from services.novus_security_integration import novus_security

    summary = novus_security.get_cached_security_summary()
    cache = dict(summary.get("threats") or novus_security._threat_cache or {})
    counters = get_platform_counters(tenant_id=tenant_id)
    inventory = build_endpoint_inventory(tenant_id=tenant_id)
    ransomware = get_active_ransomware_findings(cache)

    return {
        "system_health": summary.get("system_health", {}),
        "threats": cache,
        "total_threats": counters.get("threats_total"),
        "vulnerabilities": summary.get("vulnerabilities") or cache.get("vulnerabilities") or [],
        "endpoints": summary.get("endpoints", {}),
        "counters": counters,
        "endpoint_inventory": inventory,
        "ransomware_active": ransomware,
        "has_active_ransomware": len(ransomware) > 0,
        "alerts_active": _safe_active_alerts_count(tenant_id=tenant_id),
        "alerts": _safe_canonical_alerts(limit=50, tenant_id=tenant_id),
    }


def _safe_active_alerts_count(tenant_id: Optional[str] = None) -> Optional[int]:
    try:
        from services.alerts_canonical_service import get_active_alerts_count
        return get_active_alerts_count(tenant_id=tenant_id)
    except Exception as exc:
        logger.debug("alerts count: %s", exc)
        return None


def _safe_canonical_alerts(limit: int = 50, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    try:
        from services.alerts_canonical_service import get_canonical_alerts
        return get_canonical_alerts(include_resolved=False, limit=limit, tenant_id=tenant_id)
    except Exception as exc:
        logger.debug("canonical alerts payload: %s", exc)
        return []
