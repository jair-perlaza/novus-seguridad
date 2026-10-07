"""
Network routes for NOVUS
Network scanning and device management with integrated security motor
"""
import psutil
from flask import Blueprint, render_template
from flask_login import login_required, current_user
from services.system_monitor import system_monitor
from services.network_scanner import network_scanner
from services.novus_security_integration import novus_security
from services.tenant_scope_service import get_tenant_context, tenant_may_read_platform_telemetry
from utils.logger import logger
from utils.user_helpers import get_current_user_data
from utils.security_helpers import get_compromised_nodes


network_bp = Blueprint('network', __name__)


def _get_network_bandwidth_label():
    """Return real link speed from network interfaces when available."""
    try:
        stats = psutil.net_if_stats()
        speeds = [
            iface_stats.speed
            for iface_stats in stats.values()
            if iface_stats.isup and iface_stats.speed > 0
        ]
        if not speeds:
            return "Sin datos disponibles"
        max_speed = max(speeds)
        if max_speed >= 1000:
            return f"{max_speed / 1000:.1f} Gbps"
        return f"{max_speed} Mbps"
    except Exception as e:
        logger.error(f"Error reading network bandwidth: {e}")
        return "Sin datos disponibles"


@network_bp.route('/network')
@login_required
def network_route():
    """
    Network route with real-time scan data and integrated security motor
    Shows compromised nodes, suspicious connections, risk by endpoint
    """
    try:
        user_data = get_current_user_data()
        tenant_ctx = get_tenant_context(current_user)
        if not tenant_may_read_platform_telemetry(tenant_ctx):
            return render_template(
                'network.html',
                user=user_data,
                nodos=[],
                stats={
                    "total_nodos": 0,
                    "nodos_activos": 0,
                    "ancho_banda": "Sin datos disponibles",
                    "trafico_total": "0 MB",
                },
                compromised_nodes=[],
                suspicious_connections=[],
                dangerous_processes=[],
                risk_by_endpoint={},
                threat_registry=[],
                monitoring_not_configured=True,
                monitoring_message=tenant_ctx.get("message"),
            )

        from services.http_shell_service import (
            get_threat_cache_snapshot,
            schedule_threat_scan_if_stale,
        )

        dispositivos_reales = network_scanner.get_cached_nodes()
        net_stats = system_monitor.get_network_stats()
        threats_data = get_threat_cache_snapshot()
        if not threats_data.get('last_scan'):
            schedule_threat_scan_if_stale()

        suspicious_connections = []
        dangerous_processes = []
        compromised_nodes = get_compromised_nodes(threats_data, dispositivos_reales)

        for proc in threats_data.get('suspicious_processes', []):
            dangerous_processes.append({
                "pid": proc.get('pid'),
                "name": proc.get('name'),
                "description": proc.get('description', proc.get('command_line', 'Proceso detectado')),
                "risk": "DETECTADO",
            })

        for port in threats_data.get('open_ports', []):
            suspicious_connections.append({
                "port": port.get('port'),
                "description": port.get('description', 'Puerto abierto detectado'),
                "status": "DETECTADO",
            })

        engine_threats = threats_data.get('threats', [])
        threat_registry = novus_security.security_engine.threat_registry

        total_findings = len(engine_threats) + len(dangerous_processes)
        risk_by_endpoint = {}

        stats_red = {
            "total_nodos": len(dispositivos_reales),
            "nodos_activos": len(dispositivos_reales),
            "nodos_comprometidos": len(compromised_nodes),
            "conexiones_sospechosas": len(suspicious_connections),
            "procesos_peligrosos": len(dangerous_processes),
            "ancho_banda": _get_network_bandwidth_label(),
            "trafico_total": f"{round((net_stats.get('bytes_sent', 0) + net_stats.get('bytes_recv', 0)) / (1024**2), 2)} MB",
            "conexiones_activas": net_stats.get('connections', 0),
            "bytes_enviados": f"{round(net_stats.get('bytes_sent', 0) / (1024**2), 2)} MB",
            "bytes_recibidos": f"{round(net_stats.get('bytes_recv', 0) / (1024**2), 2)} MB",
            "threat_registry_size": len(threat_registry),
            "hallazgos_seguridad": total_findings if total_findings else "Sin amenazas detectadas",
        }

        logger.info(
            f"Network route: {len(dispositivos_reales)} devices, "
            f"{len(compromised_nodes)} compromised, "
            f"{len(suspicious_connections)} suspicious connections"
        )
        return render_template(
            'network.html',
            user=user_data,
            nodos=dispositivos_reales,
            stats=stats_red,
            compromised_nodes=compromised_nodes,
            suspicious_connections=suspicious_connections,
            dangerous_processes=dangerous_processes,
            risk_by_endpoint=risk_by_endpoint,
            threat_registry=threat_registry
        )

    except Exception as e:
        logger.error(f"Network route error: {e}", exc_info=True)
        return render_template(
            'network.html',
            user=get_current_user_data(),
            nodos=[],
            stats={
                "total_nodos": 0,
                "nodos_activos": 0,
                "ancho_banda": "Sin datos disponibles",
                "trafico_total": "0 MB"
            },
            compromised_nodes=[],
            suspicious_connections=[],
            dangerous_processes=[],
            risk_by_endpoint={},
            threat_registry={}
        )
