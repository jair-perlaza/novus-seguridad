"""Helpers for deriving real security metrics from runtime scans."""
import socket

from utils.host_data import get_local_ip, format_ip_or_unavailable


def count_node_findings(node):
    """Return real open-port count for a discovered network node."""
    if not node:
        return "Sin datos disponibles"
    open_ports = node.get("open_ports")
    if open_ports is None:
        return "Sin datos disponibles"
    return len(open_ports)


def get_compromised_nodes(threat_cache, network_nodes):
    """
    Mark nodes as compromised only when a confirmed threat references their IP.
    """
    if not network_nodes:
        return []

    threat_ips = set()
    local_ip = get_local_ip()

    for threat in (threat_cache or {}).get("threats", []):
        details = threat.get("details") or {}
        for key in ("target_ip", "ip", "source_ip"):
            ip = details.get(key)
            if ip:
                threat_ips.add(ip)

    for proc in (threat_cache or {}).get("suspicious_processes", []):
        if proc.get("pid"):
            if local_ip:
                threat_ips.add(local_ip)

    compromised = []
    for node in network_nodes:
        ip = node.get("ip")
        if ip and ip in threat_ips:
            compromised.append({
                "ip": ip,
                "mac": node.get("mac") or "Sin datos disponibles",
                "name": node.get("name") or "Sin datos disponibles",
                "status": "COMPROMETIDO",
                "reason": "Amenaza confirmada asociada a este host",
            })
    return compromised


def compute_risk_summary(cpu, ram, disk, threat_count, vuln_count):
    """Derive report/dashboard risk labels from live metrics only."""
    threat_count = threat_count if isinstance(threat_count, int) else 0
    vuln_count = vuln_count if isinstance(vuln_count, int) else 0

    if threat_count > 0 or vuln_count > 5:
        nivel_riesgo = "ALTO"
    elif vuln_count > 0 or cpu > 90 or ram > 90:
        nivel_riesgo = "MEDIO"
    else:
        nivel_riesgo = "BAJO"

    if cpu > 95 or ram > 95 or disk > 95:
        salud_sistema = "CRÍTICO"
    elif cpu > 85 or ram > 85:
        salud_sistema = "DEGRADADO"
    else:
        salud_sistema = "ESTABLE"

    if threat_count > 0:
        estado_sistema = "ALERTA ACTIVA"
        nivel_critico = str(threat_count)
    else:
        estado_sistema = "MONITORIZANDO"
        nivel_critico = "Sin amenazas detectadas"

    return {
        "nivel_riesgo": nivel_riesgo,
        "salud_sistema": salud_sistema,
        "estado_sistema": estado_sistema,
        "nivel_critico": nivel_critico,
    }


def get_node_id():
    """Return real node identifier from environment or hostname."""
    import os
    return os.environ.get("NODE_ID") or socket.gethostname() or "Sin datos disponibles"
