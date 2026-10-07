"""Estados verificables para endpoints — sin asumir Online sin evidencia."""


def local_host_status():
    """Host local con métricas psutil activas."""
    return "Monitorizado (psutil)"


def arp_node_status(response_ms=None):
    """Dispositivo descubierto por ARP; no implica disponibilidad ICMP."""
    if response_ms is not None and isinstance(response_ms, (int, float)):
        return f"Detectado (ARP, {response_ms:.0f}ms)"
    return "Detectado (ARP)"
