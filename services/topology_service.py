"""
Topology Service — Gemelo digital de la red basado exclusivamente en telemetría real.
Conexiones: gateway verificado + flujos psutil hacia IPs del inventario ARP.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger

NO_DATA = "Sin datos disponibles"

CATEGORY_ORDER = [
    "Gateway", "Router", "Switch", "Servidor", "PC", "Laptop",
    "Celular", "Tablet", "IoT", "Impresora", "Smart TV", "Otro",
]

RISK_LABELS = {
    "seguro": ("Seguro", "🟢"),
    "observacion": ("Observación", "🟡"),
    "riesgo": ("Riesgo", "🟠"),
    "critico": ("Crítico", "🔴"),
}


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _explain_vlan() -> str:
    return (
        "VLAN no identificable — el escaneo ARP de NOVUS opera en capa 2/3 "
        "sin consulta SNMP ni mirror de switch. Requiere integración con infraestructura de red."
    )


def _network_function(node: dict, gateway: Optional[str]) -> str:
    ip = node.get("ip")
    dtype = node.get("device_type") or "Otro"
    if gateway and ip == gateway:
        return "Gateway principal — enrutamiento del segmento local"
    if dtype in ("Router", "Gateway"):
        return "Enrutamiento y salida a Internet/WAN"
    if dtype == "Switch":
        return "Conmutación de tráfico en LAN"
    if dtype == "Servidor":
        return "Servicios y aplicaciones en red"
    if dtype in ("PC", "Laptop"):
        return "Estación de trabajo / endpoint de usuario"
    if dtype in ("Celular", "Tablet"):
        return "Dispositivo móvil en Wi‑Fi"
    if dtype == "IoT":
        return "Dispositivo IoT conectado al segmento"
    if dtype == "Impresora":
        return "Impresión en red"
    if node.get("is_pending_approval"):
        return "Pendiente de aprobación AIE — función en revisión"
    status = node.get("asset_status_label") or node.get("status_display")
    if status:
        return f"Nodo {dtype} — {status}"
    return f"Nodo {dtype} en segmento LAN"


def _latency_display(node: dict) -> dict:
    from services.network_ndr_service import _field
    ms = node.get("response_time_ms")
    if isinstance(ms, (int, float)) and ms > 0:
        return {"value": ms, "display": f"{ms} ms (ICMP)", "reason": None}
    if ms and ms != NO_DATA and str(ms).replace(".", "").isdigit():
        return {"value": float(ms), "display": f"{ms} ms (ICMP)", "reason": None}
    return {
        "value": None,
        "display": "No medida — el host no respondió a ping o el escaneo ARP no incluye latencia ICMP para este dispositivo.",
        "reason": "generic",
    }


def build_peer_connections(nodes: List[dict], meta: dict) -> List[dict]:
    """Conexiones reales host local → IPs remotas medidas por psutil."""
    edges: List[dict] = []
    local_ip = meta.get("local_ip")
    node_ips = {n.get("ip") for n in nodes if n.get("ip")}
    try:
        import psutil
        conn_map: Dict[str, int] = {}
        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr:
                continue
            rip = conn.raddr.ip
            if rip in node_ips and rip != local_ip:
                conn_map[rip] = conn_map.get(rip, 0) + 1
        for rip, count in conn_map.items():
            edges.append({
                "from": local_ip or "host_local",
                "to": rip,
                "type": "active_flow",
                "connections": count,
                "traffic_intensity": None,
                "traffic_measured": False,
                "traffic_label": "Tráfico no medido",
                "evidence": f"{count} conexión(es) activa(s) observada(s) vía psutil.net_connections",
            })
    except Exception as exc:
        logger.debug("peer connections: %s", exc)
    return edges


def sanitize_topology_connections(connections: List[dict]) -> List[dict]:
    """Elimina intensidad de tráfico no medida — snapshots legacy no pueden mostrarse como LIVE."""
    out: List[dict] = []
    for raw in connections or []:
        c = dict(raw)
        measured = bool(c.get("traffic_measured")) and c.get("traffic_intensity") is not None
        if not measured:
            c["traffic_intensity"] = None
            c["traffic_measured"] = False
            c.setdefault("traffic_label", "Tráfico no medido")
        out.append(c)
    return out


def build_real_connections(nodes: List[dict], meta: dict) -> List[dict]:
    """Gateway verificado → dispositivos del segmento ARP."""
    gateway = meta.get("gateway")
    if not gateway or gateway == NO_DATA:
        return []

    gw_in_scan = any(n.get("ip") == gateway for n in nodes)
    if not gw_in_scan:
        return []

    edges = []
    for node in nodes:
        ip = node.get("ip")
        if not ip or ip == gateway:
            continue
        traffic = node.get("traffic") or {}
        conn = traffic.get("connections_active")
        # NOVUS no mide bytes/paquetes en aristas LAN — conexiones ≠ intensidad de tráfico.
        has_bytes = isinstance(traffic.get("bytes_recv"), (int, float)) or isinstance(
            traffic.get("bytes_sent"), (int, float)
        )
        edges.append({
            "from": gateway,
            "to": ip,
            "type": "lan_segment",
            "traffic_intensity": None,
            "traffic_measured": bool(has_bytes),
            "traffic_label": "Tráfico no medido" if not has_bytes else None,
            "connections": conn if isinstance(conn, int) else None,
            "connections_observed": conn if isinstance(conn, int) else None,
            "evidence": "Dispositivo descubierto por ARP en el segmento del gateway",
            "data_origin": "live_discovery" if meta.get("data_freshness") == "live" else meta.get("data_freshness", "cached"),
        })
    return edges


def build_digital_twin_summary(
    nodes: List[dict],
    connections: List[dict],
    meta: dict,
    ndr: dict,
) -> dict:
    """Resumen ejecutivo del gemelo digital."""
    exec_sum = ndr.get("executive_summary") or {}
    gateway = meta.get("gateway")
    return {
        "overall_status": exec_sum.get("overall_status", "Monitorizando"),
        "network_health": exec_sum.get("network_health", "—"),
        "protection_level": exec_sum.get("protection_level", "—"),
        "gateway": gateway,
        "segment": meta.get("network_range") or NO_DATA,
        "device_count": len(nodes),
        "unknown_count": ndr.get("unknown_count", 0),
        "critical_devices": [n.get("ip") for n in nodes if n.get("risk_level") == "critico"],
        "observation_devices": [n.get("ip") for n in nodes if n.get("risk_level") == "observacion"],
        "vulnerable_devices": [n.get("ip") for n in nodes if (n.get("vulnerabilities_count") or 0) > 0],
        "high_traffic_devices": [
            t.get("ip") for t in (ndr.get("top_traffic") or [])[:3]
        ],
        "active_connections": len(connections),
        "last_analysis": ndr.get("timestamp") or NO_DATA,
        "communication_model": (
            f"Modelo hub-and-spoke: gateway {gateway} conecta {len(nodes)} dispositivo(s) "
            f"en {meta.get('network_range') or 'segmento local'}. "
            f"Flujos activos locales: {sum(1 for c in connections if c.get('type') == 'active_flow')}."
        ),
    }


def build_topology_payload(force_refresh: bool = False) -> dict:
    """Payload canónico del gemelo digital para /topology — snapshot-first."""
    if not force_refresh:
        from services.network_snapshot_service import _load

        ndr_snap = _load("ndr")
        if ndr_snap and ndr_snap.get("body"):
            body = ndr_snap["body"]
            if body.get("nodes") is not None or body.get("status") in ("success", "scanning", "no_data"):
                return _build_topology_payload_from_ndr(body)

    from services.performance_cache import get_or_compute, invalidate
    from core.config import Config

    if force_refresh:
        invalidate("topology_payload")

    return get_or_compute(
        "topology_payload",
        Config.PANEL_CACHE_TTL,
        lambda: _build_topology_payload_uncached(force_refresh=force_refresh),
    )


def _build_topology_payload_from_ndr(ndr: dict) -> dict:
    """Construye topología desde cuerpo NDR ya materializado (sin ARP sync)."""
    from services.network_ndr_service import _related_vulns

    meta = ndr.get("meta") or {}
    nodes = list(ndr.get("nodes") or [])
    alerts = ndr.get("alerts") or []
    gateway = meta.get("gateway")
    segment = meta.get("network_range")

    for node in nodes:
        ip = node.get("ip")
        vulns = _related_vulns(ip) if ip else []
        node["vulnerabilities_count"] = len(vulns)
        node["vulnerabilities"] = vulns[:5]
        risk = node.get("risk_level") or "seguro"
        label, emoji = RISK_LABELS.get(risk, ("Seguro", "🟢"))
        node["risk_label"] = label
        node["risk_emoji"] = emoji
        node["status_label"] = "Activo (ARP)" if node.get("ip") else NO_DATA
        node["network_function"] = _network_function(node, gateway)
        node["segment"] = segment or NO_DATA
        node["gateway_associated"] = gateway or NO_DATA
        node["vlan"] = _explain_vlan()
        node["latency"] = _latency_display(node)
        node["is_gateway"] = ip == gateway
        node["is_critical"] = risk in ("critico", "riesgo")
        node["has_vulnerabilities"] = len(vulns) > 0

    categories: Dict[str, List[dict]] = {cat: [] for cat in CATEGORY_ORDER}
    for node in nodes:
        dtype = node.get("device_type") or "Otro"
        if dtype not in categories:
            categories.setdefault("Otro", []).append(node)
        else:
            categories[dtype].append(node)

    category_groups = [
        {"category": cat, "devices": categories.get(cat) or []}
        for cat in CATEGORY_ORDER
        if categories.get(cat)
    ]

    gw_connections = build_real_connections(nodes, meta)
    peer_connections = build_peer_connections(nodes, meta)
    connections = sanitize_topology_connections(
        gw_connections
        + [
            c
            for c in peer_connections
            if not any(
                e.get("to") == c.get("to") and e.get("from") == c.get("from")
                for e in gw_connections
            )
        ]
    )

    summary = {
        "device_count": len(nodes),
        "unknown_count": ndr.get("unknown_count", 0),
        "alert_count": ndr.get("alert_count", 0),
        "critical_count": sum(1 for n in nodes if n.get("risk_level") == "critico"),
        "observation_count": sum(1 for n in nodes if n.get("risk_level") == "observacion"),
        "risk_count": sum(1 for n in nodes if n.get("risk_level") == "riesgo"),
        "with_vulnerabilities": sum(1 for n in nodes if n.get("vulnerabilities_count", 0) > 0),
        "gateway": gateway if gateway else NO_DATA,
        "segment": segment or NO_DATA,
        "last_scan": (ndr.get("cache") or {}).get("last_scan") or NO_DATA,
        "connection_count": len(connections),
        "observed_device_count": ndr.get("observed_device_count", len(nodes)),
        "historical_device_count": ndr.get("historical_device_count", len(nodes)),
        "data_freshness": ndr.get("data_freshness"),
    }

    digital_twin = build_digital_twin_summary(nodes, connections, meta, ndr)
    if ndr.get("data_freshness") == "stale":
        digital_twin["device_count"] = ndr.get("observed_device_count", 0)
        digital_twin["historical_device_count"] = ndr.get("historical_device_count", len(nodes))

    return {
        "status": "success",
        "timestamp": ndr.get("timestamp") or _now(),
        "meta": meta,
        "nodes": nodes,
        "connections": connections,
        "categories": category_groups,
        "summary": summary,
        "digital_twin": digital_twin,
        "executive_summary": ndr.get("executive_summary") or {},
        "alerts": alerts,
        "top_traffic": ndr.get("top_traffic") or [],
        "unknown_devices": ndr.get("unknown_devices") or [],
        "motors": ndr.get("motors") or [],
        "cache": ndr.get("cache") or {},
    }


def _build_topology_payload_uncached(force_refresh: bool = False) -> dict:
    from services.network_ndr_service import build_ndr_payload, build_ndr_payload_from_cache

    if force_refresh:
        ndr = build_ndr_payload(force_refresh=True)
    else:
        ndr = build_ndr_payload_from_cache()
    return _build_topology_payload_from_ndr(ndr)


def get_topology_device(ip: str) -> dict:
    """Ficha técnica completa del gemelo digital — reutiliza enriquecimiento NDR."""
    from services.network_ndr_service import get_device_detail
    from services.network_scanner import network_scanner

    detail = get_device_detail(ip)
    if detail.get("status") == "not_found":
        return detail

    device = detail.get("device") or {}
    meta = network_scanner.get_network_meta() or {}
    gateway = meta.get("gateway")
    risk = device.get("risk_level") or "seguro"
    label, emoji = RISK_LABELS.get(risk, ("Seguro", "🟢"))

    return {
        **detail,
        "device": device,
        "panel": {
            "nombre": device.get("name_display", {}).get("display")
            if isinstance(device.get("name_display"), dict)
            else (device.get("hostname") or device.get("name") or ip),
            "ip": device.get("ip_display", {}).get("display") if isinstance(device.get("ip_display"), dict) else device.get("ip"),
            "mac": device.get("mac_display", {}).get("display") if isinstance(device.get("mac_display"), dict) else device.get("mac"),
            "fabricante": device.get("vendor_display", {}).get("display") if isinstance(device.get("vendor_display"), dict) else device.get("vendor"),
            "sistema_operativo": (device.get("os_estimate") or {}).get("display", device.get("os_estimate_short")),
            "tipo_dispositivo": device.get("device_type_display", {}).get("display") if isinstance(device.get("device_type_display"), dict) else device.get("device_type"),
            "funcion_red": _network_function(device, gateway),
            "gateway_asociado": gateway or "No identificado en meta de red",
            "segmento": meta.get("network_range") or "Segmento no determinado por escáner",
            "vlan": _explain_vlan(),
            "estado": device.get("asset_status_label") or device.get("status_display") or "Pendiente de aprobación",
            "trust_score": device.get("trust_score"),
            "trust_display": device.get("trust_display"),
            "riesgo_emoji": emoji,
            "riesgo_nivel": label,
            "tiempo_conectado": device.get("connected_since_display", {}).get("display") if isinstance(device.get("connected_since_display"), dict) else device.get("connected_since"),
            "ultima_actividad": device.get("last_activity_display", {}).get("display") if isinstance(device.get("last_activity_display"), dict) else device.get("last_seen"),
            "latencia": _latency_display(device).get("display"),
            "trafico": {
                "bytes_enviados": device.get("traffic_sent_display", {}).get("display") if isinstance(device.get("traffic_sent_display"), dict) else (device.get("traffic") or {}).get("bytes_sent"),
                "bytes_recibidos": device.get("traffic_recv_display", {}).get("display") if isinstance(device.get("traffic_recv_display"), dict) else (device.get("traffic") or {}).get("bytes_recv"),
                "ancho_banda_mbps": device.get("bandwidth_display", {}).get("display") if isinstance(device.get("bandwidth_display"), dict) else (device.get("traffic") or {}).get("bandwidth_mbps"),
                "conexiones_activas": (device.get("traffic") or {}).get("connections_active"),
                "fuente": (device.get("traffic") or {}).get("source"),
            },
            "puertos_detectados": device.get("open_ports_display") or device.get("open_ports") or [],
            "servicios_detectados": device.get("services_display") or device.get("services") or [],
            "vulnerabilidades": detail.get("vulnerabilities_related") or [],
            "incidentes": device.get("incidents") or [],
            "nivel_confianza": device.get("confidence") or {},
            "adaptive_defense": device.get("adaptive_defense") or {},
            "motores_proteccion": device.get("protection_motors") or [],
            "recomendaciones": device.get("recommendations") or detail.get("recommendations") or [],
            "historial": detail.get("history") or [],
            "alertas": detail.get("alerts") or [],
            "es_pendiente_aie": device.get("is_pending_approval", False),
            "asset_status": device.get("asset_status"),
        },
    }


def answer_kernel_query(question: str) -> Optional[str]:
    """Respuestas Kernel IA exclusivamente desde Topology / motores de red."""
    q = (question or "").lower()
    triggers = (
        "topolog", "mapa de red", "nodo", "nodos", "dispositivo", "dispositivos",
        "conectados", "conectado", "red local", "infraestructura", "gemelo digital",
        "mayor riesgo", "más riesgo", "mas riesgo",
        "cuántos dispositivo", "cuantos dispositivo", "cuántos hay", "cuantos hay",
        "más tráfico", "mas trafico", "consume más",
        "apareció recientemente", "aparecio recientemente", "reciente en la red",
        "desconocido", "sospech", "conexiones sospechosas",
    )
    if not any(k in q for k in triggers):
        return None

    payload = build_topology_payload(force_refresh=False)
    nodes = payload.get("nodes") or []
    summary = payload.get("summary") or {}
    twin = payload.get("digital_twin") or {}
    unknown = payload.get("unknown_devices") or []
    alerts = payload.get("alerts") or []
    top = payload.get("top_traffic") or []

    if any(k in q for k in ("cuántos dispositivo", "cuantos dispositivo", "cuántos hay conect", "cuantos hay conect")):
        return (
            f"Gemelo digital Topology: {summary.get('device_count', 0)} dispositivo(s), "
            f"gateway {summary.get('gateway', NO_DATA)}, segmento {summary.get('segment', NO_DATA)}. "
            f"Desconocidos: {summary.get('unknown_count', 0)}. "
            f"Conexiones documentadas: {summary.get('connection_count', 0)}."
        )

    if any(k in q for k in ("mayor riesgo", "más riesgo", "mas riesgo")):
        order = {"critico": 4, "riesgo": 3, "observacion": 2, "seguro": 1}
        ranked = sorted(nodes, key=lambda n: order.get(n.get("risk_level"), 0), reverse=True)
        if not ranked:
            return NO_DATA
        n = ranked[0]
        return (
            f"{n.get('risk_emoji', '')} Mayor riesgo: {n.get('ip')} ({n.get('device_type')}) — {n.get('risk_label')}. "
            f"Función: {n.get('network_function', '')}. "
            f"Vulnerabilidades: {n.get('vulnerabilities_count', 0)}."
        )

    if any(k in q for k in ("más tráfico", "mas trafico", "consume más")):
        if not top:
            return "Sin datos de tráfico por dispositivo remoto. Solo el host local reporta bytes vía psutil."
        lines = [f"• {t.get('ip')}: {t.get('metric')} {t.get('metric_label')}" for t in top[:5]]
        return "Dispositivos con mayor actividad medida:\n" + "\n".join(lines)

    if any(k in q for k in ("apareció recientemente", "aparecio recientemente", "reciente en la red", "nuevo dispositivo")):
        recent = sorted(
            [n for n in nodes if n.get("first_seen") and n.get("first_seen") != NO_DATA],
            key=lambda n: n.get("first_seen", ""),
            reverse=True,
        )[:5]
        if not recent:
            return "Sin registros de aparición reciente en el inventario ARP."
        lines = [f"• {n.get('ip')} ({n.get('device_type')}) — primera vez: {n.get('first_seen')}" for n in recent]
        return "Dispositivos registrados más recientemente:\n" + "\n".join(lines)

    if any(k in q for k in ("desconocido", "unknown")):
        if not unknown:
            return "No hay dispositivos desconocidos en la topología actual."
        lines = [f"• {u.get('ip')} MAC {u.get('mac')} — {u.get('device_type')}" for u in unknown[:10]]
        return f"{len(unknown)} dispositivo(s) desconocido(s):\n" + "\n".join(lines)

    if any(k in q for k in ("sospech", "conexiones sospechosas", "anomal")):
        if not alerts:
            return "No hay conexiones o actividad sospechosa con evidencia verificable."
        lines = [f"• [{a.get('level')}] {a.get('title')} — IP {a.get('ip')}: {a.get('evidence')}" for a in alerts[:8]]
        return f"{len(alerts)} alerta(s) de red:\n" + "\n".join(lines)

    if any(k in q for k in ("topolog", "mapa", "gemelo")):
        return twin.get("communication_model") or (
            f"Topología: {summary.get('device_count', 0)} dispositivos, "
            f"críticos: {summary.get('critical_count', 0)}, "
            f"con vulnerabilidades: {summary.get('with_vulnerabilities', 0)}."
        )

    return (
        f"Topology (gemelo digital): {summary.get('device_count', 0)} dispositivos. "
        f"Gateway: {summary.get('gateway', NO_DATA)}. "
        f"Salud: {(payload.get('executive_summary') or {}).get('network_health', '—')}."
    )
