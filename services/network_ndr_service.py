"""
NOVUS Network NDR — inventario, telemetría y comportamiento basados en datos reales.
Sin placeholders: métricas de bytes solo cuando psutil/ARP las proveen.
"""
from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

import psutil

from utils.logger import logger

NO_DATA = "Sin datos disponibles"
_scan_presence: Dict[str, List[bool]] = defaultdict(list)
_prev_scan_macs: Dict[str, str] = {}
_lock = threading.Lock()
_payload_cache: Dict[str, Any] = {"ts": 0.0, "payload": None}
_PAYLOAD_TTL = 8.0

ALERT_PLAIN_EXPLANATIONS = {
    "Superficie de puertos elevada": (
        "El dispositivo expone varios puertos de red abiertos. Esto amplía la superficie "
        "de ataque; conviene verificar que cada servicio sea necesario."
    ),
    "Conexiones activas elevadas": (
        "Este equipo mantiene muchas conexiones simultáneas hacia el dispositivo. "
        "Puede ser tráfico legítimo intenso o actividad que merece revisión."
    ),
    "Dispositivo intermitente en ARP": (
        "El dispositivo aparece y desaparece del mapa ARP con frecuencia. "
        "Suele deberse a ahorro de energía, Wi‑Fi inestable o un host que entra y sale de la red."
    ),
    "Cambio de IP en dispositivo conocido": (
        "El dispositivo obtuvo una nueva dirección IP asignada por el router. "
        "Normalmente ocurre por renovación DHCP y no representa un riesgo por sí solo."
    ),
}

EVENT_PATTERN_EXPLANATIONS = [
    ("escaneo manual", "Se inició un escaneo de red solicitado por el operador para actualizar el inventario ARP."),
    ("escaneo de red", "NOVUS completó o inició un ciclo de descubrimiento ARP en el segmento local."),
    ("caché de red", "Se limpió la caché del escáner; el próximo ciclo reconstruirá el inventario desde cero."),
    ("[ndr]", "El motor NDR detectó un comportamiento que requiere atención según telemetría verificable."),
    ("dispositivo", "Cambio en el inventario de dispositivos detectado por el escáner de red."),
    ("arp", "Actualización del mapa ARP: dispositivos visibles en la red local."),
]


def _field(value: Any, reason_key: str = "generic") -> dict:
    """Valor con explicación cuando falta telemetría."""
    from services.telemetry_resolver import is_absent, explain

    if isinstance(value, (int, float)) and not is_absent(value):
        return {"value": value, "display": str(value), "reason": None}
    if not is_absent(value):
        return {"value": value, "display": str(value), "reason": None}
    reason = explain(reason_key)
    return {"value": None, "display": reason, "reason": reason_key}


def _plain_alert(alert: dict) -> str:
    title = alert.get("title") or ""
    if title in ALERT_PLAIN_EXPLANATIONS:
        return ALERT_PLAIN_EXPLANATIONS[title]
    return (
        f"Alerta generada por {alert.get('motor', 'motor NDR')} con confianza "
        f"{alert.get('confidence', 'N/A')}. Revise la evidencia técnica adjunta."
    )


def explain_network_event(message: str, level: str = "info") -> str:
    msg = (message or "").lower()
    for pattern, explanation in EVENT_PATTERN_EXPLANATIONS:
        if pattern in msg:
            return explanation
    if level == "alert":
        return "Evento crítico registrado por un motor de seguridad NOVUS. Requiere revisión del operador."
    if level == "warn":
        return "Advertencia de red basada en telemetría real. Puede ser informativa o requerir seguimiento."
    return "Evento operativo del módulo de red NOVUS registrado durante el monitoreo continuo."


def estimate_os(node: dict) -> dict:
    """SO estimado solo desde vendor, tipo y puertos — sin inventar fingerprint."""
    vendor = (node.get("vendor") or "").lower()
    dtype = (node.get("device_type") or "").lower()
    ports = {p.get("port") for p in (node.get("open_ports") or []) if p.get("port")}

    if "apple" in vendor:
        return _field("macOS / iOS (estimado)", "generic")
    if "microsoft" in vendor or 3389 in ports:
        return _field("Windows (estimado por vendor/puertos)", "generic")
    if any(k in vendor for k in ("samsung", "xiaomi", "huawei", "motorola")):
        return _field("Android (estimado por fabricante móvil)", "generic")
    if dtype in ("router", "gateway"):
        return _field("Firmware de router (estimado)", "generic")
    if dtype == "iot":
        return _field("Sistema embebido / IoT (estimado)", "generic")
    if dtype == "impresora":
        return _field("Firmware de impresora (estimado)", "generic")
    if ports & {22}:
        return _field("Linux/Unix posible (puerto SSH)", "generic")
    from services.telemetry_resolver import explain
    return {
        "value": None,
        "display": (
            "No identificable — el escaneo ARP no incluye fingerprinting de SO. "
            "Use «Investigar» para reanalizar con motores NOVUS."
        ),
        "reason": "generic",
    }


def compute_analysis_confidence(node: dict, inv: Any) -> dict:
    score = 35
    from services.telemetry_resolver import is_absent

    if not is_absent(node.get("vendor")):
        score += 20
    if inv and (inv.times_seen or 0) > 3:
        score += 20
    elif inv and (inv.times_seen or 0) > 1:
        score += 10
    if node.get("open_ports"):
        score += min(15, len(node.get("open_ports") or []) * 3)
    if not is_absent(node.get("hostname") or node.get("name")):
        score += 10
    if isinstance(node.get("traffic", {}).get("connections_active"), int):
        score += 5
    score = min(100, score)
    label = "ALTA" if score >= 75 else "MEDIA" if score >= 50 else "BAJA"
    return {"score": score, "label": label}


def _device_adaptive_defense(ip: str) -> dict:
    try:
        from services.adaptive_defense_engine import get_adaptive_defense_panel, get_endpoint_states
        from services.network_scanner import network_scanner

        meta = network_scanner.get_network_meta()
        local_ip = meta.get("local_ip")
        panel = get_adaptive_defense_panel()
        estado = panel.get("estado_actual") or ""

        if ip == local_ip:
            for ep in get_endpoint_states() or []:
                if ep.get("ip") == ip or ep.get("ip") == local_ip:
                    if (ep.get("contenciones_activas") or 0) > 0:
                        return {
                            "active": True,
                            "display": "Sí — contenciones Adaptive Defense activas en este host",
                            "detail": ep,
                        }
            if estado and estado != "Sin activación reciente":
                return {
                    "active": True,
                    "display": f"Sí — Adaptive Defense en nivel {estado} (host local)",
                    "detail": panel.get("ultima_respuesta"),
                }

        from services.telemetry_resolver import explain
        return {
            "active": False,
            "display": (
                f"No — Adaptive Defense opera sobre el endpoint local ({local_ip or 'N/A'}). "
                f"Dispositivos remotos se monitorizan vía NDR. {explain('adaptive_defense_idle')}"
            ),
            "detail": None,
        }
    except Exception as exc:
        logger.debug("adaptive defense lookup: %s", exc)
        return _field(None, "adaptive_defense_idle")


def _protection_motors_active() -> List[str]:
    motors = [
        "network_scanner ARP (Scapy)",
        "advanced_detector.scan_open_ports",
        "psutil.net_connections",
        "psutil.net_io_counters",
        "network_device_inventory (SQLite)",
    ]
    try:
        from services.adaptive_sector_protection_engine import aspe
        if aspe:
            motors.append("Adaptive Sector Protection Engine (ASPE)")
    except Exception:
        pass
    try:
        from services.adaptive_defense_engine import get_adaptive_defense_panel
        panel = get_adaptive_defense_panel()
        if panel.get("estado_actual") and panel["estado_actual"] != "Sin activación reciente":
            motors.append("Adaptive Defense Engine")
    except Exception:
        pass
    return motors


def _related_incidents(ip: str) -> List[dict]:
    incidents: List[dict] = []
    try:
        from services.threat_intelligence_service import threat_intelligence
        for case in threat_intelligence.list_cases(limit=40) or []:
            blob = json.dumps(case, ensure_ascii=False).lower()
            if ip.lower() in blob:
                incidents.append(case)
    except Exception:
        pass
    try:
        from database import SessionLocal, Alerta
        db = SessionLocal()
        try:
            rows = db.query(Alerta).filter(Alerta.ip_afectada == ip).limit(10).all()
            for row in rows:
                incidents.append({
                    "id": row.id,
                    "title": row.titulo,
                    "severity": row.nivel,
                    "time": row.fecha,
                    "source": "database.Alerta",
                })
        finally:
            db.close()
    except Exception:
        pass
    return incidents[:10]


def _device_recommendations(node: dict, alerts: List[dict], vulns: List[dict]) -> List[str]:
    recs: List[str] = []
    if node.get("is_unknown"):
        recs.append(
            "Identifique el dispositivo desconocido antes de permitir acceso a recursos sensibles."
        )
    open_ports = node.get("open_ports") or []
    if len(open_ports) >= 5:
        recs.append("Revise y cierre puertos no esenciales para reducir la superficie de ataque.")
    if any(a.get("level") in ("riesgo", "critico") for a in alerts):
        recs.append("Priorice la investigación de alertas activas en este host.")
    if vulns:
        recs.append(
            f"Aplique remediación para {len(vulns)} vulnerabilidad(es) vinculada(s) a esta IP."
        )
    risk = node.get("risk_level")
    if risk == "critico":
        recs.append("Considere aislar temporalmente el dispositivo hasta completar el análisis.")
    if not recs:
        recs.append("Mantener monitorización periódica; sin acciones urgentes según telemetría actual.")
    return recs


def build_executive_summary(nodes: List[dict], alerts: List[dict], meta: dict, ts: str) -> dict:
    risk_counts = {"seguro": 0, "observacion": 0, "riesgo": 0, "critico": 0}
    for n in nodes:
        rl = n.get("risk_level") or "seguro"
        if rl in risk_counts:
            risk_counts[rl] += 1

    critical = risk_counts["critico"]
    observation = risk_counts["observacion"]
    active_threats = len(alerts)
    device_count = len(nodes)

    if critical > 0 or active_threats >= 5:
        overall = "Atención crítica"
        health = "Comprometida"
        protection = "Elevado — respuesta activa recomendada"
    elif risk_counts["riesgo"] > 0 or active_threats > 0:
        overall = "Atención requerida"
        health = "Regular"
        protection = "Medio — monitoreo reforzado"
    elif observation > 0:
        overall = "Estable con observaciones"
        health = "Buena"
        protection = "Medio — sin amenazas críticas"
    else:
        overall = "Protegido"
        health = "Buena"
        protection = "Alto — sin alertas activas"

    return {
        "overall_status": overall,
        "network_health": health,
        "device_count": device_count,
        "observation_count": observation,
        "critical_risks": critical,
        "active_threats": active_threats,
        "last_analysis": ts,
        "protection_level": protection,
        "risk_counts": risk_counts,
    }


def _build_top_traffic(nodes: List[dict], meta: dict) -> List[dict]:
    ranked: List[dict] = []
    total_conn = 0
    for n in nodes:
        t = n.get("traffic") or {}
        conn = t.get("connections_active")
        if isinstance(conn, int):
            total_conn += conn

    for n in nodes:
        t = n.get("traffic") or {}
        conn = t.get("connections_active")
        if not isinstance(conn, int):
            continue
        pct = round((conn / total_conn) * 100, 1) if total_conn else 0.0
        bw = t.get("bandwidth_mbps")
        ranked.append({
            "ip": n.get("ip"),
            "name": n.get("hostname") or n.get("name"),
            "metric": conn,
            "metric_label": "conexiones activas",
            "bytes_recv": t.get("bytes_recv"),
            "bytes_sent": t.get("bytes_sent"),
            "bandwidth_mbps": bw,
            "traffic_percent": pct,
            "last_activity": n.get("last_seen"),
            "connected_since": n.get("connected_since"),
            "device_type": n.get("device_type"),
        })

    ranked.sort(key=lambda x: x.get("metric") or 0, reverse=True)
    top = ranked[:5]

    if not top:
        local_ip = meta.get("local_ip")
        local = [n for n in nodes if n.get("ip") == local_ip]
        if local:
            n = local[0]
            t = n.get("traffic") or {}
            if isinstance(t.get("bytes_recv"), int):
                top = [{
                    "ip": n.get("ip"),
                    "name": n.get("hostname") or n.get("name"),
                    "metric": t.get("bytes_recv"),
                    "metric_label": "bytes recibidos (host local)",
                    "bytes_recv": t.get("bytes_recv"),
                    "bytes_sent": t.get("bytes_sent"),
                    "bandwidth_mbps": t.get("bandwidth_mbps"),
                    "traffic_percent": 100.0,
                    "last_activity": n.get("last_seen"),
                    "connected_since": n.get("connected_since"),
                    "device_type": n.get("device_type"),
                }]
    return top


def _enrich_device_detail(node: dict, alerts: List[dict], history: List[dict], vulns: List[dict]) -> dict:
    from database import SessionLocal, NetworkDeviceInventory

    mac = (node.get("mac") or "").lower()
    inv = None
    db = SessionLocal()
    try:
        if mac:
            inv = db.query(NetworkDeviceInventory).filter(
                NetworkDeviceInventory.mac == mac
            ).first()
    finally:
        db.close()

    os_info = estimate_os(node)
    confidence = compute_analysis_confidence(node, inv)
    adaptive = _device_adaptive_defense(node.get("ip") or "")
    incidents = _related_incidents(node.get("ip") or "")
    recommendations = _device_recommendations(node, alerts, vulns)
    t = node.get("traffic") or {}

    status_display = node.get("status_display") or node.get("asset_status_label") or "Pendiente de aprobación"
    services = node.get("services") or []
    if not services and node.get("open_ports"):
        services = [
            {"port": p.get("port"), "service": p.get("service") or f"TCP/{p.get('port')}"}
            for p in node.get("open_ports") or []
        ]

    return {
        **node,
        "name_display": _field(node.get("hostname") or node.get("name"), "generic"),
        "ip_display": _field(node.get("ip"), "generic"),
        "mac_display": _field(node.get("mac"), "generic"),
        "vendor_display": _field(node.get("vendor"), "generic"),
        "os_estimate": os_info,
        "device_type_display": _field(node.get("device_type"), "generic"),
        "status_display": {"value": status_display, "display": status_display, "reason": None},
        "risk_display": _field(node.get("risk_level"), "generic"),
        "confidence": confidence,
        "connected_since_display": _field(node.get("connected_since"), "generic"),
        "last_activity_display": _field(node.get("last_seen"), "generic"),
        "bandwidth_display": _field(
            f"{t.get('bandwidth_mbps')} Mbps" if isinstance(t.get("bandwidth_mbps"), (int, float)) else None,
            "bandwidth_unmeasured",
        ),
        "traffic_sent_display": _field(t.get("bytes_sent"), "bandwidth_unmeasured"),
        "traffic_recv_display": _field(t.get("bytes_recv"), "bandwidth_unmeasured"),
        "open_ports_display": node.get("open_ports") or [],
        "services_display": services,
        "vulnerabilities": vulns,
        "incidents": incidents,
        "incidents_display": incidents if incidents else _field(None, "no_incidents"),
        "adaptive_defense": adaptive,
        "protection_motors": _protection_motors_active(),
        "history": history,
        "recommendations": recommendations,
        "alerts": [{**a, "plain_explanation": _plain_alert(a)} for a in alerts],
    }


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def estimate_device_type(node: dict, gateway: Optional[str] = None) -> str:
    """Clasificación heurística desde hostname, vendor, TTL, puertos y rol gateway."""
    ip = node.get("ip") or ""
    vendor = (node.get("vendor") or "").lower()
    ports = {p.get("port") for p in (node.get("open_ports") or []) if p.get("port")}

    if gateway and ip == gateway:
        return "Gateway"

    hostname = node.get("name") or node.get("hostname") or ""
    if hostname in ("Sin datos disponibles", "Unknown", "Desconocido"):
        hostname = ""
    ttl_raw = node.get("ttl")
    ttl: Optional[int] = None
    if isinstance(ttl_raw, int):
        ttl = ttl_raw
    elif isinstance(ttl_raw, str) and ttl_raw.isdigit():
        ttl = int(ttl_raw)

    try:
        from services.network_device_defense.device_classifier import NOVUSDeviceClassifier

        dtype_host = NOVUSDeviceClassifier.classify(
            node.get("mac") or "",
            ttl,
            hostname,
            vendor,
        )
        if dtype_host != "Otro":
            return dtype_host
    except Exception:
        pass

    vendor_rules = [
        (("apple",), "Laptop"),
        (("samsung", "xiaomi", "huawei", "motorola", "oneplus"), "Celular"),
        (("microsoft",), "PC"),
        (("intel", "realtek", "qualcomm"), "PC"),
        (("hp", "hewlett", "canon", "epson", "brother"), "Impresora"),
        (("amazon", "google nest", "tuya", "espressif"), "IoT"),
        (("cisco", "juniper", "ubiquiti", "tp-link", "netgear", "d-link"), "Router"),
        (("lg electronics", "sony"), "Smart TV"),
    ]
    for keys, dtype in vendor_rules:
        if any(k in vendor for k in keys):
            return dtype

    if ports & {9100, 631, 515}:
        return "Impresora"
    if ports & {80, 443, 53, 8080} and len(ports) >= 2:
        if gateway and ip == gateway:
            return "Router"
        return "Servidor"
    if ports & {3389, 445, 139}:
        return "PC"
    if ports:
        return "Otro"
    return "Otro"


def _connection_stats_by_ip() -> Dict[str, dict]:
    """Conexiones activas locales agrupadas por IP remota — evidencia psutil."""
    stats: Dict[str, dict] = defaultdict(lambda: {"connections": 0, "states": []})
    try:
        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr:
                continue
            rip = conn.raddr.ip
            stats[rip]["connections"] += 1
            if conn.status:
                stats[rip]["states"].append(str(conn.status))
    except (psutil.AccessDenied, psutil.Error) as exc:
        logger.debug("connection stats: %s", exc)
    return dict(stats)


def _local_traffic_stats() -> dict:
    """Tráfico del host local desde psutil.net_io_counters."""
    try:
        net = psutil.net_io_counters()
        if not net:
            return {}
        return {
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv,
        }
    except Exception as exc:
        logger.debug("local traffic: %s", exc)
        return {}


def _interface_bandwidth_mbps() -> Optional[float]:
    try:
        counters1 = psutil.net_io_counters()
        time.sleep(0.25)
        counters2 = psutil.net_io_counters()
        if not counters1 or not counters2:
            return None
        delta = (counters2.bytes_sent + counters2.bytes_recv) - (
            counters1.bytes_sent + counters1.bytes_recv
        )
        return round((delta * 8) / (0.25 * 1_000_000), 2)
    except Exception:
        return None


def sync_inventory_from_nodes(nodes: List[dict], meta: Optional[dict] = None) -> None:
    """Persiste inventario AIE desde resultados ARP reales."""
    from services.asset_intelligence_engine import sync_asset_from_node
    from services.tenant_scope_service import get_platform_tenant_id

    platform_tid = get_platform_tenant_id()
    existing_map = None
    try:
        from database import SessionLocal, NetworkDeviceInventory
        db = SessionLocal()
        try:
            existing_map = {
                (r.mac or "").lower(): r
                for r in db.query(NetworkDeviceInventory).filter(
                    (NetworkDeviceInventory.tenant_id == platform_tid)
                    | (NetworkDeviceInventory.tenant_id.is_(None))
                ).all()
            }
        finally:
            db.close()
    except Exception:
        existing_map = None

    for node in nodes:
        try:
            sync_asset_from_node(node, meta, existing_map)
        except Exception as exc:
            logger.debug("AIE sync node: %s", exc)


def _update_presence_tracking(nodes: List[dict]) -> None:
    """Rastrea aparición/desaparición intermitente para alertas NDR (sin duplicar eventos de conexión)."""
    from services.device_connection_monitor import _prev_scan_macs

    with _lock:
        current_macs = {(n.get("mac") or "").lower() for n in nodes if n.get("mac")}
        for mac in current_macs:
            _scan_presence[mac].append(True)
            _scan_presence[mac] = _scan_presence[mac][-10:]
        for mac in list(_prev_scan_macs):
            if mac not in current_macs:
                _scan_presence[mac].append(False)
                _scan_presence[mac] = _scan_presence[mac][-10:]


def analyze_behavior(nodes: List[dict], meta: Optional[dict] = None) -> List[dict]:
    """Genera alertas solo con evidencia verificable del motor."""
    from services.network_event_log import network_event_log

    alerts: List[dict] = []
    meta = meta or {}
    conn_stats = meta.get("lab_conn_stats") or _connection_stats_by_ip()
    ts = _now()

    for node in nodes:
        ip = node.get("ip")
        mac = (node.get("mac") or "").lower()
        if not ip:
            continue

        open_ports = node.get("open_ports") or []
        if len(open_ports) >= 5:
            alerts.append({
                "id": f"NDR-PORT-{ip}",
                "motor": "advanced_detector.scan_open_ports",
                "level": "observacion",
                "confidence": "MEDIA",
                "time": ts,
                "ip": ip,
                "mac": mac,
                "title": "Superficie de puertos elevada",
                "evidence": f"{len(open_ports)} puerto(s) abierto(s): "
                + ", ".join(str(p.get("port")) for p in open_ports[:8]),
            })

        cstat = conn_stats.get(ip)
        if cstat and cstat.get("connections", 0) >= 25:
            alerts.append({
                "id": f"NDR-CONN-{ip}",
                "motor": "psutil.net_connections",
                "level": "riesgo",
                "confidence": "ALTA",
                "time": ts,
                "ip": ip,
                "mac": mac,
                "title": "Conexiones activas elevadas",
                "evidence": f"{cstat['connections']} conexión(es) desde el host hacia {ip}",
            })

        presence = _scan_presence.get(mac, [])
        if len(presence) >= 4:
            flips = sum(
                1 for i in range(1, len(presence)) if presence[i] != presence[i - 1]
            )
            if flips >= 3:
                alerts.append({
                    "id": f"NDR-FLIP-{mac}",
                    "motor": "network_scanner ARP presence",
                    "level": "observacion",
                    "confidence": "MEDIA",
                    "time": ts,
                    "ip": ip,
                    "mac": mac,
                    "title": "Dispositivo intermitente en ARP",
                    "evidence": f"{flips} cambio(s) presencia/ausencia en últimos escaneos",
                })

    from database import SessionLocal, NetworkDeviceInventory
    db = SessionLocal()
    try:
        for node in nodes:
            mac = (node.get("mac") or "").lower()
            ip = node.get("ip")
            if not mac:
                continue
            prev = db.query(NetworkDeviceInventory).filter(
                NetworkDeviceInventory.mac == mac
            ).first()
            if prev and prev.ip and prev.ip != ip:
                same_vendor = (
                    prev.vendor and node.get("vendor")
                    and str(prev.vendor).lower() == str(node.get("vendor")).lower()
                )
                level = "observacion" if same_vendor and (prev.times_seen or 0) > 2 else "riesgo"
                conf = "MEDIA" if level == "observacion" else "ALTA"
                alerts.append({
                    "id": f"NDR-IPCHG-{mac}",
                    "motor": "network_inventory",
                    "level": level,
                    "confidence": conf,
                    "time": ts,
                    "ip": ip,
                    "mac": mac,
                    "title": "Cambio de IP en dispositivo conocido",
                    "evidence": f"MAC {mac}: {prev.ip} -> {ip}"
                    + (" (posible renovación DHCP)" if level == "observacion" else ""),
                })
    finally:
        db.close()

    gateway = meta.get("gateway")
    ip_to_macs: Dict[str, set] = {}
    for node in nodes:
        nip = node.get("ip")
        nmac = (node.get("mac") or "").lower()
        if nip and nmac:
            ip_to_macs.setdefault(nip, set()).add(nmac)

    sensitive_ports = {22, 23, 80, 443, 3389, 3306, 5432, 8080, 8443}
    outbound_ports: set = set()
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.raddr and conn.status in ("SYN_SENT", "TIME_WAIT", "ESTABLISHED"):
                outbound_ports.add(conn.raddr.port)
    except (psutil.AccessDenied, psutil.Error):
        pass
    scan_hits = sorted(outbound_ports & sensitive_ports)
    if len(scan_hits) >= 3:
        alerts.append({
            "id": "NDR-SCAN-HOST",
            "motor": "psutil.net_connections",
            "level": "riesgo",
            "confidence": "MEDIA",
            "time": ts,
            "ip": meta.get("local_ip") or "host",
            "mac": "",
            "title": "Patrón de escaneo de puertos detectado",
            "evidence": f"Conexiones hacia puertos sensibles: {', '.join(str(p) for p in scan_hits[:8])}",
        })

    device_count = len(nodes)
    unknown_count = sum(1 for n in nodes if n.get("is_unknown") or not n.get("vendor"))
    if device_count >= 8 and unknown_count / max(device_count, 1) >= 0.6:
        alerts.append({
            "id": "NDR-HOSTILE-UNKNOWN",
            "motor": "network_ndr_service",
            "level": "riesgo",
            "confidence": "MEDIA",
            "time": ts,
            "ip": meta.get("local_ip") or "segment",
            "mac": "",
            "title": "Entorno hostil — alta proporción de dispositivos desconocidos",
            "evidence": f"{unknown_count}/{device_count} dispositivos sin inventario consolidado",
        })

    if device_count >= 25:
        alerts.append({
            "id": "NDR-HOSTILE-DENSITY",
            "motor": "network_ndr_service",
            "level": "observacion",
            "confidence": "MEDIA",
            "time": ts,
            "ip": meta.get("network_range") or "segment",
            "mac": "",
            "title": "Alta densidad de dispositivos en segmento",
            "evidence": f"{device_count} dispositivos visibles — monitoreo intensificado recomendado",
        })

    try:
        from database import SessionLocal, Log
        from datetime import datetime, timedelta

        db = SessionLocal()
        try:
            cutoff = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
            recent_rows = (
                db.query(Log)
                .filter(Log.evento == "LOGIN_FAILED", Log.fecha >= cutoff)
                .order_by(Log.id.desc())
                .limit(200)
                .all()
            )
            auth_fails = 0
            for row in recent_rows:
                det = row.detalle or ""
                if "[EXCLUIDO: IP RFC 5737" in det:
                    continue
                ip = "unknown"
                for part in det.split():
                    if part.startswith("ip="):
                        ip = part.split("=", 1)[1]
                        break
                from utils.ip_validation import is_documentation_ip
                if is_documentation_ip(ip):
                    continue
                if ip.startswith("127.") or ip in ("::1", "localhost", "unknown"):
                    continue
                auth_fails += 1
            if auth_fails >= 15:
                alerts.append({
                    "id": "NDR-HOSTILE-AUTH",
                    "motor": "audit_logs",
                    "level": "riesgo",
                    "confidence": "ALTA",
                    "time": ts,
                    "ip": "auth",
                    "mac": "",
                    "title": "Entorno hostil — actividad de autenticación anómala",
                    "evidence": f"{auth_fails} eventos LOGIN_FAILED verificables (24 h, sin loopback)",
                })
        finally:
            db.close()
    except Exception:
        pass

    for dup_ip, macs in ip_to_macs.items():
        if len(macs) < 2:
            continue
        is_gateway = gateway and dup_ip == gateway
        level = "critico" if is_gateway else "riesgo"
        conf = "ALTA"
        title = "Posible ARP spoofing en gateway" if is_gateway else "Conflicto ARP — misma IP, MACs distintas"
        alerts.append({
            "id": f"NDR-ARP-{dup_ip.replace('.', '-')}",
            "motor": "network_scanner ARP conflict",
            "level": level,
            "confidence": conf,
            "time": ts,
            "ip": dup_ip,
            "mac": ",".join(sorted(macs)[:4]),
            "title": title,
            "evidence": f"IP {dup_ip} asociada a {len(macs)} MAC(s): {', '.join(sorted(macs)[:4])}",
        })

    for alert in alerts:
        alert["plain_explanation"] = _plain_alert(alert)
        network_event_log.record(
            f"[NDR] {alert['title']}: {alert['evidence']}",
            level="warn" if alert["level"] != "critico" else "alert",
        )
        try:
            from services.defense_coordinator import defense_coordinator

            defense_coordinator.record_detection(
                "network_ndr_service",
                "ndr_alert",
                alert,
                phase="detect",
                outcome="detected",
                threat_type="iot_anomaly" if "IOT" in alert.get("id", "") else "lateral_movement",
                finding_id=alert.get("id"),
                detail=alert.get("title"),
                confidence=alert.get("confidence"),
            )
        except Exception as ndr_reg_exc:
            logger.debug("NDR defense registry: %s", ndr_reg_exc)
        if alert.get("level") in ("riesgo", "critico"):
            try:
                from services.adaptive_sector_protection_engine import aspe
                aspe.evaluate_incident(
                    {
                        "id": alert.get("id"),
                        "tipo": "network_anomaly",
                        "motor": alert.get("motor"),
                        "nombre": alert.get("title"),
                        "descripcion": alert.get("evidence"),
                        "evidencia": alert,
                        "ip": alert.get("ip"),
                        "verified": alert.get("confidence") == "ALTA",
                        "confianza": "Alta" if alert.get("confidence") == "ALTA" else "Media",
                    },
                    source="network_ndr",
                )
            except Exception as exc:
                logger.debug("ASPE NDR alert: %s", exc)

    return alerts


def enrich_nodes_for_ndr(nodes: List[dict], meta: Optional[dict] = None) -> List[dict]:
    """Enriquece nodos ARP con inventario AIE, telemetría y riesgo."""
    from database import SessionLocal, NetworkDeviceInventory
    from services.asset_intelligence_engine import enrich_node_with_aie

    meta = meta or {}
    local_ip = meta.get("local_ip")
    conn_stats = _connection_stats_by_ip()
    local_traffic = _local_traffic_stats()
    bandwidth_mbps = _interface_bandwidth_mbps()

    db = SessionLocal()
    inventory_map = {}
    try:
        for row in db.query(NetworkDeviceInventory).all():
            inventory_map[row.mac.lower()] = row
    finally:
        db.close()

    today = datetime.now().strftime("%Y-%m-%d")
    enriched = []
    for node in list(nodes):
        mac = (node.get("mac") or "").lower()
        ip = node.get("ip")
        inv = inventory_map.get(mac)
        dtype = node.get("device_type") or estimate_device_type(node, meta.get("gateway"))

        first_seen = inv.first_seen if inv else None
        asset_status = getattr(inv, "asset_status", None) if inv else "nuevo_dispositivo"
        is_new = asset_status == "nuevo_dispositivo" or (
            bool(first_seen and str(first_seen).startswith(today)) or (inv and (inv.times_seen or 0) <= 1)
        )
        recent_change = False
        if inv and inv.history_json:
            try:
                hist = json.loads(inv.history_json or "[]")
                if len(hist) >= 2 and hist[-1].get("ip") != hist[-2].get("ip"):
                    recent_change = True
            except Exception:
                recent_change = False

        risk = "seguro"
        if asset_status in ("sospechoso", "comprometido", "no_autorizado"):
            risk = "riesgo"
        if asset_status == "comprometido":
            risk = "critico"
        elif asset_status in ("pendiente_aprobacion", "nuevo_dispositivo"):
            risk = "observacion"
        if len(node.get("open_ports") or []) >= 5:
            risk = "riesgo" if risk != "critico" else risk
        cstat = conn_stats.get(ip or "")
        if cstat and cstat.get("connections", 0) >= 25:
            risk = "critico"

        traffic = {
            "bytes_sent": NO_DATA,
            "bytes_recv": NO_DATA,
            "bandwidth_mbps": NO_DATA,
            "usage_percent": NO_DATA,
            "connections_active": cstat.get("connections") if cstat else NO_DATA,
            "source": "psutil.net_connections",
        }

        if ip == local_ip and local_traffic:
            active_conn = NO_DATA
            try:
                active_conn = sum(
                    1 for c in psutil.net_connections(kind="inet") if c.raddr
                )
            except (psutil.AccessDenied, psutil.Error):
                pass
            traffic = {
                "bytes_sent": local_traffic.get("bytes_sent"),
                "bytes_recv": local_traffic.get("bytes_recv"),
                "bandwidth_mbps": bandwidth_mbps if bandwidth_mbps is not None else NO_DATA,
                "usage_percent": NO_DATA,
                "connections_active": active_conn,
                "source": "psutil.net_io_counters",
            }

        confidence = compute_analysis_confidence(node, inv)
        base = {
            **node,
            "device_type": dtype,
            "vendor": node.get("vendor") or NO_DATA,
            "hostname": node.get("name") or NO_DATA,
            "is_new": is_new,
            "recent_change": recent_change,
            "first_seen": inv.first_seen if inv else NO_DATA,
            "last_seen": inv.last_seen if inv else NO_DATA,
            "times_seen": inv.times_seen if inv else NO_DATA,
            "connected_since": inv.first_seen if inv else NO_DATA,
            "risk_level": risk,
            "risk_color": {
                "seguro": "green",
                "observacion": "yellow",
                "riesgo": "orange",
                "critico": "red",
            }.get(risk, "green"),
            "confidence_score": confidence["score"],
            "confidence_label": confidence["label"],
            "os_estimate_short": estimate_os({**node, "device_type": dtype}).get("display"),
            "traffic": traffic,
            "open_ports_count": len(node.get("open_ports") or []),
            "services": node.get("services") or [],
        }
        enriched.append(enrich_node_with_aie(base, inv, meta))

    return enriched


def _aie_payload_summary() -> dict:
    try:
        from services.asset_intelligence_engine import get_inventory_summary
        return get_inventory_summary()
    except Exception as exc:
        logger.debug("aie summary: %s", exc)
        return {}


def build_ndr_payload(force_refresh: bool = False) -> dict:
    """Payload NDR — lectura snapshot; ARP solo vía force_refresh explícito o background."""
    if not force_refresh:
        try:
            from services.network_snapshot_service import read_ndr_api

            return read_ndr_api(trigger_discovery=True)
        except Exception as exc:
            logger.debug("ndr snapshot read fallback: %s", exc)
        return _build_ndr_payload_from_cache(scanning=True)

    return _build_ndr_payload_heavy(force_refresh=True)


def build_ndr_payload_from_cache() -> dict:
    """Construye payload NDR desde caché existente — nunca dispara ARP."""
    return _build_ndr_payload_from_cache(scanning=False)


def _build_ndr_payload_heavy(force_refresh: bool = False) -> dict:
    """Escaneo pesado — solo background o POST force."""
    global _payload_cache
    from services.network_scanner import network_scanner

    if force_refresh:
        network_scanner.scan_network(force=True)
    result = _build_ndr_payload_from_cache(scanning=network_scanner._scanning)
    _payload_cache = {"ts": time.time(), "payload": result}
    return result


def _build_ndr_payload_from_cache(*, scanning: bool = False) -> dict:
    """Ensambla NDR desde nodos en caché — sin scan_arp_light/sync."""
    global _payload_cache
    now = time.time()
    if (
        not scanning
        and _payload_cache.get("payload")
        and (now - (_payload_cache.get("ts") or 0)) < _PAYLOAD_TTL
    ):
        return _payload_cache["payload"]

    from services.network_scanner import network_scanner

    meta = network_scanner.get_network_meta()
    raw_nodes = network_scanner.get_cached_nodes() or []
    _update_presence_tracking(raw_nodes)
    sync_inventory_from_nodes(raw_nodes, meta)
    nodes = enrich_nodes_for_ndr(raw_nodes, meta)
    alerts = analyze_behavior(raw_nodes, meta)
    ts = _now()

    top_traffic = _build_top_traffic(nodes, meta)
    pending = [n for n in nodes if n.get("is_pending_approval")]
    attention = [n for n in nodes if n.get("requires_attention")]
    summary = build_executive_summary(nodes, alerts, meta, ts)

    network_baseline: dict = {}
    try:
        from services.network_baseline_service import compare_to_baseline, update_baseline

        network_baseline = compare_to_baseline(nodes)
        if not network_baseline.get("has_baseline") and nodes:
            snap = update_baseline(nodes)
            network_baseline["initial_baseline_created"] = True
            network_baseline["baseline_at"] = snap.get("updated_at")
            network_baseline["baseline_count"] = snap.get("device_count", 0)
    except Exception as exc:
        logger.debug("network_baseline payload: %s", exc)
        network_baseline = {"verified": False, "error": str(exc)}

    connection_events: List[dict] = []
    try:
        from services.device_connection_monitor import get_recent_connection_summary
        connection_events = get_recent_connection_summary(limit=25)
    except Exception as exc:
        logger.debug("connection_events payload: %s", exc)

    discovery_assessment: dict = {}
    try:
        from utils.network_helpers import assess_discovery_limitations, read_os_arp_neighbors
        from services.network_scan_coordinator import get_bound_context

        ctx = get_bound_context() or {}
        os_neighbors = read_os_arp_neighbors(interface_ip=meta.get("local_ip"))
        discovery_assessment = assess_discovery_limitations(
            scapy_count=len([n for n in raw_nodes if n.get("detection_method") == "arp_scapy"]),
            os_arp_count=len(os_neighbors),
            subnet_cidr=meta.get("network_range"),
            ssid=ctx.get("ssid"),
            connection_type=meta.get("connection_type"),
        )
    except Exception as exc:
        logger.debug("discovery_assessment ndr: %s", exc)

    data_freshness = "live"
    try:
        from services.network_snapshot_service import (
            freshness_from_generated_at,
            observed_device_count_for_freshness,
            _load as _load_nodes_snapshot,
        )

        nodes_snap = _load_nodes_snapshot("nodes")
        gen_at = (nodes_snap or {}).get("generated_at_utc")
        if gen_at:
            data_freshness = freshness_from_generated_at(gen_at)
    except Exception as exc:
        logger.debug("ndr freshness from nodes snapshot: %s", exc)

    observed_count = observed_device_count_for_freshness(data_freshness, len(nodes))
    summary["observed_device_count"] = observed_count

    result = {
        "status": "success" if nodes else ("scanning" if scanning else "no_data"),
        "timestamp": ts,
        "meta": meta,
        "cache": network_scanner.get_cache_info(),
        "nodes": nodes,
        "device_count": len(nodes),
        "observed_device_count": observed_count,
        "data_freshness": data_freshness,
        "message": "Network discovery running in background" if scanning and not nodes else None,
        "pending_devices": pending,
        "pending_count": len(pending),
        "attention_devices": attention,
        "attention_count": len(attention),
        "unknown_devices": attention,
        "unknown_count": len(attention),
        "aie_summary": _aie_payload_summary(),
        "connection_events": connection_events,
        "alerts": alerts,
        "alert_count": len(alerts),
        "top_traffic": top_traffic,
        "executive_summary": summary,
        "network_baseline": network_baseline,
        "motors": _protection_motors_active(),
        "discovery_assessment": discovery_assessment,
    }
    # Aprendizaje en segundo plano (sin exponer baseline en UI NDR)
    try:
        from flask_login import current_user

        email = getattr(current_user, "email", None) if current_user else None
        if email:
            from services.adaptive_profile_engine import observe_async

            observe_async(
                str(email),
                event_type="ndr_tick",
                mechanisms=["network_ndr"],
                source_motor="network_ndr",
                evidence={"device_count": len(nodes), "alert_count": len(alerts)},
                evaluate=True,
            )
    except Exception as exc:
        logger.debug("APE ndr_tick: %s", exc)

    _payload_cache = {"ts": time.time(), "payload": result}
    return result


def get_device_detail(ip: str) -> dict:
    """Detalle enriquecido de un dispositivo para ficha técnica NDR."""
    payload = build_ndr_payload(force_refresh=False)
    for node in payload.get("nodes") or []:
        if node.get("ip") == ip:
            device_alerts = [
                a for a in (payload.get("alerts") or []) if a.get("ip") == ip
            ]
            history = []
            from database import SessionLocal, NetworkDeviceInventory
            db = SessionLocal()
            try:
                inv = db.query(NetworkDeviceInventory).filter(
                    NetworkDeviceInventory.ip == ip
                ).first()
                if not inv:
                    inv = db.query(NetworkDeviceInventory).filter(
                        NetworkDeviceInventory.mac == (node.get("mac") or "").lower()
                    ).first()
                if inv and inv.history_json:
                    history = json.loads(inv.history_json)
            finally:
                db.close()
            vulns = _related_vulns(ip)
            detail = _enrich_device_detail(node, device_alerts, history, vulns)
            return {
                "status": "success",
                "device": detail,
                "alerts": detail.get("alerts") or device_alerts,
                "history": history,
                "vulnerabilities_related": vulns,
                "recommendations": detail.get("recommendations") or [],
            }
    return {
        "status": "not_found",
        "message": (
            f"No se encontró el dispositivo {ip} en el inventario ARP actual. "
            "Ejecute un escaneo ARP para actualizar el radar."
        ),
    }


def _compute_node_risk(node: dict, conn_stats: Optional[dict] = None) -> str:
    """Recalcula nivel de riesgo desde telemetría real del nodo."""
    conn_stats = conn_stats or _connection_stats_by_ip()
    risk = "seguro"
    if node.get("is_unknown"):
        risk = "observacion"
    if len(node.get("open_ports") or []) >= 5:
        risk = "riesgo"
    ip = node.get("ip") or ""
    cstat = conn_stats.get(ip)
    if cstat and cstat.get("connections", 0) >= 25:
        risk = "critico"
    return risk


def _persist_investigation(node: dict, investigation: dict) -> List[dict]:
    """Registra investigación en inventario SQLite y devuelve historial actualizado."""
    from database import SessionLocal, NetworkDeviceInventory

    mac = (node.get("mac") or "").lower()
    ip = node.get("ip")
    if not mac or not ip:
        return investigation.get("history") or []

    ts = _now()
    db = SessionLocal()
    try:
        record = db.query(NetworkDeviceInventory).filter(
            NetworkDeviceInventory.mac == mac
        ).first()
        hist_entry = {
            "time": ts,
            "event": "investigation",
            "ip": ip,
            "hostname": node.get("name") or node.get("hostname"),
            "vendor": node.get("vendor"),
            "device_type": node.get("device_type"),
            "os_estimate": (investigation.get("os_estimate") or {}).get("display")
            if isinstance(investigation.get("os_estimate"), dict)
            else investigation.get("os_estimate"),
            "ports_scanned": len(node.get("open_ports") or []),
            "services_found": len(node.get("services") or []),
            "confidence_score": (investigation.get("confidence") or {}).get("score"),
            "confidence_label": (investigation.get("confidence") or {}).get("label"),
            "risk_level": node.get("risk_level"),
            "response_ms": node.get("response_time_ms"),
        }
        history: List[dict] = []
        if record:
            try:
                history = json.loads(record.history_json or "[]")
            except Exception:
                history = []
            history.append(hist_entry)
            history = history[-50:]
            record.ip = ip
            record.hostname = node.get("name") or record.hostname
            record.vendor = node.get("vendor") or record.vendor
            record.device_type = node.get("device_type") or record.device_type
            record.last_seen = ts
            record.times_seen = (record.times_seen or 0) + 1
            record.is_known = True
            record.risk_level = node.get("risk_level") or record.risk_level
            record.history_json = json.dumps(history, ensure_ascii=False)
            record.last_open_ports_json = json.dumps(
                node.get("open_ports") or [], ensure_ascii=False
            )
        else:
            history = [hist_entry]
            record = NetworkDeviceInventory(
                mac=mac,
                ip=ip,
                hostname=node.get("name"),
                vendor=node.get("vendor"),
                device_type=node.get("device_type"),
                first_seen=ts,
                last_seen=ts,
                times_seen=1,
                is_known=True,
                risk_level=node.get("risk_level") or "observacion",
                history_json=json.dumps(history, ensure_ascii=False),
                last_open_ports_json=json.dumps(
                    node.get("open_ports") or [], ensure_ascii=False
                ),
            )
            db.add(record)
        db.commit()
        from services.network_event_log import network_event_log
        network_event_log.record(
            f"[Topology/NDR] Investigación completada: {ip} — "
            f"{node.get('device_type')} — riesgo {node.get('risk_level')} — "
            f"confianza {(investigation.get('confidence') or {}).get('label', 'N/A')}",
            level="info",
        )
        return history
    except Exception as exc:
        db.rollback()
        logger.error("_persist_investigation: %s", exc)
        return investigation.get("history") or []
    finally:
        db.close()


def invalidate_ndr_cache() -> None:
    """Invalida caché NDR tras re-escaneo forzado."""
    global _payload_cache
    _payload_cache = {"ts": 0.0, "payload": None}


def investigate_device(ip: str) -> dict:
    """Re-análisis profundo de dispositivo desconocido — telemetría real."""
    from utils.network_device_helpers import lookup_mac_vendor

    invalidate_ndr_cache()
    payload = build_ndr_payload(force_refresh=True)
    node = next((n for n in (payload.get("nodes") or []) if n.get("ip") == ip), None)
    if not node:
        return {
            "status": "not_found",
            "message": (
                f"El dispositivo {ip} no está visible en el segmento ARP tras el re-escaneo. "
                "Puede estar desconectado o fuera del rango escaneado."
            ),
        }

    mac = node.get("mac")
    vendor = lookup_mac_vendor(mac) if mac else None
    if vendor and vendor != NO_DATA:
        node["vendor"] = vendor

    try:
        from services.advanced_detector_service import advanced_detector
        ports = advanced_detector.scan_open_ports(ip)
        if ports:
            node["open_ports"] = ports
    except Exception as exc:
        logger.debug("investigate ports: %s", exc)

    dtype = estimate_device_type(node, (payload.get("meta") or {}).get("gateway"))
    node["device_type"] = dtype
    os_info = estimate_os(node)
    if ports:
        node["services"] = [
            {"port": p.get("port"), "service": p.get("service") or f"TCP/{p.get('port')}"}
            for p in ports
        ]

    from database import SessionLocal, NetworkDeviceInventory
    db = SessionLocal()
    inv = None
    try:
        inv = db.query(NetworkDeviceInventory).filter(
            NetworkDeviceInventory.mac == (mac or "").lower()
        ).first()
    finally:
        db.close()

    node["risk_level"] = _compute_node_risk(node)
    confidence = compute_analysis_confidence(node, inv)
    from services.asset_intelligence_engine import enrich_node_with_aie
    node = enrich_node_with_aie(node, inv, payload.get("meta"))

    kernel_insight = None
    try:
        kernel_insight = answer_kernel_query(f"dispositivo {ip} MAC {mac}")
    except Exception:
        pass

    history: List[dict] = []
    vulns = _related_vulns(ip)
    device_alerts = [a for a in (payload.get("alerts") or []) if a.get("ip") == ip]
    investigation_stub = {
        "os_estimate": os_info,
        "confidence": confidence,
        "history": history,
    }
    history = _persist_investigation(node, investigation_stub)
    detail = _enrich_device_detail(node, device_alerts, history, vulns)
    return {
        "status": "success",
        "ip": ip,
        "investigation_time": _now(),
        "vendor": _field(vendor if vendor and vendor != NO_DATA else None, "generic"),
        "device_type": _field(dtype, "generic"),
        "os_estimate": os_info,
        "confidence": confidence,
        "risk_level": node.get("risk_level"),
        "open_ports": node.get("open_ports") or [],
        "services": node.get("services") or [],
        "kernel_insight": kernel_insight or "Consulte el Kernel IA para análisis contextual del dispositivo.",
        "device": detail,
        "history": history,
        "recommendations": detail.get("recommendations") or [],
        "message": (
            f"Investigación completada para {ip}: "
            f"{dtype}, riesgo {node.get('risk_level')}, "
            f"confianza {confidence.get('label')} ({confidence.get('score')}%)."
        ),
    }


def enrich_events_with_explanations(events: List[dict]) -> List[dict]:
    return [
        {
            **ev,
            "plain_explanation": explain_network_event(ev.get("message"), ev.get("level")),
        }
        for ev in events
    ]


_vulns_cache: Dict[str, Any] = {"ts": 0.0, "by_ip": {}}
_VULNS_TTL = 60.0


def _related_vulns(ip: str) -> List[dict]:
    now = time.time()
    if (now - _vulns_cache.get("ts", 0)) < _VULNS_TTL and ip in _vulns_cache.get("by_ip", {}):
        return _vulns_cache["by_ip"][ip]
    try:
        from services.novus_security_integration import novus_security
        vulns = novus_security.scan_vulnerabilities() or []
        by_ip: Dict[str, List[dict]] = defaultdict(list)
        for v in vulns:
            vip = str(v.get("ip") or "")
            if vip:
                by_ip[vip].append(v)
        _vulns_cache["ts"] = now
        _vulns_cache["by_ip"] = {k: vals[:10] for k, vals in by_ip.items()}
        return _vulns_cache["by_ip"].get(ip, [])[:10]
    except Exception:
        return []


def answer_kernel_query(question: str) -> Optional[str]:
    """Respuestas del Kernel IA exclusivamente desde datos NDR."""
    q = (question or "").lower()
    payload = build_ndr_payload(force_refresh=False)
    nodes = payload.get("nodes") or []
    unknown = payload.get("unknown_devices") or []
    alerts = payload.get("alerts") or []
    top = payload.get("top_traffic") or []

    if any(k in q for k in ("ancho de banda", "consume más", "más tráfico", "más trafico")):
        if not top:
            return "Sin datos disponibles de consumo por dispositivo. Solo el host local reporta bytes vía psutil."
        lines = [
            f"• {t.get('ip')} ({t.get('name')}): {t.get('metric')} {t.get('metric_label')}"
            for t in top[:5]
        ]
        return "Top dispositivos por actividad medida:\n" + "\n".join(lines)

    if any(k in q for k in ("desconocido", "unknown", "nuevo")):
        if not unknown:
            return "No hay dispositivos desconocidos en el inventario ARP actual."
        lines = [
            f"• {u.get('ip')} MAC {u.get('mac')} — visto {u.get('times_seen')} vez/veces"
            for u in unknown[:10]
        ]
        return f"{len(unknown)} dispositivo(s) desconocido(s):\n" + "\n".join(lines)

    if any(k in q for k in ("sospech", "anomal", "alerta")):
        if not alerts:
            return "No hay actividad sospechosa con evidencia verificable en este momento."
        lines = [
            f"• [{a.get('confidence')}] {a.get('title')} — {a.get('evidence')}"
            for a in alerts[:8]
        ]
        return f"{len(alerts)} alerta(s) NDR:\n" + "\n".join(lines)

    if any(k in q for k in ("apareció hoy", "aparecio hoy", "equipo apareció", "nuevo dispositivo")):
        today = datetime.now().strftime("%Y-%m-%d")
        new_today = [
            n for n in nodes
            if str(n.get("first_seen") or "").startswith(today)
        ]
        if not new_today:
            return "Ningún dispositivo nuevo registrado hoy en el inventario ARP."
        lines = [f"• {n.get('ip')} ({n.get('device_type')}) — {n.get('first_seen')}" for n in new_today]
        return "Dispositivos vistos por primera vez hoy:\n" + "\n".join(lines)

    if any(k in q for k in ("más conexiones", "mas conexiones", "abrió más", "abrio mas", "abrió mas")):
        ranked = sorted(
            [n for n in nodes if isinstance(n.get("traffic", {}).get("connections_active"), int)],
            key=lambda n: n["traffic"]["connections_active"],
            reverse=True,
        )
        if not ranked:
            return "Sin datos disponibles de conexiones por dispositivo remoto."
        n = ranked[0]
        return (
            f"Mayor actividad de conexiones: {n.get('ip')} "
            f"({n['traffic']['connections_active']} conexiones activas medidas por psutil)."
        )

    if any(k in q for k in ("mayor riesgo", "más riesgo", "mas riesgo")):
        order = {"critico": 4, "riesgo": 3, "observacion": 2, "seguro": 1}
        ranked = sorted(nodes, key=lambda n: order.get(n.get("risk_level"), 0), reverse=True)
        if not ranked:
            return NO_DATA
        n = ranked[0]
        return (
            f"Dispositivo con mayor riesgo NDR: {n.get('ip')} "
            f"({n.get('risk_level')}) — {n.get('device_type')} — {n.get('known_label')}"
        )

    return None
