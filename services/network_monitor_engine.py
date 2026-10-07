"""
Network Monitor Engine — monitoreo continuo de red en segundo plano mientras NOVUS está activo.
Telemetría real únicamente (ARP, psutil, inventario AIE). Sin eventos simulados.
"""
from __future__ import annotations

import os
import random
import threading
import time
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Set

import psutil

from utils.logger import logger

MODE_NORMAL = "normal"
MODE_INTENSIVE = "intensive"

_lock = threading.Lock()
_state: Dict[str, Any] = {
    "active": False,
    "mode": MODE_NORMAL,
    "started_at": None,
    "last_scan_at": None,
    "next_scan_at": None,
    "last_scan_duration_ms": None,
    "changes_today": 0,
    "changes_day": None,
    "stable_cycles": 0,
    "revision": 0,
    "devices_monitored": 0,
    "devices_authorized": 0,
    "devices_pending": 0,
    "cpu_percent": None,
    "memory_mb": None,
    "avg_cpu_percent": None,
    "avg_memory_mb": None,
    "avg_connect_detection_sec": None,
    "avg_disconnect_detection_sec": None,
    "last_change_at": None,
    "scan_count": 0,
    "error_count": 0,
    "last_error": None,
}

_prev_nodes_by_mac: Dict[str, dict] = {}
_prev_ports_by_ip: Dict[str, List[int]] = {}
_prev_traffic_by_ip: Dict[str, int] = {}
_prev_gateway: Optional[str] = None
_prev_wifi_ctx: Dict[str, Optional[str]] = {
    "ssid": None,
    "bssid": None,
    "subnet": None,
    "local_ip": None,
    "adapter": None,
}
_cpu_samples: List[float] = []
_mem_samples: List[float] = []
_connect_detection_samples: List[float] = []
_disconnect_detection_samples: List[float] = []
_last_cycle_interval: float = 3.0

_thread: Optional[threading.Thread] = None
_running = False
_cycle_running = False
_last_full_port_scan = 0.0


def _cfg() -> dict:
    from services.network_monitor_config import get_network_monitor_config
    return get_network_monitor_config()


def _now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _bump_change() -> None:
    global _state
    today = date.today().isoformat()
    with _lock:
        if _state.get("changes_day") != today:
            _state["changes_day"] = today
            _state["changes_today"] = 0
        _state["changes_today"] = int(_state.get("changes_today") or 0) + 1
        _state["last_change_at"] = _now_iso()
        _state["revision"] = int(_state.get("revision") or 0) + 1
        _state["stable_cycles"] = 0


def _enter_intensive() -> None:
    with _lock:
        _state["mode"] = MODE_INTENSIVE
        _state["stable_cycles"] = 0


def _maybe_exit_intensive() -> None:
    cfg = _cfg()
    with _lock:
        _state["stable_cycles"] = int(_state.get("stable_cycles") or 0) + 1
        if (
            _state.get("mode") == MODE_INTENSIVE
            and _state["stable_cycles"] >= cfg.get("intensive_stable_cycles", 5)
        ):
            _state["mode"] = MODE_NORMAL
            logger.info("Network Monitor Engine: regreso a modo normal")


def _next_interval_sec() -> float:
    cfg = _cfg()
    with _lock:
        mode = _state.get("mode") or MODE_NORMAL
    if mode == MODE_INTENSIVE:
        return float(cfg.get("intensive_interval_sec", 1))
    lo = float(cfg.get("normal_interval_min_sec", 2))
    hi = float(cfg.get("normal_interval_max_sec", 5))
    return random.uniform(lo, hi)


def _inventory_counts() -> Dict[str, int]:
    try:
        from database import SessionLocal, NetworkDeviceInventory
        db = SessionLocal()
        try:
            rows = db.query(NetworkDeviceInventory).all()
            monitored = len(rows)
            authorized = sum(1 for r in rows if (r.asset_status or "") == "autorizado")
            pending = sum(
                1 for r in rows
                if (r.asset_status or "pendiente_aprobacion") in ("pendiente_aprobacion", "nuevo_dispositivo")
            )
            return {
                "devices_monitored": monitored,
                "devices_authorized": authorized,
                "devices_pending": pending,
            }
        finally:
            db.close()
    except Exception as exc:
        logger.debug("inventory_counts: %s", exc)
    return {"devices_monitored": 0, "devices_authorized": 0, "devices_pending": 0}


def _update_resource_metrics(process: psutil.Process) -> None:
    global _cpu_samples, _mem_samples
    try:
        cpu = process.cpu_percent(interval=None)
        mem_mb = process.memory_info().rss / (1024 * 1024)
    except Exception:
        cpu = None
        mem_mb = None
    with _lock:
        _state["cpu_percent"] = round(cpu, 2) if cpu is not None else None
        _state["memory_mb"] = round(mem_mb, 1) if mem_mb is not None else None
    if cpu is not None:
        _cpu_samples.append(cpu)
        _cpu_samples = _cpu_samples[-120:]
    if mem_mb is not None:
        _mem_samples.append(mem_mb)
        _mem_samples = _mem_samples[-120:]
    with _lock:
        if _cpu_samples:
            _state["avg_cpu_percent"] = round(sum(_cpu_samples) / len(_cpu_samples), 2)
        if _mem_samples:
            _state["avg_memory_mb"] = round(sum(_mem_samples) / len(_mem_samples), 1)


def _invalidate_derived_caches() -> None:
    """Invalida capas derivadas (NDR/topología) sin borrar nodos ARP recién escaneados."""
    try:
        from services.network_ndr_service import invalidate_ndr_cache
        invalidate_ndr_cache()
    except Exception as exc:
        logger.debug("invalidate ndr: %s", exc)
    try:
        from services.performance_cache import invalidate
        invalidate("topology_payload")
        invalidate("network_nodes")
    except Exception as exc:
        logger.debug("invalidate topology: %s", exc)


def _invalidate_caches() -> None:
    """Invalidación completa — reservada para cambio de contexto de red."""
    global _prev_nodes_by_mac, _prev_ports_by_ip, _prev_traffic_by_ip
    _invalidate_derived_caches()
    try:
        from services.network_scanner import network_scanner
        network_scanner.clear_cache()
    except Exception as exc:
        logger.debug("invalidate network_scanner: %s", exc)
    _prev_nodes_by_mac = {}
    _prev_ports_by_ip = {}
    _prev_traffic_by_ip = {}


def _node_meta(node: dict, inv=None) -> dict:
    return {
        "ip": node.get("ip"),
        "mac": (node.get("mac") or "").lower(),
        "hostname": node.get("name") or node.get("hostname"),
        "vendor": node.get("vendor"),
        "device_type": node.get("device_type"),
        "asset_status": getattr(inv, "asset_status", None) if inv else node.get("asset_status"),
        "trust_score": getattr(inv, "trust_score", None) if inv else node.get("trust_score"),
        "risk_level": getattr(inv, "risk_level", None) if inv else node.get("risk_level"),
    }


def _detect_and_handle_changes(nodes: List[dict], meta: dict) -> bool:
    """Compara snapshot anterior; registra eventos reales. Retorna True si hubo cambio relevante."""
    global _prev_nodes_by_mac, _prev_ports_by_ip, _prev_traffic_by_ip, _prev_gateway
    global _connect_detection_samples, _disconnect_detection_samples

    from services.device_connection_monitor import process_scan_presence, record_monitor_event

    cfg = _cfg()
    changed = False
    previous_macs = set(_prev_nodes_by_mac.keys())
    current_macs = {(n.get("mac") or "").lower() for n in nodes if n.get("mac")}
    nodes_by_mac = {(n.get("mac") or "").lower(): n for n in nodes if n.get("mac")}

    presence = process_scan_presence(nodes)
    if any(presence.get(k, 0) for k in ("connected", "disconnected", "ip_changes", "hostname_changes")):
        changed = True
        if presence.get("connected"):
            _connect_detection_samples.append(_last_cycle_interval)
            _connect_detection_samples = _connect_detection_samples[-50:]
        if presence.get("disconnected"):
            _disconnect_detection_samples.append(_last_cycle_interval)
            _disconnect_detection_samples = _disconnect_detection_samples[-50:]

    for mac in current_macs & previous_macs:
        prev = _prev_nodes_by_mac.get(mac) or {}
        cur = nodes_by_mac.get(mac) or {}
        if prev.get("name") and cur.get("name") and prev.get("name") != cur.get("name"):
            changed = True

    # Puertos — solo comparar cuando hay datos escaneados
    for node in nodes:
        ip = node.get("ip")
        if not ip:
            continue
        ports = sorted(int(p.get("port")) for p in (node.get("open_ports") or []) if p.get("port"))
        prev_ports = _prev_ports_by_ip.get(ip)
        if prev_ports is not None and ports != prev_ports:
            new_ports = sorted(set(ports) - set(prev_ports))
            if new_ports:
                changed = True
                record_monitor_event(
                    "port_change",
                    _node_meta(node),
                    extra={"previous_ports": prev_ports, "new_ports": new_ports, "verified": True},
                )
        if ports:
            _prev_ports_by_ip[ip] = ports

    # Tráfico / conexiones activas hacia IPs del segmento
    try:
        from services.network_ndr_service import _connection_stats_by_ip
        conn_stats = _connection_stats_by_ip()
        threshold = int(cfg.get("traffic_change_threshold_connections", 15))
        pct_threshold = float(cfg.get("traffic_change_threshold_percent", 25))
        for node in nodes:
            ip = node.get("ip")
            if not ip:
                continue
            cstat = conn_stats.get(ip) or {}
            cur_conn = int(cstat.get("connections") or 0)
            prev_conn = _prev_traffic_by_ip.get(ip)
            if prev_conn is not None:
                delta = abs(cur_conn - prev_conn)
                pct = (delta / max(prev_conn, 1)) * 100
                if delta >= threshold or pct >= pct_threshold:
                    changed = True
                    record_monitor_event(
                        "traffic_change",
                        _node_meta(node),
                        extra={
                            "previous_connections": prev_conn,
                            "current_connections": cur_conn,
                            "verified": True,
                            "source": "psutil.net_connections",
                        },
                    )
            _prev_traffic_by_ip[ip] = cur_conn
    except Exception as exc:
        logger.debug("traffic compare: %s", exc)

    gateway = (meta or {}).get("gateway")
    if _prev_gateway and gateway and gateway != _prev_gateway:
        changed = True
        record_monitor_event(
            "infrastructure_change",
            {"ip": gateway, "mac": None, "hostname": "gateway"},
            extra={"previous_gateway": _prev_gateway, "new_gateway": gateway, "verified": True},
        )
    if gateway:
        _prev_gateway = gateway

    wifi_ssid = wifi_bssid = None
    try:
        from utils.network_identity import get_wifi_association
        wifi = get_wifi_association()
        wifi_ssid = wifi.get("ssid")
        wifi_bssid = wifi.get("bssid")
    except Exception as exc:
        logger.debug("wifi association probe: %s", exc)

    ctx_checks = [
        ("ssid", wifi_ssid),
        ("bssid", wifi_bssid),
        ("subnet", (meta or {}).get("network_range")),
        ("local_ip", (meta or {}).get("local_ip")),
        ("adapter", (meta or {}).get("adapter")),
    ]
    for key, current in ctx_checks:
        previous = _prev_wifi_ctx.get(key)
        if previous and current and str(current) != str(previous):
            changed = True
            record_monitor_event(
                "wifi_context_change" if key in ("ssid", "bssid") else "network_context_change",
                {"ip": (meta or {}).get("local_ip"), "mac": None, "hostname": key},
                extra={
                    "field": key,
                    "previous": previous,
                    "current": current,
                    "verified": True,
                    "source": "network_monitor_engine",
                },
            )
        if current:
            _prev_wifi_ctx[key] = str(current)

    _prev_nodes_by_mac = {m: dict(nodes_by_mac[m]) for m in current_macs}

    if changed:
        _bump_change()
        _enter_intensive()
        try:
            from services.network_endpoint_enterprise.publish import publish_event

            publish_event(
                motor="network_monitor_engine",
                action="network_topology_change",
                evidence={
                    "verified": True,
                    "gateway": (meta or {}).get("gateway"),
                    "local_ip": (meta or {}).get("local_ip"),
                    "devices": len(nodes),
                    "presence": presence,
                },
                threat_type="network_change",
                confidence="medium",
                detail="NME detected real ARP/topology change",
                finding_id=f"NME-CHG-{int(time.time())}",
                feed_ape=True,
                risk_level="medium",
            )
        except Exception as exc:
            logger.debug("nme swarm publish: %s", exc)
    return changed


def _intensive_analysis(nodes: List[dict], affected_ips: Optional[List[str]] = None) -> None:
    """Análisis profundo en modo intensivo — puertos y AIE en dispositivos afectados."""
    if not affected_ips:
        return
    from services.network_scanner import network_scanner
    from services.network_ndr_service import analyze_behavior

    meta = network_scanner.get_network_meta()
    for ip in affected_ips[:6]:
        if ip:
            network_scanner.enrich_node_ports(ip)

    alerts = analyze_behavior(network_scanner.get_cached_nodes(), meta)
    for alert in alerts:
        if alert.get("level") in ("riesgo", "critico", "alerta"):
            try:
                from services.network_event_log import network_event_log
                network_event_log.record(
                    f"[NME] {alert.get('title', 'Anomalía')}: {alert.get('evidence', '')[:120]}",
                    level="alert",
                )
            except Exception:
                pass


def _monitor_cycle() -> None:
    global _running, _last_full_port_scan, _last_cycle_interval, _cycle_running
    from services.network_scanner import network_scanner
    from services.network_ndr_service import sync_inventory_from_nodes

    if not _running or _cycle_running:
        return
    _cycle_running = True
    cycle_start = time.time()
    process = psutil.Process()
    changed = False
    try:
        process.cpu_percent(interval=None)
        nodes = network_scanner.scan_arp_light()
        meta = network_scanner.get_network_meta()
        changed = _detect_and_handle_changes(nodes, meta)

        sync_inventory_from_nodes(nodes, meta)

        try:
            from services.network_snapshot_service import _in_boot_grace

            in_grace = _in_boot_grace()
        except Exception:
            in_grace = False

        if changed and not in_grace:
            affected = [n.get("ip") for n in nodes if n.get("ip")]
            _intensive_analysis(nodes, affected[:6])

        cfg = _cfg()
        now = time.time()
        port_enrich = os.environ.get("NOVUS_ENABLE_PORT_ENRICHMENT", "").strip().lower() in (
            "1", "true", "yes", "on",
        )
        if (
            port_enrich
            and not in_grace
            and now - _last_full_port_scan >= float(cfg.get("full_port_rescan_sec", 300))
        ):
            network_scanner.enrich_all_ports()
            sync_inventory_from_nodes(network_scanner.get_cached_nodes(), meta)
            _last_full_port_scan = now

        if not changed:
            _maybe_exit_intensive()

        if changed:
            _invalidate_derived_caches()
        try:
            from services.network_snapshot_service import persist_after_discovery

            persist_after_discovery()
        except Exception as exc:
            logger.debug("NME snapshot persist: %s", exc)
    except Exception as exc:
        logger.error("Network Monitor cycle error: %s", exc, exc_info=True)
        with _lock:
            _state["error_count"] = int(_state.get("error_count") or 0) + 1
            _state["last_error"] = str(exc)[:200]
    finally:
        try:
            counts = _inventory_counts()
            duration_ms = int((time.time() - cycle_start) * 1000)
            interval = _next_interval_sec()
            _last_cycle_interval = interval
            next_at = time.time() + interval
            _update_resource_metrics(process)
            with _lock:
                _state["last_scan_at"] = _now_iso()
                _state["next_scan_at"] = datetime.fromtimestamp(next_at).strftime("%Y-%m-%d %H:%M:%S")
                _state["next_scan_in_sec"] = round(interval, 2)
                _state["last_scan_duration_ms"] = duration_ms
                _state["devices_monitored"] = counts["devices_monitored"] or len(
                    network_scanner.get_cached_nodes() or []
                )
                _state["devices_authorized"] = counts["devices_authorized"]
                _state["devices_pending"] = counts["devices_pending"]
                _state["scan_count"] = int(_state.get("scan_count") or 0) + 1
                if _connect_detection_samples:
                    _state["avg_connect_detection_sec"] = round(
                        sum(_connect_detection_samples) / len(_connect_detection_samples), 2
                    )
                if _disconnect_detection_samples:
                    _state["avg_disconnect_detection_sec"] = round(
                        sum(_disconnect_detection_samples) / len(_disconnect_detection_samples), 2
                    )
            sleep_sec = max(0.05, next_at - time.time())
            time.sleep(sleep_sec)
        finally:
            _cycle_running = False


def _run_loop() -> None:
    global _running
    logger.info("Network Monitor Engine: bucle iniciado — esperando boot de red")
    while _running:
        try:
            from services.network_snapshot_service import is_network_boot_ready

            if not is_network_boot_ready():
                time.sleep(2)
                continue
        except Exception:
            time.sleep(2)
            continue
        _monitor_cycle()
    logger.info("Network Monitor Engine: bucle detenido")


def get_monitor_status() -> Dict[str, Any]:
    """Estado en tiempo real para UI y API."""
    with _lock:
        st = dict(_state)
    started = st.get("started_at")
    uptime_sec = None
    if started:
        try:
            t0 = datetime.strptime(started, "%Y-%m-%d %H:%M:%S")
            uptime_sec = int((datetime.now() - t0).total_seconds())
        except ValueError:
            pass
    last_scan = st.get("last_scan_at")
    seconds_since_scan = None
    if last_scan:
        try:
            t1 = datetime.strptime(last_scan, "%Y-%m-%d %H:%M:%S")
            seconds_since_scan = max(0, int((datetime.now() - t1).total_seconds()))
        except ValueError:
            pass
    next_in = st.get("next_scan_in_sec")
    mode = st.get("mode") or MODE_NORMAL
    return {
        "engine": "network_monitor_engine",
        "status": "activo" if st.get("active") else "inactivo",
        "active": bool(st.get("active")),
        "mode": mode,
        "mode_label": "Vigilancia Intensiva" if mode == MODE_INTENSIVE else "Normal",
        "last_scan_at": last_scan,
        "seconds_since_last_scan": seconds_since_scan,
        "last_scan_label": f"Hace {seconds_since_scan}s" if seconds_since_scan is not None else "—",
        "next_scan_at": st.get("next_scan_at"),
        "next_scan_in_sec": next_in,
        "next_scan_label": f"En {int(next_in)}s" if next_in is not None else "—",
        "devices_monitored": st.get("devices_monitored") or 0,
        "devices_authorized": st.get("devices_authorized") or 0,
        "devices_pending": st.get("devices_pending") or 0,
        "changes_today": st.get("changes_today") or 0,
        "uptime_sec": uptime_sec,
        "uptime_label": _format_uptime(uptime_sec),
        "cpu_percent": st.get("cpu_percent"),
        "memory_mb": st.get("memory_mb"),
        "avg_cpu_percent": st.get("avg_cpu_percent"),
        "avg_memory_mb": st.get("avg_memory_mb"),
        "avg_connect_detection_sec": st.get("avg_connect_detection_sec"),
        "avg_disconnect_detection_sec": st.get("avg_disconnect_detection_sec"),
        "revision": st.get("revision") or 0,
        "scan_count": st.get("scan_count") or 0,
        "last_scan_duration_ms": st.get("last_scan_duration_ms"),
        "error_count": st.get("error_count") or 0,
        "config": _cfg(),
    }


def _format_uptime(sec: Optional[int]) -> str:
    if sec is None:
        return "—"
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def start_network_monitor_engine() -> None:
    """Inicia el motor de monitoreo continuo (daemon)."""
    global _thread, _running, _state
    with _lock:
        if _state.get("active"):
            return
        _running = True
        _state["active"] = True
        _state["started_at"] = _now_iso()
        _state["mode"] = MODE_NORMAL
        _state["changes_day"] = date.today().isoformat()
        _state["changes_today"] = 0
        global _last_full_port_scan
        _last_full_port_scan = time.time()

    _thread = threading.Thread(target=_run_loop, daemon=True, name="NetworkMonitorEngine")
    _thread.start()
    logger.info("Network Monitor Engine iniciado (monitoreo continuo en segundo plano)")


def stop_network_monitor_engine() -> None:
    global _running, _state
    _running = False
    with _lock:
        _state["active"] = False


class NetworkMonitorEngine:
    start = staticmethod(start_network_monitor_engine)
    stop = staticmethod(stop_network_monitor_engine)
    get_status = staticmethod(get_monitor_status)


network_monitor = NetworkMonitorEngine()
