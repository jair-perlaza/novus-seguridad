"""
Network Scanner Service for NOVUS
Optimized ARP scanning with thread-safe caching
"""
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import scapy.all as scapy
from utils.network_helpers import get_network_range, get_hostname_by_ip, read_os_arp_neighbors
from utils.network_device_helpers import measure_response_time_ms, lookup_mac_vendor
from services.network_event_log import network_event_log
from utils.host_data import get_primary_network_interface
from utils.logger import logger
from core.config import Config


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class NetworkScanner:
    """
    Thread-safe network scanner with caching
    Prevents duplicate scans and optimizes resource usage
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        self._cache = {
            "nodes": [],
            "last_scan": None,
            "active_threats": None,
        }
        self._scan_lock = threading.Lock()
        self._scanning = False
        self._last_scan_time = 0
        self._network_meta = {
            "gateway": None,
            "network_range": None,
            "local_ip": None,
            "netmask": None,
            "adapter": None,
            "mac": None,
            "connection_type": None,
            "speed_mbps": None,
        }
    
    def scan_arp_light(self) -> list:
        """
        Escaneo ARP ligero para Network Monitor Engine — sin puertos, sin intervalo mínimo.
        Preserva open_ports/services en caché para MACs ya conocidas.
        """
        from services.network_scan_coordinator import coordinated_scan, invalidate_on_context_change

        invalidate_on_context_change(force_clear_scanner=True)

        if self._scanning:
            return list(self._cache.get("nodes") or [])

        def _run() -> list:
            return self._scan_arp_light_inner()

        nodes, _meta = coordinated_scan(_run, consumer="network_monitor_engine", mode="arp_light")
        return nodes

    def _scan_arp_light_inner(self) -> list:
        if self._scanning:
            return list(self._cache.get("nodes") or [])

        with self._scan_lock:
            if self._scanning:
                return list(self._cache.get("nodes") or [])
            self._scanning = True

        try:
            from utils.host_data import get_local_ip
            from utils.network_helpers import get_default_gateway, get_network_range

            primary_iface = get_primary_network_interface()
            gateway = get_default_gateway()
            netmask = (primary_iface or {}).get("netmask")
            local_ip = (primary_iface or {}).get("local_ip") or get_local_ip()
            network_range = get_network_range(gateway=gateway, local_ip=local_ip, netmask=netmask)
            self._network_meta = {
                "gateway": gateway,
                "network_range": network_range,
                "local_ip": local_ip,
                "netmask": netmask,
                "adapter": (primary_iface or {}).get("adapter"),
                "mac": (primary_iface or {}).get("mac"),
                "connection_type": (primary_iface or {}).get("connection_type"),
                "speed_mbps": (primary_iface or {}).get("speed_mbps"),
            }
            prev_by_mac = {
                (n.get("mac") or "").lower(): n
                for n in (self._cache.get("nodes") or [])
                if n.get("mac")
            }
            prev_by_ip = {n.get("ip"): n for n in (self._cache.get("nodes") or []) if n.get("ip")}
            nodes = self._perform_arp_scan(light=True)
            for node in nodes:
                ip = node.get("ip")
                prev = prev_by_ip.get(ip) or prev_by_mac.get((node.get("mac") or "").lower())
                node["first_seen_utc"] = (prev or {}).get("first_seen_utc") or _utc_iso()
                node["last_seen_utc"] = _utc_iso()
                node.setdefault("detection_method", "arp_scapy")
                node.setdefault("data_origin", "live_discovery")
                node["interface"] = self._network_meta.get("adapter")
                mac = (node.get("mac") or "").lower()
                prev = prev_by_mac.get(mac)
                if prev:
                    node["open_ports"] = prev.get("open_ports") or []
                    node["services"] = prev.get("services") or []
                else:
                    node.setdefault("open_ports", [])
                    node.setdefault("services", [])
            with self._scan_lock:
                self._cache["nodes"] = nodes
                self._cache["last_scan"] = datetime.now().strftime("%H:%M:%S")
                self._last_scan_time = time.time()
            return nodes
        except Exception as exc:
            logger.error("scan_arp_light failed: %s", exc, exc_info=True)
            return list(self._cache.get("nodes") or [])
        finally:
            with self._scan_lock:
                self._scanning = False

    def enrich_node_ports(self, ip: str) -> Optional[dict]:
        """Escaneo de puertos para un solo host — usado en modo intensivo."""
        nodes = self._cache.get("nodes") or []
        target = next((n for n in nodes if n.get("ip") == ip), None)
        if not target:
            return None
        try:
            from services.advanced_detector_service import advanced_detector
            open_ports = advanced_detector.scan_open_ports(ip)
            target["open_ports"] = open_ports
            target["services"] = [p.get("service") for p in open_ports if p.get("service")]
            if open_ports:
                ports_label = ", ".join(str(p.get("port")) for p in open_ports)
                network_event_log.record(
                    f"Puertos abiertos detectados en {ip}: {ports_label}"
                )
            return target
        except Exception as exc:
            logger.debug("enrich_node_ports %s: %s", ip, exc)
            return target

    def enrich_all_ports(self) -> None:
        """Re-escaneo completo de puertos (ciclo lento)."""
        nodes = self._cache.get("nodes") or []
        if nodes:
            self._enrich_nodes_with_port_scan(nodes)
            self._cache["nodes"] = nodes

    def scan_network(self, force=False):
        """
        Perform ARP scan with duplicate prevention
        Args:
            force: Force scan even if recently scanned
        Returns:
            List of discovered nodes
        """
        from services.network_scan_coordinator import coordinated_scan, invalidate_on_context_change

        invalidate_on_context_change(force_clear_scanner=True)

        if self._scanning:
            logger.info("Scan already in progress, returning cached results")
            return self._cache["nodes"]

        def _run() -> list:
            return self._scan_network_inner(force=force)

        consumer = "api_force" if force else "scan_network"
        nodes, _meta = coordinated_scan(_run, consumer=consumer, mode="full", force=force)
        return nodes

    def _scan_network_inner(self, force=False):
        current_time = time.time()
        scan_interval = Config.NETWORK_SCAN_INTERVAL
        force_min_interval = max(1, int(getattr(Config, "NETWORK_FORCE_SCAN_MIN_INTERVAL", 15)))
        force_full_enrich_interval = max(
            force_min_interval,
            int(getattr(Config, "NETWORK_FORCE_FULL_ENRICH_INTERVAL", 90)),
        )
        elapsed = current_time - self._last_scan_time
        
        # Check if scan is needed
        if not force and elapsed < scan_interval:
            logger.info(f"Using cached scan results (last scan: {elapsed:.1f}s ago)")
            return self._cache["nodes"]

        # Forced scans are still deduplicated to prevent scan storms across engines.
        if force and elapsed < force_min_interval:
            logger.info(
                "Forced scan skipped (%.1fs < min %ss) — reusing cache",
                elapsed,
                force_min_interval,
            )
            return self._cache["nodes"]
        
        # Prevent concurrent scans
        if self._scanning:
            logger.info("Scan already in progress, returning cached results")
            return self._cache["nodes"]
        
        with self._scan_lock:
            if self._scanning:
                return self._cache["nodes"]
            
            self._scanning = True
            try:
                logger.info("Starting network scan...")
                network_event_log.record("Escaneo de red iniciado")
                from utils.host_data import get_local_ip
                from utils.network_helpers import get_default_gateway, get_network_range

                primary_iface = get_primary_network_interface()
                gateway = get_default_gateway()
                netmask = (primary_iface or {}).get("netmask")
                local_ip = (primary_iface or {}).get("local_ip") or get_local_ip()
                network_range = get_network_range(gateway=gateway, local_ip=local_ip, netmask=netmask)
                self._network_meta = {
                    "gateway": gateway,
                    "network_range": network_range,
                    "local_ip": local_ip,
                    "netmask": netmask,
                    "adapter": (primary_iface or {}).get("adapter"),
                    "mac": (primary_iface or {}).get("mac"),
                    "connection_type": (primary_iface or {}).get("connection_type"),
                    "speed_mbps": (primary_iface or {}).get("speed_mbps"),
                }
                quick_forced = bool(force and elapsed < force_full_enrich_interval)
                prev_by_mac = {
                    (n.get("mac") or "").lower(): n
                    for n in (self._cache.get("nodes") or [])
                    if n.get("mac")
                }
                prev_by_ip = {n.get("ip"): n for n in (self._cache.get("nodes") or []) if n.get("ip")}

                nodes = self._perform_arp_scan(light=quick_forced)
                for node in nodes:
                    ip = node.get("ip")
                    prev = prev_by_ip.get(ip) or prev_by_mac.get((node.get("mac") or "").lower())
                    node["first_seen_utc"] = (prev or {}).get("first_seen_utc") or _utc_iso()
                    node["last_seen_utc"] = _utc_iso()
                    node.setdefault("detection_method", "arp_scapy")
                    node.setdefault("data_origin", "live_discovery")
                    node["interface"] = self._network_meta.get("adapter")
                self._cache["nodes"] = nodes
                self._cache["last_scan"] = datetime.now().strftime("%H:%M:%S")
                if quick_forced:
                    # Keep last known port/service data for quick forced ARP cycles.
                    for node in nodes:
                        prev = prev_by_mac.get((node.get("mac") or "").lower())
                        if prev:
                            node["open_ports"] = prev.get("open_ports") or []
                            node["services"] = prev.get("services") or []
                        else:
                            node.setdefault("open_ports", [])
                            node.setdefault("services", [])
                else:
                    nodes = self._enrich_nodes_with_port_scan(nodes)
                
                # Update cache
                self._cache["nodes"] = nodes
                self._cache["last_scan"] = datetime.now().strftime("%H:%M:%S")
                try:
                    from services.novus_security_integration import novus_security
                    threat_count = novus_security.get_cached_threat_count()
                    self._cache["active_threats"] = (
                        threat_count if threat_count is not None else None
                    )
                except Exception:
                    self._cache["active_threats"] = None
                self._last_scan_time = current_time
                
                logger.info(
                    "Scan complete: %s devices found (mode=%s)",
                    len(nodes),
                    "quick_forced" if quick_forced else "full",
                )
                network_event_log.record(
                    f"Escaneo finalizado: {len(nodes)} dispositivo(s) detectado(s)"
                )
                try:
                    from services.network_ndr_service import sync_inventory_from_nodes
                    sync_inventory_from_nodes(nodes, self._network_meta)
                    from services.device_connection_monitor import process_scan_presence
                    process_scan_presence(nodes)
                except Exception as ndr_exc:
                    logger.debug("NDR inventory sync: %s", ndr_exc)
                return nodes
                
            except Exception as e:
                logger.error(f"Network scan failed: {e}", exc_info=True)
                return self._cache["nodes"]
            finally:
                self._scanning = False
    
    def _perform_arp_scan(self, *, light: bool = False):
        """
        Perform actual ARP scan using Scapy; supplement with OS ARP table (real only).
        Returns:
            List of discovered nodes
        """
        try:
            primary = get_primary_network_interface() or {}
            gateway = primary.get("gateway")
            netmask = primary.get("netmask")
            local_ip = primary.get("local_ip")
            network_range = get_network_range(
                gateway=gateway,
                local_ip=local_ip,
                netmask=netmask,
            )

            if not network_range:
                logger.error("Cannot perform ARP scan - no valid network range detected")
                return []

            logger.info(f"Scanning network range: {network_range}")

            arp_request = scapy.ARP(pdst=network_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request

            timeout = 3 if light else 10
            retry = 1 if light else 2
            logger.info("Sending ARP requests...")
            answered_list = scapy.srp(
                arp_request_broadcast,
                timeout=timeout,
                verbose=False,
                retry=retry,
            )[0]

            logger.info(f"ARP scan received {len(answered_list)} responses")

            nodes_by_ip: Dict[str, Dict[str, Any]] = {}
            prev_by_ip = {n.get("ip"): n for n in (self._cache.get("nodes") or []) if n.get("ip")}
            now = _utc_iso()
            iface = self._network_meta.get("adapter") or primary.get("adapter")

            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc

                logger.info(f"Device found - IP: {ip}, MAC: {mac}")

                if light:
                    hostname = "Sin datos disponibles"
                    response_ms = None
                else:
                    hostname = get_hostname_by_ip(ip)
                    response_ms = measure_response_time_ms(ip)
                vendor = lookup_mac_vendor(mac)

                arp_status = "Detectado (ARP)"
                if response_ms is not None and isinstance(response_ms, (int, float)):
                    arp_status = f"Detectado (ARP, {response_ms:.0f}ms)"

                prev = prev_by_ip.get(ip)
                node = {
                    "ip": ip,
                    "mac": mac,
                    "name": hostname if hostname != "Unknown" else "Sin datos disponibles",
                    "type": "dispositivo",
                    "status": arp_status,
                    "online": None,
                    "response_time_ms": response_ms if response_ms is not None else "Sin datos disponibles",
                    "vendor": vendor,
                    "services": [],
                    "open_ports": [],
                    "detection_method": "arp_scapy",
                    "data_origin": "live_discovery",
                    "interface": iface,
                    "first_seen_utc": (prev or {}).get("first_seen_utc") or now,
                    "last_seen_utc": now,
                    "confidence": "high",
                }
                nodes_by_ip[ip] = node
                if not light:
                    network_event_log.record(f"Dispositivo descubierto: {ip} ({mac})")

            os_neighbors = read_os_arp_neighbors(interface_ip=local_ip)
            for nb in os_neighbors:
                ip = nb.get("ip")
                if not ip or ip in nodes_by_ip:
                    continue
                mac = nb.get("mac")
                prev = prev_by_ip.get(ip)
                nodes_by_ip[ip] = {
                    "ip": ip,
                    "mac": mac or "Sin datos disponibles",
                    "name": "Sin datos disponibles",
                    "type": "dispositivo",
                    "status": "Detectado (tabla ARP del sistema)",
                    "online": None,
                    "response_time_ms": "Sin datos disponibles",
                    "vendor": lookup_mac_vendor(mac) if mac else "Sin datos disponibles",
                    "services": [],
                    "open_ports": [],
                    "detection_method": "arp_os_table",
                    "data_origin": "os_neighbor_table",
                    "interface": nb.get("interface") or iface,
                    "first_seen_utc": (prev or {}).get("first_seen_utc") or now,
                    "last_seen_utc": now,
                    "confidence": "medium",
                }
                logger.info("OS ARP neighbor merged: %s (%s)", ip, mac)

            nodes = list(nodes_by_ip.values())
            logger.info(f"ARP scan complete: {len(nodes)} devices discovered")
            return nodes

        except Exception as e:
            logger.error(f"ARP scan failed: {e}", exc_info=True)
            return []

    def _enrich_nodes_with_port_scan(self, nodes):
        """Attach real open-port scan results to each discovered host."""
        if not nodes:
            return nodes
        try:
            from services.advanced_detector_service import advanced_detector
            for node in nodes:
                ip = node.get("ip")
                if not ip:
                    continue
                open_ports = advanced_detector.scan_open_ports(ip)
                node["open_ports"] = open_ports
                node["services"] = [p.get("service") for p in open_ports if p.get("service")]
                if open_ports:
                    ports_label = ", ".join(str(p.get("port")) for p in open_ports)
                    network_event_log.record(
                        f"Puertos abiertos detectados en {ip}: {ports_label}"
                    )
        except Exception as e:
            logger.error(f"Port enrichment failed: {e}")
        return nodes
    
    def get_network_meta(self):
        """Return cached network metadata discovered during scans."""
        return dict(self._network_meta)

    def get_cached_nodes(self):
        """Get cached nodes without scanning"""
        return self._cache["nodes"]
    
    def get_cache_info(self):
        """Get cache information"""
        return {
            "node_count": len(self._cache["nodes"]),
            "last_scan": self._cache["last_scan"],
            "active_threats": self._cache["active_threats"]
        }
    
    def clear_cache(self):
        """Clear the scan cache"""
        with self._scan_lock:
            self._cache = {
                "nodes": [],
                "last_scan": None,
                "active_threats": None,
            }
            self._last_scan_time = 0
        logger.info("Network scan cache cleared")


# Global scanner instance
network_scanner = NetworkScanner()


def start_background_scanner():
    """
    Inicia Network Monitor Engine (reemplaza escaneo periódico fijo).
    """
    from services.network_monitor_engine import start_network_monitor_engine
    start_network_monitor_engine()
