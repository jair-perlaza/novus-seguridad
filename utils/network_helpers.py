"""
Network utility functions for NOVUS
Handles socket operations with robust error handling
"""
import ipaddress
import socket
import subprocess
import platform
import re
import time
import psutil
from typing import Any, Dict, List, Optional

from utils.logger import logger

_gateway_cache: dict = {"value": None, "ts": 0.0}
_GATEWAY_TTL = 60.0


def get_hostname():
    """
    Get system hostname with error handling
    Returns 'Unknown' on error
    """
    try:
        return socket.gethostname()
    except Exception as e:
        logger.error(f"Error getting hostname: {e}")
        return "Unknown"


def get_host_ip(hostname=None):
    """
    Get host IP address with robust error handling.
    Returns None when no real address is available.
    """
    from utils.host_data import get_local_ip
    return get_local_ip()


def get_hostname_by_ip(ip):
    """
    Get hostname by IP address with robust error handling
    Returns 'Unknown' on error
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror as e:
        logger.debug(f"gethostbyaddr failed for {ip}: {e}")
        return "Unknown"
    except socket.gaierror as e:
        logger.debug(f"gethostbyaddr failed for {ip}: {e}")
        return "Unknown"
    except Exception as e:
        logger.debug(f"Error getting hostname for {ip}: {e}")
        return "Unknown"


def is_valid_ipv4(ip):
    """
    Validate IPv4 address format using regex
    Returns True if valid IPv4, False otherwise
    """
    if not ip:
        return False
    # IPv4 regex pattern
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(ipv4_pattern, ip.strip()))


def _remember_gateway(gateway):
    if gateway:
        _gateway_cache["value"] = gateway
        _gateway_cache["ts"] = time.time()
    return gateway


def get_default_gateway():
    """
    Detect default gateway based on OS
    Only returns valid IPv4 gateways, filters out IPv6
    Returns None if no valid gateway found
    """
    now = time.time()
    if _gateway_cache["value"] and (now - _gateway_cache["ts"]) < _GATEWAY_TTL:
        return _gateway_cache["value"]

    try:
        # Method 1: Use psutil to get gateway from network interfaces
        logger.debug("Detecting gateway via psutil...")
        
        # Get all network interfaces
        interfaces = psutil.net_if_addrs()
        
        for interface_name, interface_addresses in interfaces.items():
            for addr in interface_addresses:
                # Look for IPv4 addresses that are not localhost
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    logger.info(f"Found interface {interface_name} with IP: {addr.address}")
                    
                    # Try to get gateway from routing table
                    if platform.system() == "Windows":
                        result = subprocess.run(
                            ['route', 'print', '0.0.0.0'],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        for line in result.stdout.split('\n'):
                            if '0.0.0.0' in line and addr.address.split('.')[0:3] == line.split()[2].split('.')[0:3]:
                                gateway = line.split()[2]
                                if is_valid_ipv4(gateway):
                                    logger.info(f"Gateway detected via route print: {gateway}")
                                    return _remember_gateway(gateway)
                    else:
                        result = subprocess.run(
                            ['ip', 'route', 'show', 'default'],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        if result.returncode == 0:
                            parts = result.stdout.split()
                            if len(parts) >= 3:
                                gateway = parts[2]
                                if is_valid_ipv4(gateway):
                                    logger.info(f"Gateway detected via ip route: {gateway}")
                                    return _remember_gateway(gateway)
        
        # Method 2: Fallback to ipconfig for Windows
        if platform.system() == "Windows":
            logger.info("Attempting gateway detection via ipconfig...")
            result = subprocess.run(
                ['ipconfig'],
                capture_output=True,
                text=True,
                timeout=10
            )
            for line in result.stdout.split('\n'):
                if ('Default Gateway' in line or 
                    'Puerta de enlace predeterminada' in line) and ':' in line:
                    gateway = line.split(':')[-1].strip()
                    if is_valid_ipv4(gateway):
                        logger.info(f"Gateway detected via ipconfig: {gateway}")
                        return _remember_gateway(gateway)
        
        # Method 3: Try to derive gateway from local IP
        logger.info("Attempting to derive gateway from local IP...")
        local_ip = get_local_ip_from_interfaces()
        if local_ip and is_valid_ipv4(local_ip):
            ip_parts = local_ip.split('.')
            derived_gateway = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
            if is_valid_ipv4(derived_gateway):
                logger.info(f"Derived gateway from local IP: {derived_gateway}")
                return _remember_gateway(derived_gateway)
        
        logger.error("No valid IPv4 gateway detected")
        return None
        
    except subprocess.TimeoutExpired:
        logger.error("Gateway detection timeout")
        return None
    except Exception as e:
        logger.error(f"Error detecting gateway: {e}", exc_info=True)
        return None


def get_local_ip_from_interfaces():
    """
    Get local IP from network interfaces using psutil
    Returns first non-localhost IPv4 address
    """
    try:
        interfaces = psutil.net_if_addrs()
        for interface_name, interface_addresses in interfaces.items():
            for addr in interface_addresses:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    logger.info(f"Local IP detected from interface {interface_name}: {addr.address}")
                    return addr.address
        return None
    except Exception as e:
        logger.error(f"Error getting local IP from interfaces: {e}")
        return None


def _netmask_to_prefix(netmask: Optional[str]) -> Optional[int]:
    if not netmask or netmask == "Sin datos disponibles":
        return None
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask}", strict=False).prefixlen
    except Exception:
        return None


def cidr_from_ip_netmask(local_ip: str, netmask: Optional[str]) -> Optional[str]:
    """Calcula CIDR real a partir de IP y máscara de la interfaz activa."""
    if not local_ip or not is_valid_ipv4(local_ip):
        return None
    prefix = _netmask_to_prefix(netmask)
    if prefix is None:
        return None
    try:
        network = ipaddress.IPv4Network(f"{local_ip}/{prefix}", strict=False)
        return str(network)
    except Exception as exc:
        logger.debug("cidr_from_ip_netmask failed: %s", exc)
        return None


def subnet_host_count(cidr: Optional[str]) -> Optional[int]:
    if not cidr:
        return None
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        return max(0, net.num_addresses - 2)
    except Exception:
        return None


def read_os_arp_neighbors(*, interface_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Lee entradas ARP dinámicas del sistema operativo (evidencia diagnóstica real).
    No inventa dispositivos: solo devuelve lo que el SO reporta como vecino unicast.
    """
    neighbors: List[Dict[str, Any]] = []
    try:
        if platform.system() != "Windows":
            result = subprocess.run(
                ["ip", "neigh", "show"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in (result.stdout or "").splitlines():
                parts = line.split()
                if len(parts) < 5:
                    continue
                ip, _dev, _ll, _state, mac = parts[0], parts[1], parts[2], parts[3], parts[4]
                if _state not in ("REACHABLE", "STALE", "DELAY", "PROBE"):
                    continue
                if not is_valid_ipv4(ip) or ip.startswith("224.") or ip.startswith("239."):
                    continue
                if interface_ip and not ip.startswith(".".join(interface_ip.split(".")[:3])):
                    continue
                neighbors.append({
                    "ip": ip,
                    "mac": mac.replace("-", ":").lower(),
                    "detection_method": "arp_os_table",
                    "data_origin": "os_neighbor_table",
                })
            return neighbors

        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        current_iface = None
        for raw in (result.stdout or "").splitlines():
            line = raw.strip()
            if line.lower().startswith("interfaz:"):
                current_iface = line.split(":", 1)[-1].strip().split("---")[0].strip()
                continue
            if interface_ip and current_iface and interface_ip not in current_iface:
                continue
            m = re.match(
                r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F\-]{17})\s+(\S+)",
                line,
            )
            if not m:
                continue
            ip, mac_raw, entry_type = m.group(1), m.group(2), m.group(3).lower()
            static_markers = ("estatico", "estático", "static", "permanente", "permanent")
            if any(s in entry_type for s in static_markers):
                continue
            if not is_valid_ipv4(ip) or ip.endswith(".255"):
                continue
            if ip.startswith(("224.", "239.", "255.")):
                continue
            neighbors.append({
                "ip": ip,
                "mac": mac_raw.replace("-", ":").lower(),
                "detection_method": "arp_os_table",
                "data_origin": "os_neighbor_table",
                "interface": current_iface,
            })
    except Exception as exc:
        logger.debug("read_os_arp_neighbors: %s", exc)
    return neighbors


def assess_discovery_limitations(
    *,
    scapy_count: int,
    os_arp_count: int,
    subnet_cidr: Optional[str],
    ssid: Optional[str] = None,
    connection_type: Optional[str] = None,
    ap_client_isolation_confirmed: bool = False,
) -> Dict[str, Any]:
    """
    Evalúa limitaciones de visibilidad demostrables desde el host.
    No infla conteos ni afirma aislamiento AP sin evidencia directa.
    """
    ssid_l = (ssid or "").lower()
    guest_markers = ("invitad", "guest", "visitant", "public", "hotspot")
    likely_guest = any(m in ssid_l for m in guest_markers)
    hosts_possible = subnet_host_count(subnet_cidr)
    low_visibility = scapy_count <= 2 and os_arp_count <= 1
    limited = low_visibility or (
        hosts_possible is not None and hosts_possible > 10 and scapy_count < hosts_possible * 0.05
    )

    classification = "REAL_DATA_LIMITED_VISIBILITY" if limited else "REAL_DATA_NORMAL"
    user_message = None
    if limited:
        user_message = (
            f"NOVUS detectó {scapy_count} dispositivo(s) que respondieron al método de "
            f"descubrimiento disponible (ARP) en {subnet_cidr or 'el segmento local'}. "
            "Otros hosts pueden no ser observables desde esta interfaz o red. "
            "La causa exacta de la limitación no pudo determinarse desde este equipo."
        )
        if ap_client_isolation_confirmed:
            user_message += (
                " Evidencia técnica directa indica aislamiento de clientes en el punto de acceso."
            )

    return {
        "classification": classification,
        "scapy_arp_count": scapy_count,
        "os_arp_dynamic_count": os_arp_count,
        "subnet_cidr": subnet_cidr,
        "subnet_hosts_possible": hosts_possible,
        "ssid": ssid,
        "connection_type": connection_type,
        "likely_guest_network": likely_guest,
        "ap_client_isolation_confirmed": bool(ap_client_isolation_confirmed),
        "visibility": "limited" if limited else "normal",
        "user_message": user_message,
        "data_authenticity": "real_detected_only",
    }


def get_network_range(gateway=None, local_ip=None, netmask=None):
    """
    Determine network range from active interface netmask (preferred) or gateway/local IP.
    Returns network range in CIDR notation — never hardcoded unless netmask unavailable.
    """
    try:
        from utils.host_data import get_primary_network_interface

        primary = get_primary_network_interface() or {}
        local_ip = local_ip or primary.get("local_ip")
        netmask = netmask or primary.get("netmask")
        gateway = gateway or get_default_gateway()
        
        cidr = cidr_from_ip_netmask(local_ip, netmask) if local_ip else None
        if cidr:
            logger.info("Network range from interface netmask: %s", cidr)
            return cidr

        if gateway and is_valid_ipv4(gateway):
            gateway_parts = gateway.split(".")
            if len(gateway_parts) == 4:
                gateway_parts[-1] = "0/24"
                network_range = ".".join(gateway_parts)
                logger.warning(
                    "Network range fallback /24 from gateway (netmask unavailable): %s",
                    network_range,
                )
                return network_range

        if local_ip and is_valid_ipv4(local_ip):
            ip_parts = local_ip.split(".")
            network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            logger.warning(
                "Network range fallback /24 from local IP (netmask unavailable): %s",
                network_range,
            )
            return network_range

        logger.error("Cannot determine network range - no valid gateway, local IP or netmask")
        return None
        
    except Exception as e:
        logger.error(f"Error getting network range: {e}", exc_info=True)
        return None


def is_valid_ip(ip):
    """
    Validate IP address format
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def is_port_open(host, port, timeout=2):
    """
    Check if a port is open on a host
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception as e:
        logger.debug(f"Port check failed for {host}:{port}: {e}")
        return False
