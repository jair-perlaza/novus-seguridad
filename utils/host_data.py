"""
Host and network helpers for resolving real runtime data only.
"""
import os
import shutil
import socket

import psutil


def _is_usable_ipv4(address):
    if not address or address.startswith("127."):
        return False
    if address.startswith("169.254."):
        return False
    parts = address.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def get_local_ip():
    """Return the primary local IPv4 on the active routed interface."""
    primary = get_primary_network_interface()
    if primary and primary.get("local_ip"):
        return primary["local_ip"]

    try:
        for addresses in psutil.net_if_addrs().values():
            for addr in addresses:
                if addr.family == socket.AF_INET and _is_usable_ipv4(addr.address):
                    return addr.address
    except Exception:
        pass

    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if _is_usable_ipv4(ip):
            return ip
    except Exception:
        pass

    return None


def get_primary_network_interface():
    """
    Return real metadata for the primary IPv4 interface.
    Prefers the interface whose subnet matches the detected default gateway.
    """
    from utils.network_helpers import get_default_gateway

    gateway = get_default_gateway()
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    candidates = []
    for iface_name, iface_addrs in addrs.items():
        iface_stats = stats.get(iface_name)
        if iface_stats and not iface_stats.isup:
            continue

        ipv4 = None
        netmask = None
        mac = None
        for addr in iface_addrs:
            if addr.family == socket.AF_INET and _is_usable_ipv4(addr.address):
                ipv4 = addr.address
                netmask = addr.netmask
            elif getattr(addr, "family", None) == psutil.AF_LINK or (
                hasattr(psutil, "AF_LINK") and addr.family == psutil.AF_LINK
            ):
                mac = addr.address
            elif len(getattr(addr, "address", "")) == 17 and ":" in addr.address:
                mac = addr.address

        if not ipv4:
            continue

        same_subnet = (
            gateway
            and ipv4.split(".")[:3] == gateway.split(".")[:3]
        )
        candidates.append({
            "adapter": iface_name,
            "local_ip": ipv4,
            "netmask": netmask or "Sin datos disponibles",
            "mac": mac or "Sin datos disponibles",
            "gateway": gateway or "Sin datos disponibles",
            "connection_type": _infer_connection_type(iface_name),
            "is_up": iface_stats.isup if iface_stats else None,
            "speed_mbps": iface_stats.speed if iface_stats and iface_stats.speed > 0 else None,
            "same_subnet_as_gateway": same_subnet,
        })

    if not candidates:
        return None

    for candidate in candidates:
        if candidate.get("same_subnet_as_gateway"):
            return candidate

    return candidates[0]


def _infer_connection_type(iface_name):
    name = (iface_name or "").lower()
    if "wi" in name or "wlan" in name or "wireless" in name:
        return "Wi-Fi"
    if "eth" in name or "ethernet" in name:
        return "Ethernet"
    if "vpn" in name:
        return "VPN"
    if "loopback" in name:
        return "Loopback"
    return iface_name or "Sin datos disponibles"


def get_disk_usage(path=None):
    """Return real disk usage metrics; falls back to shutil when psutil fails."""
    if not path:
        path = os.environ.get("SystemDrive", "C:") + os.sep

    try:
        return psutil.disk_usage(path)
    except Exception:
        pass

    try:
        usage = shutil.disk_usage(path)
        percent = round((usage.used / usage.total) * 100, 1) if usage.total else 0.0
        return type(
            "DiskUsage",
            (),
            {
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": percent,
            },
        )()
    except Exception:
        return type(
            "DiskUsage",
            (),
            {"total": 0, "used": 0, "free": 0, "percent": 0.0},
        )()


def format_ip_or_unavailable(ip=None):
    """Return a real IP string or a neutral unavailable label."""
    return ip or "Sin datos disponibles"
