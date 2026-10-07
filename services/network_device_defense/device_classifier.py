"""Clasificación heurística de dispositivos — hostname, vendor OUI y TTL opcional."""
from __future__ import annotations

from typing import Any, Dict, Optional


class NOVUSDeviceClassifier:
    """
    Clasifica dispositivos usando prefijo OUI (vendor), TTL y hostname.
    Salida alineada con taxonomía NDR/AIE (Celular, Laptop, PC, …).
    """

    MOBILE_VENDORS = (
        "apple", "samsung", "xiaomi", "huawei", "oppo", "vivo", "realme", "motorola",
    )
    PC_VENDORS = ("intel", "dell", "hp", "lenovo", "asus", "acer", "msi", "gigabyte")

    _HOSTNAME_MOBILE = ("android", "iphone", "galaxy", "redmi", "pixel")
    _HOSTNAME_TABLET = ("ipad", "tab", "mediapad")
    _HOSTNAME_LAPTOP = ("laptop", "book", "macbook", "thinkpad", "zenbook", "lap", "note")
    _HOSTNAME_DESKTOP = ("desktop", "pc", "workstation", "srv", "server")

    @classmethod
    def classify(
        cls,
        mac: str,
        ttl: Optional[int],
        hostname: str,
        vendor: str,
    ) -> str:
        hostname_lower = (hostname or "").lower()
        vendor_lower = (vendor or "").lower()

        if any(term in hostname_lower for term in cls._HOSTNAME_MOBILE):
            return "Celular"
        if any(term in hostname_lower for term in cls._HOSTNAME_TABLET):
            return "Tablet"
        if any(term in hostname_lower for term in cls._HOSTNAME_LAPTOP):
            return "Laptop"
        if any(term in hostname_lower for term in cls._HOSTNAME_DESKTOP):
            return "PC"

        if ttl == 64:
            if any(v in vendor_lower for v in cls.MOBILE_VENDORS):
                return "Celular"
            if "apple" in vendor_lower:
                return "Laptop"
            return "Otro"

        if ttl == 128:
            if any(term in hostname_lower for term in ("lap", "note")):
                return "Laptop"
            return "PC"

        if any(v in vendor_lower for v in cls.MOBILE_VENDORS):
            return "Celular"
        if any(v in vendor_lower for v in cls.PC_VENDORS):
            return "PC"

        return "Otro"


def classify_device_from_node(node: dict, gateway: Optional[str] = None) -> str:
    """
    Clasifica un nodo ARP/NDR. Usa señales del clasificador y cae en estimate_device_type
    cuando hostname/vendor no son concluyentes.
    """
    ip = node.get("ip") or ""
    if gateway and ip == gateway:
        return "Gateway"

    hostname = (
        node.get("name")
        or node.get("hostname")
        or ""
    )
    if hostname in ("Sin datos disponibles", "Unknown", "Desconocido"):
        hostname = ""

    vendor = node.get("vendor") or ""
    mac = node.get("mac") or ""
    ttl_raw = node.get("ttl")
    ttl: Optional[int] = None
    if isinstance(ttl_raw, int):
        ttl = ttl_raw
    elif isinstance(ttl_raw, str) and ttl_raw.isdigit():
        ttl = int(ttl_raw)

    heuristic = NOVUSDeviceClassifier.classify(mac, ttl, hostname, vendor)
    if heuristic != "Otro":
        return heuristic

    from services.network_ndr_service import estimate_device_type as ndr_estimate

    return ndr_estimate(node, gateway)


def classification_evidence(node: dict, gateway: Optional[str] = None) -> Dict[str, Any]:
    """Evidencia de clasificación — campos no verificables como NO DISPONIBLE."""
    dtype = classify_device_from_node(node, gateway)
    hostname = node.get("name") or node.get("hostname") or "NO DISPONIBLE"
    ttl = node.get("ttl")
    return {
        "device_type": dtype,
        "hostname": hostname,
        "vendor": node.get("vendor") or "NO DISPONIBLE",
        "mac": node.get("mac") or "NO DISPONIBLE",
        "ip": node.get("ip") or "NO DISPONIBLE",
        "ttl": ttl if ttl is not None else "NO DISPONIBLE",
        "source": "network_device_defense.device_classifier",
        "verified": bool(node.get("mac") and node.get("ip")),
        "invented": False,
    }
