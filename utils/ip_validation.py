"""Validación de direcciones IP — filtra rangos de documentación RFC 5737."""
from __future__ import annotations

import ipaddress
from typing import Optional


_DOC_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def is_documentation_ip(ip: Optional[str]) -> bool:
    """True si la IP pertenece a rangos reservados para documentación (RFC 5737)."""
    if not ip or not isinstance(ip, str):
        return False
    candidate = ip.strip()
    if not candidate or candidate.lower() in (
        "sin datos disponibles",
        "n/d",
        "unknown",
        "localhost",
    ):
        return False
    try:
        addr = ipaddress.ip_address(candidate.split(":")[0].split("%")[0])
    except ValueError:
        return False
    return any(addr in net for net in _DOC_NETWORKS)


def extract_ips_from_text(text: Optional[str]) -> list[str]:
    """Extrae direcciones IPv4 de un texto."""
    if not text:
        return []
    import re

    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(text))

def text_contains_documentation_ip(text: Optional[str]) -> bool:
    return any(is_documentation_ip(ip) for ip in extract_ips_from_text(text))
