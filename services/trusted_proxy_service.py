"""
Validación de proxy confiable — X-Forwarded-For solo desde hops de confianza explícitos.
"""
from __future__ import annotations

import ipaddress
import os
from typing import FrozenSet


def trusted_proxy_ips() -> FrozenSet[str]:
    raw = os.environ.get(
        "NOVUS_TRUSTED_PROXY_IPS",
        "127.0.0.1,::1,localhost",
    )
    out = set()
    for item in raw.split(","):
        item = item.strip().lower()
        if item:
            out.add(item)
    return frozenset(out)


def is_trusted_proxy_hop(ip: str) -> bool:
    ip = (ip or "").strip()
    if not ip:
        return False
    if ip.lower() in trusted_proxy_ips():
        return True
    extra_cidrs = os.environ.get("NOVUS_TRUSTED_PROXY_CIDRS", "").strip()
    if not extra_cidrs:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in extra_cidrs.split(","):
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def extract_client_ip(*, remote_addr: str, x_forwarded_for: str | None, behind_proxy: bool) -> str:
    """
    IP efectiva del cliente. XFF solo si behind_proxy Y el hop directo es proxy confiable.
    """
    remote = (remote_addr or "unknown").strip()
    if not behind_proxy or not x_forwarded_for:
        return remote or "unknown"
    if not is_trusted_proxy_hop(remote):
        return remote or "unknown"
    client = x_forwarded_for.split(",")[0].strip()
    return client or remote
