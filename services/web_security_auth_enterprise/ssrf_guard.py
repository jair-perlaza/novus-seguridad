"""
SSRF guard — bloquea destinos privados/metadata.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse


_BLOCKED_HOSTS = {
    "metadata.google.internal",
    "metadata",
    "localhost",
}


def _ip_blocked(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or str(addr) == "169.254.169.254"
    )


def is_url_safe(url: str) -> Tuple[bool, str]:
    if not url or not isinstance(url, str):
        return False, "empty_url"
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        return False, "scheme_not_allowed"
    host = (parsed.hostname or "").lower()
    if not host:
        return False, "no_host"
    if host in _BLOCKED_HOSTS or host.endswith(".localhost"):
        return False, "blocked_host"
    # literal IP
    try:
        if _ip_blocked(host):
            return False, "private_or_metadata_ip"
    except Exception:
        pass
    # DNS resolve
    try:
        infos = socket.getaddrinfo(host, parsed.port or 80, type=socket.SOCK_STREAM)
        for info in infos:
            ip = info[4][0]
            if _ip_blocked(ip):
                return False, f"resolves_to_blocked:{ip}"
    except socket.gaierror:
        return False, "dns_failed"
    except Exception as exc:
        return False, f"resolve_error:{exc}"
    return True, "ok"


def assert_url_safe(url: str) -> Dict[str, Any]:
    ok, reason = is_url_safe(url)
    return {"allowed": ok, "reason": reason, "url_scheme_host": urlparse(url).netloc if url else None, "verified": True}
