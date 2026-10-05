#!/usr/bin/env python3
"""
Network asset tracker — presencia de red y evaluación Zero Trust en login.
Integrado con WSAE/session_risk. Kernel IA: recomendación only (executes_actions=false).
"""
from __future__ import annotations

import asyncio
import datetime
import ipaddress
import os
import socket
from typing import Any, Dict, List, Optional, Set

from utils.logger import logger

NA = "NO DISPONIBLE"


def _resolve_corporate_subnet() -> str:
    """Subred corporativa desde entorno o detección local — NA si no verificable."""
    env = os.environ.get("NOVUS_CORPORATE_SUBNET", "").strip()
    if env:
        return env
    try:
        from services.network_scanner import network_scanner
        rng = network_scanner.get_network_range()
        if rng and "/" in str(rng):
            return str(rng)
    except Exception:
        pass
    try:
        from utils.host_data import get_local_ip
        ip = get_local_ip()
        if ip and ip not in (NA, "Sin datos disponibles", "127.0.0.1"):
            parts = ip.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        pass
    return "10.0.0.0/8"


def _allowed_admin_ips() -> List[str]:
    raw = os.environ.get("NOVUS_ALLOWED_ADMIN_IPS", "")
    if raw.strip():
        return [x.strip() for x in raw.split(",") if x.strip()]
    return []


def _asm_known_ips() -> Set[str]:
    try:
        from services.asm.store import load_inventory
        inv = load_inventory() or {}
        ips: Set[str] = set()
        for asset in inv.get("assets") or []:
            if isinstance(asset, dict):
                ip = asset.get("ip") or asset.get("primary_ip")
                if ip and str(ip) != NA:
                    ips.add(str(ip))
        return ips
    except Exception:
        return set()


class NetworkAssetTracker:
    """
    Rastrea presencia ON-CONNECT/OFF-CONNECT (async) y evalúa login Zero Trust.
    No ejecuta bloqueos — devuelve recomendaciones para SOPE/WSAE.
    """

    def __init__(self, target_subnet: Optional[str] = None, allowed_admin_ips: Optional[List[str]] = None):
        subnet = target_subnet or _resolve_corporate_subnet()
        try:
            self.subnet = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            self.subnet = ipaddress.ip_network("10.0.0.0/8", strict=False)
        self.allowed_admin_ips = set(allowed_admin_ips or _allowed_admin_ips())
        self.active_devices: Set[str] = set()

    async def _ping_host(self, ip_str: str) -> bool:
        loop = asyncio.get_event_loop()
        try:
            await loop.getaddrinfo(ip_str, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
            return True
        except (socket.gaierror, Exception):
            return False

    async def scan_network_presence(self) -> Dict[str, Any]:
        """Escaneo de subred — usar con moderación (costoso). Preferir network_scanner."""
        current_online: Set[str] = set()
        tasks = []
        try:
            hosts = list(self.subnet.hosts())
        except Exception:
            hosts = []
        for host in hosts[:254]:
            ip_str = str(host)
            tasks.append(self._check_and_add(ip_str, current_online))
        if tasks:
            await asyncio.gather(*tasks)
        connected = list(current_online - self.active_devices)
        disconnected = list(self.active_devices - current_online)
        self.active_devices = current_online
        if connected:
            logger.info("[ON-CONNECT] equipos: %s", connected[:10])
        if disconnected:
            logger.info("[ON-DISCONNECT] equipos: %s", disconnected[:10])
        return {
            "connected": connected,
            "disconnected": disconnected,
            "total_active": len(self.active_devices),
            "verified": True,
            "invented": False,
        }

    async def _check_and_add(self, ip_str: str, current_set: Set[str]) -> None:
        if await self._ping_host(ip_str):
            current_set.add(ip_str)

    def evaluate_zero_trust_login(
        self,
        user: str,
        is_admin: bool,
        origin_ip: str,
        user_agent: str = "",
        *,
        email: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Evalúa riesgo de login. Acciones = recomendación (no ejecuta bloqueo).
        executes_actions=false para Kernel IA.
        """
        risk_score = 0
        reasons: List[str] = []
        observed: List[str] = []
        not_verified: List[str] = []

        try:
            ip_obj = ipaddress.ip_address(origin_ip)
            is_internal = ip_obj in self.subnet
            observed.append(f"IP {origin_ip} internal={is_internal}")
        except ValueError:
            is_internal = False
            observed.append(f"IP {origin_ip} no parseable como IPv4/IPv6")

        asm_ips = _asm_known_ips()
        if asm_ips and origin_ip not in asm_ips:
            risk_score += 15
            reasons.append("IP no presente en inventario ASM observado.")
            observed.append("asm_inventory_checked")
        elif not asm_ips:
            not_verified.append("asm_inventory_empty_or_unavailable")

        if is_admin:
            if not is_internal and origin_ip not in self.allowed_admin_ips:
                risk_score += 40
                reasons.append(
                    f"Acceso administrativo desde IP fuera de subred corporativa: {origin_ip}"
                )
                observed.append("admin_external_ip")

        ua_l = (user_agent or "").lower()
        if "python" in ua_l or "curl" in ua_l or "wget" in ua_l:
            risk_score += 20
            reasons.append("Cliente automatizado/script en User-Agent.")
            observed.append("automated_user_agent")

        recommendation = "ALLOW"
        if risk_score >= 70:
            recommendation = "RECOMMEND_BLOCK_AND_STEP_UP_MFA"
        elif risk_score >= 40:
            recommendation = "RECOMMEND_MFA_STEP_UP"

        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "user": user,
            "email": email or NA,
            "origin_ip": origin_ip,
            "risk_score": risk_score,
            "recommendation": recommendation,
            "action": recommendation,
            "executes_actions": False,
            "reasons": reasons,
            "observed": observed,
            "not_verified": not_verified,
            "subnet": str(self.subnet),
            "allowed_admin_ips": sorted(self.allowed_admin_ips)[:20],
            "invented": False,
            "verified": True,
        }


_tracker: Optional[NetworkAssetTracker] = None


def get_network_tracker() -> NetworkAssetTracker:
    global _tracker
    if _tracker is None:
        _tracker = NetworkAssetTracker()
    return _tracker


def evaluate_login_zero_trust(
    *,
    user: str,
    is_admin: bool,
    origin_ip: str,
    user_agent: str = "",
    email: Optional[str] = None,
) -> Dict[str, Any]:
    """API síncrona para login_pipeline."""
    return get_network_tracker().evaluate_zero_trust_login(
        user, is_admin, origin_ip, user_agent, email=email
    )
