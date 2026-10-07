"""
T1 — Inventario automático de red del host NOVUS (datos reales, sin estáticos).
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil

from utils.logger import logger

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "network_endpoint_enterprise"
INVENTORY_PATH = DATA_DIR / "host_network_inventory.json"
CHANGES_PATH = DATA_DIR / "host_network_changes.jsonl"


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ensure_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _iface_kind(name: str) -> str:
    n = (name or "").lower()
    if any(x in n for x in ("vethernet", "hyper-v", "vmware", "virtualbox", "vbox", "wsl", "loopback", "isatap", "teredo")):
        return "virtual"
    if any(x in n for x in ("wi-fi", "wifi", "wlan", "wireless")):
        return "wireless"
    if any(x in n for x in ("ethernet", "eth", "lan")):
        return "ethernet"
    return "other"


def _collect_dns_windows() -> List[str]:
    servers: List[str] = []
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-DnsClientServerAddress -AddressFamily IPv4 | "
             "Select-Object -ExpandProperty ServerAddresses"],
            timeout=8,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        for line in out.splitlines():
            ip = line.strip()
            if ip and ip.count(".") == 3 and ip not in servers:
                servers.append(ip)
    except Exception as exc:
        logger.debug("dns collect: %s", exc)
    return servers


def _collect_dhcp_windows() -> Dict[str, Any]:
    """DHCP habilitado / servidor desde configuración real del adaptador."""
    info: Dict[str, Any] = {"dhcp_enabled": None, "dhcp_servers": [], "source": None}
    try:
        out = subprocess.check_output(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-CimInstance Win32_NetworkAdapterConfiguration | "
                    "Where-Object { $_.IPEnabled -eq $true } | "
                    "Select-Object Description,DHCPEnabled,DHCPServer,"
                    "@{N='IP';E={$_.IPAddress -join ','}} | ConvertTo-Json -Compress"
                ),
            ],
            timeout=12,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        raw = (out or "").strip()
        if not raw:
            return info
        data = json.loads(raw)
        rows = data if isinstance(data, list) else [data]
        servers = []
        enabled_any = False
        for row in rows:
            if row.get("DHCPEnabled"):
                enabled_any = True
            srv = row.get("DHCPServer")
            if srv and str(srv) not in servers:
                servers.append(str(srv))
        info["dhcp_enabled"] = enabled_any
        info["dhcp_servers"] = servers
        info["adapters"] = [
            {
                "description": r.get("Description"),
                "dhcp_enabled": bool(r.get("DHCPEnabled")),
                "dhcp_server": r.get("DHCPServer"),
                "ip": r.get("IP"),
            }
            for r in rows
            if isinstance(r, dict)
        ]
        info["source"] = "Win32_NetworkAdapterConfiguration"
    except Exception as exc:
        logger.debug("dhcp collect: %s", exc)
        info["error"] = str(exc)[:200]
    return info


def collect_host_network_inventory() -> Dict[str, Any]:
    """Inventario completo del host: interfaces, IP/MAC, gateway, DNS, DHCP."""
    from utils.host_data import get_local_ip, get_primary_network_interface
    from utils.network_helpers import get_default_gateway, get_network_range

    primary = get_primary_network_interface() or {}
    gateway = get_default_gateway()
    local_ip = primary.get("local_ip") or get_local_ip()
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    interfaces: List[Dict[str, Any]] = []
    for name, iface_addrs in addrs.items():
        st = stats.get(name)
        entry: Dict[str, Any] = {
            "name": name,
            "kind": _iface_kind(name),
            "is_up": bool(st.isup) if st else None,
            "speed_mbps": getattr(st, "speed", None) if st else None,
            "mtu": getattr(st, "mtu", None) if st else None,
            "ipv4": [],
            "ipv6": [],
            "mac": None,
        }
        for addr in iface_addrs:
            fam = addr.family
            if fam == socket.AF_INET:
                entry["ipv4"].append({"address": addr.address, "netmask": addr.netmask})
            elif fam == socket.AF_INET6:
                entry["ipv6"].append({"address": addr.address, "netmask": addr.netmask})
            elif getattr(psutil, "AF_LINK", None) is not None and fam == psutil.AF_LINK:
                entry["mac"] = addr.address
            elif len(getattr(addr, "address", "") or "") == 17 and ":" in addr.address:
                entry["mac"] = addr.address
        interfaces.append(entry)

    dns = _collect_dns_windows() if platform.system() == "Windows" else []
    dhcp = _collect_dhcp_windows() if platform.system() == "Windows" else {"dhcp_enabled": None, "dhcp_servers": []}

    # Rutas (solo default / primeras)
    routes: List[Dict[str, Any]] = []
    try:
        out = subprocess.check_output(
            ["route", "print", "-4"],
            timeout=8,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0].count(".") == 3:
                routes.append(
                    {
                        "destination": parts[0],
                        "netmask": parts[1],
                        "gateway": parts[2],
                        "interface": parts[3],
                        "metric": parts[4] if len(parts) > 4 else None,
                    }
                )
                if len(routes) >= 40:
                    break
    except Exception as exc:
        logger.debug("routes collect: %s", exc)

    inv = {
        "collected_at_utc": _utc(),
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "local_ip": local_ip,
        "gateway": gateway,
        "network_range": get_network_range(gateway) if gateway else None,
        "dns_servers": dns,
        "dhcp": dhcp,
        "primary_adapter": {
            "name": primary.get("adapter"),
            "mac": primary.get("mac"),
            "netmask": primary.get("netmask"),
            "connection_type": primary.get("connection_type"),
            "speed_mbps": primary.get("speed_mbps"),
            "kind": _iface_kind(primary.get("adapter") or ""),
        },
        "interfaces": interfaces,
        "physical_adapters": [i for i in interfaces if i.get("kind") in ("ethernet", "wireless", "other") and i.get("mac")],
        "virtual_adapters": [i for i in interfaces if i.get("kind") == "virtual"],
        "routes_sample": routes,
        "source": "psutil+Win32+route",
    }
    inv["fingerprint"] = _fingerprint(inv)
    return inv


def _fingerprint(inv: Dict[str, Any]) -> str:
    core = {
        "local_ip": inv.get("local_ip"),
        "gateway": inv.get("gateway"),
        "dns_servers": inv.get("dns_servers"),
        "dhcp_servers": (inv.get("dhcp") or {}).get("dhcp_servers"),
        "mac": (inv.get("primary_adapter") or {}).get("mac"),
        "routes": [
            (r.get("destination"), r.get("gateway"), r.get("interface"))
            for r in (inv.get("routes_sample") or [])[:15]
        ],
    }
    blob = json.dumps(core, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def load_previous_inventory() -> Optional[Dict[str, Any]]:
    if not INVENTORY_PATH.is_file():
        return None
    try:
        return json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None


def persist_inventory(inv: Dict[str, Any]) -> None:
    _ensure_dir()
    INVENTORY_PATH.write_text(json.dumps(inv, indent=2, ensure_ascii=False), encoding="utf-8")


def diff_inventory(prev: Optional[Dict[str, Any]], cur: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Solo cambios reales entre inventarios."""
    if not prev:
        return []
    changes: List[Dict[str, Any]] = []

    def add(kind: str, field: str, old, new):
        if old != new:
            changes.append(
                {
                    "change_type": kind,
                    "field": field,
                    "previous": old,
                    "current": new,
                    "detected_at_utc": _utc(),
                }
            )

    add("ip_change", "local_ip", prev.get("local_ip"), cur.get("local_ip"))
    add("gateway_change", "gateway", prev.get("gateway"), cur.get("gateway"))
    add("dns_change", "dns_servers", prev.get("dns_servers"), cur.get("dns_servers"))
    add(
        "mac_change",
        "primary_mac",
        (prev.get("primary_adapter") or {}).get("mac"),
        (cur.get("primary_adapter") or {}).get("mac"),
    )
    prev_dhcp = (prev.get("dhcp") or {}).get("dhcp_servers") or []
    cur_dhcp = (cur.get("dhcp") or {}).get("dhcp_servers") or []
    add("dhcp_change", "dhcp_servers", prev_dhcp, cur_dhcp)

    prev_routes = {
        (r.get("destination"), r.get("gateway"), r.get("interface"))
        for r in (prev.get("routes_sample") or [])
    }
    cur_routes = {
        (r.get("destination"), r.get("gateway"), r.get("interface"))
        for r in (cur.get("routes_sample") or [])
    }
    if prev_routes != cur_routes:
        added = list(cur_routes - prev_routes)[:10]
        removed = list(prev_routes - cur_routes)[:10]
        changes.append(
            {
                "change_type": "route_change",
                "field": "routes",
                "added": added,
                "removed": removed,
                "detected_at_utc": _utc(),
            }
        )
    return changes


def append_changes(changes: List[Dict[str, Any]]) -> None:
    if not changes:
        return
    _ensure_dir()
    with open(CHANGES_PATH, "a", encoding="utf-8") as fh:
        for ch in changes:
            fh.write(json.dumps(ch, ensure_ascii=False) + "\n")


def snapshot_and_diff() -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    prev = load_previous_inventory()
    cur = collect_host_network_inventory()
    changes = diff_inventory(prev, cur)
    persist_inventory(cur)
    append_changes(changes)
    return cur, changes
