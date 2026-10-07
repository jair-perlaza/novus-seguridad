#!/usr/bin/env python3
"""
ASM Discovery — descubrimiento real de activos, software, servicios, certificados.
NO inventa activos. Todo viene del sistema operativo o la red real.
"""
from __future__ import annotations

import os
import platform
import socket
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psutil

from services.asm.limitations import NA
from utils.logger import logger


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_run(cmd: List[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return r.stdout or ""
    except Exception:
        return ""


def discover_local_host() -> Dict[str, Any]:
    """Descubre el host local con datos reales del SO."""
    try:
        boot = psutil.boot_time()
        uptime_sec = time.time() - boot
    except Exception:
        uptime_sec = 0

    interfaces = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for iface, addr_list in addrs.items():
            info: Dict[str, Any] = {"name": iface, "ip": None, "mac": None, "up": False}
            for a in addr_list:
                if a.family == socket.AF_INET:
                    info["ip"] = a.address
                    info["netmask"] = a.netmask
                elif hasattr(socket, "AF_LINK") and a.family == socket.AF_LINK:
                    info["mac"] = a.address
                elif a.family == psutil.AF_LINK:
                    info["mac"] = a.address
            st = stats.get(iface)
            if st:
                info["up"] = st.isup
                info["speed_mbps"] = st.speed
                info["mtu"] = st.mtu
            interfaces.append(info)
    except Exception:
        pass

    users = []
    try:
        for u in psutil.users():
            users.append({"name": u.name, "terminal": u.terminal, "host": u.host,
                          "started": datetime.fromtimestamp(u.started).strftime("%Y-%m-%d %H:%M")})
    except Exception:
        pass

    gateway = NA
    dns_servers: List[str] = []
    try:
        if platform.system() == "Windows":
            out = _safe_run(["ipconfig", "/all"])
            for line in out.splitlines():
                l = line.strip()
                if "gateway" in l.lower() or "puerta de enlace" in l.lower():
                    parts = l.split(":")
                    if len(parts) > 1:
                        gw = parts[-1].strip()
                        if gw and gw != "": gateway = gw
                if "dns" in l.lower() and "server" in l.lower() or "dns" in l.lower() and "servidor" in l.lower():
                    parts = l.split(":")
                    if len(parts) > 1:
                        ds = parts[-1].strip()
                        if ds: dns_servers.append(ds)
    except Exception:
        pass

    return {
        "asset_id": f"host-{socket.gethostname().lower()}",
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "ip": _get_primary_ip(),
        "mac": _get_primary_mac(interfaces),
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "processor": platform.processor() or NA,
        "cpu_cores": psutil.cpu_count(),
        "ram_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "uptime_hours": round(uptime_sec / 3600, 2),
        "uptime_days": round(uptime_sec / 86400, 2),
        "boot_time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
        "active_users": users,
        "gateway": gateway,
        "dns_servers": dns_servers if dns_servers else [NA],
        "interfaces": interfaces,
        "classification": "servidor" if _is_server() else "cliente",
        "criticality": "production",
        "status": "active",
        "discovered_at_utc": _utc(),
        "invented": False,
    }


def _get_primary_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _get_primary_mac(interfaces: List[Dict]) -> str:
    for i in interfaces:
        if i.get("ip") and i["ip"] != "127.0.0.1" and i.get("mac"):
            return i["mac"]
    return NA


def _is_server() -> bool:
    if platform.system() == "Windows":
        return "server" in platform.version().lower() or "server" in platform.release().lower()
    return os.path.exists("/etc/server-release")


def discover_network_nodes() -> List[Dict[str, Any]]:
    """Descubre nodos desde snapshot/cache — ARP solo en background."""
    try:
        from services.network_scanner import network_scanner
        from services.network_scan_coordinator import schedule_network_discovery

        nodes = network_scanner.get_cached_nodes() or []
        if not nodes:
            schedule_network_discovery(consumer="asm_warmup", force=False)
            return []
        result = []
        for n in nodes:
            result.append({
                "asset_id": f"net-{(n.get('mac') or n.get('ip', 'unknown')).replace(':', '-').lower()}",
                "hostname": n.get("hostname") or n.get("name") or NA,
                "ip": n.get("ip") or NA,
                "mac": n.get("mac") or NA,
                "vendor": n.get("vendor") or n.get("manufacturer") or NA,
                "open_ports": n.get("open_ports") or [],
                "services": n.get("services") or [],
                "status": "active",
                "classification": _classify_device(n),
                "discovered_at_utc": _utc(),
                "invented": False,
            })
        return result
    except Exception as exc:
        logger.error("ASM discover_network_nodes: %s", exc)
        return []


def _classify_device(node: Dict) -> str:
    vendor = str(node.get("vendor") or "").lower()
    hostname = str(node.get("hostname") or "").lower()
    ports = [p.get("port") if isinstance(p, dict) else p for p in (node.get("open_ports") or [])]

    if any(kw in vendor for kw in ("cisco", "juniper", "mikrotik", "ubiquiti", "netgear", "tp-link")):
        return "infraestructura"
    if any(kw in vendor for kw in ("hikvision", "dahua", "axis", "vivotek")):
        return "iot_camera"
    if any(kw in vendor for kw in ("hp", "brother", "epson", "canon", "xerox", "ricoh")) and 9100 in ports:
        return "impresora"
    if 80 in ports or 443 in ports or 8080 in ports:
        if 22 in ports or 3389 in ports:
            return "servidor"
    if any(kw in hostname for kw in ("server", "srv", "dc", "ad")):
        return "servidor"
    return "cliente"


def discover_installed_software() -> List[Dict[str, Any]]:
    """Lee software real del SO — NO inventa."""
    software: List[Dict[str, Any]] = []
    if platform.system() != "Windows":
        return [{"name": NA, "note": "Solo Windows soportado actualmente"}]
    try:
        import winreg
        paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        seen = set()
        for hive, path in paths:
            try:
                key = winreg.OpenKey(hive, path)
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        def _val(name):
                            try: return winreg.QueryValueEx(subkey, name)[0]
                            except: return None
                        name = _val("DisplayName")
                        if not name or name in seen:
                            continue
                        seen.add(name)
                        software.append({
                            "name": name,
                            "version": _val("DisplayVersion") or NA,
                            "publisher": _val("Publisher") or NA,
                            "install_date": _val("InstallDate") or NA,
                            "install_location": _val("InstallLocation") or NA,
                            "invented": False,
                        })
                        winreg.CloseKey(subkey)
                    except Exception:
                        pass
                winreg.CloseKey(key)
            except Exception:
                pass
    except ImportError:
        software.append({"name": NA, "note": "winreg no disponible"})
    return software


def discover_services() -> List[Dict[str, Any]]:
    """Lee servicios reales del SO."""
    services: List[Dict[str, Any]] = []
    if platform.system() == "Windows":
        try:
            import psutil
            for svc in psutil.win_service_iter():
                try:
                    info = svc.as_dict()
                    services.append({
                        "name": info.get("name") or NA,
                        "display_name": info.get("display_name") or NA,
                        "status": info.get("status") or NA,
                        "start_type": info.get("start_type") or NA,
                        "pid": info.get("pid"),
                        "username": info.get("username") or NA,
                        "invented": False,
                    })
                except Exception:
                    pass
        except Exception:
            pass
    else:
        try:
            out = _safe_run(["systemctl", "list-units", "--type=service", "--no-pager", "--no-legend"])
            for line in out.strip().splitlines()[:100]:
                parts = line.split()
                if len(parts) >= 4:
                    services.append({
                        "name": parts[0],
                        "status": parts[2],
                        "sub_state": parts[3] if len(parts) > 3 else NA,
                        "invented": False,
                    })
        except Exception:
            pass
    return services


def discover_certificates() -> List[Dict[str, Any]]:
    """Lee certificados reales del almacen del SO."""
    certs: List[Dict[str, Any]] = []
    if platform.system() == "Windows":
        try:
            out = _safe_run([
                "powershell", "-Command",
                "Get-ChildItem Cert:\\LocalMachine\\My,Cert:\\LocalMachine\\Root | "
                "Select-Object -First 30 Subject,Issuer,NotBefore,NotAfter,Thumbprint,SignatureAlgorithm | "
                "ConvertTo-Json -Depth 2"
            ], timeout=15)
            if out.strip():
                import json
                data = json.loads(out)
                if isinstance(data, dict):
                    data = [data]
                for c in data:
                    not_after = str(c.get("NotAfter") or "")
                    expired = False
                    if not_after:
                        try:
                            from dateutil.parser import parse as dparse
                            expired = dparse(not_after) < datetime.now(timezone.utc)
                        except Exception:
                            pass
                    certs.append({
                        "subject": str(c.get("Subject") or NA),
                        "issuer": str(c.get("Issuer") or NA),
                        "not_before": str(c.get("NotBefore") or NA),
                        "not_after": not_after or NA,
                        "thumbprint": str(c.get("Thumbprint") or NA),
                        "algorithm": str(c.get("SignatureAlgorithm") or NA),
                        "expired": expired,
                        "invented": False,
                    })
        except Exception as exc:
            certs.append({"subject": NA, "note": f"Error reading certs: {str(exc)[:100]}"})
    else:
        certs.append({"subject": NA, "note": "Certificate store reading only on Windows currently"})
    return certs


def discover_open_ports_local() -> List[Dict[str, Any]]:
    """Puertos abiertos reales del host local via psutil."""
    ports: List[Dict[str, Any]] = []
    seen = set()
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN" and conn.laddr:
                port = conn.laddr.port
                if port in seen:
                    continue
                seen.add(port)
                ports.append({
                    "port": port,
                    "address": conn.laddr.ip,
                    "pid": conn.pid,
                    "status": "LISTEN",
                    "invented": False,
                })
    except (psutil.AccessDenied, PermissionError):
        ports.append({"port": NA, "note": "Acceso denegado para listar puertos"})
    except Exception as exc:
        ports.append({"port": NA, "note": str(exc)[:100]})
    return sorted(ports, key=lambda p: p.get("port") or 0)


def discover_processes_summary() -> Dict[str, Any]:
    """Resumen de procesos activos reales."""
    try:
        procs = list(psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]))
        return {
            "total": len(procs),
            "top_cpu": sorted(
                [{"pid": p.info["pid"], "name": p.info["name"], "cpu": p.info.get("cpu_percent")} for p in procs if p.info.get("cpu_percent")],
                key=lambda x: x.get("cpu") or 0, reverse=True
            )[:10],
            "top_mem": sorted(
                [{"pid": p.info["pid"], "name": p.info["name"], "mem": p.info.get("memory_percent")} for p in procs if p.info.get("memory_percent")],
                key=lambda x: x.get("mem") or 0, reverse=True
            )[:10],
            "invented": False,
        }
    except Exception:
        return {"total": 0, "note": NA}
