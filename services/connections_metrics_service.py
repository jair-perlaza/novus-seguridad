"""
Métricas verificables de conexiones de red del host NOVUS (psutil).
Fuente única para Dashboard, XDR y APIs — sin valores simulados.
"""
from __future__ import annotations

import socket
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import psutil

from utils.logger import logger

NOVUS_PROCESS_HINTS = ("python", "py.exe", "novus", "flask", "waitress", "gunicorn")
NGROK_HINTS = ("ngrok",)
CURSOR_HINTS = ("cursor",)
BROWSER_HINTS = ("chrome", "msedge", "firefox", "brave", "opera", "iexplore")


def _now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _is_loopback(addr) -> bool:
    if not addr:
        return False
    ip = addr.ip if hasattr(addr, "ip") else str(addr)
    if not ip:
        return False
    return ip.startswith("127.") or ip == "::1"


def _proc_name(pid: Optional[int], cache: Dict[int, str]) -> str:
    if pid is None:
        return "Sistema / no disponible"
    if pid in cache:
        return cache[pid]
    try:
        cache[pid] = psutil.Process(pid).name()
    except Exception:
        cache[pid] = f"pid-{pid}"
    return cache[pid]


def _classify_process(name: str) -> str:
    low = (name or "").lower()
    if any(h in low for h in NOVUS_PROCESS_HINTS):
        return "novus"
    if any(h in low for h in NGROK_HINTS):
        return "ngrok"
    if any(h in low for h in CURSOR_HINTS):
        return "cursor"
    if any(h in low for h in BROWSER_HINTS):
        return "browser"
    if low in ("system", "svchost.exe", "services.exe", "lsass.exe", "wininit.exe"):
        return "sistema_windows"
    return "otros"


def _port(c) -> Optional[int]:
    if c.laddr:
        return c.laddr.port
    return None


def _remote_port(c) -> Optional[int]:
    if c.raddr:
        return c.raddr.port
    return None


def analyze_host_connections() -> Dict[str, Any]:
    """
    Analiza psutil.net_connections(kind='inet') en el nodo NOVUS.
    Retorna desglose completo + metadatos para UI.
    """
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as exc:
        logger.error("connections_metrics: %s", exc)
        return {
            "available": False,
            "error": str(exc),
            "updated_at": _now_iso(),
        }

    proc_cache: Dict[int, str] = {}
    by_status: Counter = Counter()
    by_process: Counter = Counter()
    tcp = udp = other_proto = 0
    ipv4 = ipv6 = 0
    local_only = remote = 0
    https = dns = 0
    established = listen = time_wait = 0
    novus_n = ngrok_n = cursor_n = browser_n = system_n = 0

    samples: List[Dict[str, Any]] = []

    for c in conns:
        status = (c.status or "NONE").upper()
        by_status[status] += 1
        if status == "ESTABLISHED":
            established += 1
        elif status == "LISTEN":
            listen += 1
        elif status == "TIME_WAIT":
            time_wait += 1

        if c.type == socket.SOCK_STREAM:
            tcp += 1
        elif c.type == socket.SOCK_DGRAM:
            udp += 1
        else:
            other_proto += 1

        fam = getattr(c, "family", None)
        if fam == socket.AF_INET6:
            ipv6 += 1
        else:
            ipv4 += 1

        loc_loop = _is_loopback(c.laddr)
        rem_loop = _is_loopback(c.raddr) if c.raddr else False
        has_remote = bool(c.raddr and c.raddr.ip)
        if has_remote and not rem_loop:
            remote += 1
        if loc_loop or rem_loop or (not has_remote and loc_loop):
            local_only += 1

        lp, rp = _port(c), _remote_port(c)
        if lp in (443, 8443) or rp in (443, 8443):
            https += 1
        if lp == 53 or rp == 53:
            dns += 1

        pname = _proc_name(c.pid, proc_cache)
        by_process[pname] += 1
        bucket = _classify_process(pname)
        if bucket == "novus":
            novus_n += 1
        elif bucket == "ngrok":
            ngrok_n += 1
        elif bucket == "cursor":
            cursor_n += 1
        elif bucket == "browser":
            browser_n += 1
        elif bucket == "sistema_windows":
            system_n += 1

        if len(samples) < 40:
            samples.append({
                "pid": c.pid,
                "process": pname,
                "family": "IPv6" if fam == socket.AF_INET6 else "IPv4",
                "type": "TCP" if c.type == socket.SOCK_STREAM else ("UDP" if c.type == socket.SOCK_DGRAM else "OTHER"),
                "status": status,
                "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "—",
                "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "—",
            })

    total = len(conns)
    established_remote = sum(
        1 for c in conns
        if (c.status or "").upper() == "ESTABLISHED"
        and c.raddr
        and c.raddr.ip
        and not _is_loopback(c.raddr)
    )

    risk = "normal"
    if established_remote > 150:
        risk = "elevado"
    if established_remote > 300:
        risk = "alto"

    top_processes = [
        {"process": name, "connections": count}
        for name, count in by_process.most_common(12)
    ]

    return {
        "available": True,
        "updated_at": _now_iso(),
        "source": "psutil.net_connections(kind='inet')",
        "host_scope": "Nodo NOVUS (host local del servidor)",
        "definition": (
            "Conteo de sockets de red IPv4/IPv6 visibles para el proceso NOVUS vía psutil. "
            "Incluye LISTEN, ESTABLISHED, TIME_WAIT y otros estados del sistema operativo."
        ),
        "total": total,
        "display_primary": total,
        "display_primary_label": "Sockets de red (IPv4/IPv6)",
        "established_remote": established_remote,
        "established_remote_label": "TCP/UDP establecidas hacia remoto",
        "tcp": tcp,
        "udp": udp,
        "other_protocol": other_proto,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "local_loopback_or_sin_remoto": local_only,
        "remote_endpoints": remote,
        "https_related": https,
        "dns_related": dns,
        "by_status": dict(by_status),
        "established": established,
        "listen": listen,
        "time_wait": time_wait,
        "by_process_category": {
            "novus_stack": novus_n,
            "ngrok": ngrok_n,
            "cursor_ide": cursor_n,
            "navegador": browser_n,
            "sistema_windows": system_n,
            "otros": total - novus_n - ngrok_n - cursor_n - browser_n - system_n,
        },
        "top_processes": top_processes,
        "samples": samples,
        "risk_level": risk,
        "is_normal_hint": (
            "Valores altos son habituales en Windows con navegador, IDE y servicios en segundo plano. "
            "Revise ESTABLISHED remotas si sospecha exfiltración o C2."
        ),
        "recommended_actions": [
            "Abra el desglose para ver procesos y estados (LISTEN vs ESTABLISHED).",
            "Correlacione con NDR si hay conexiones remotas anómalas hacia el gateway.",
            "No interpretar TIME_WAIT como sesiones activas de usuario.",
        ],
        "calculation": "Un socket = una fila devuelta por psutil; no implica una sesión de usuario única.",
    }


def get_summary_for_dashboard() -> Tuple[Optional[int], Dict[str, Any]]:
    """Valor principal + metadatos para /api/dashboard/live."""
    from services.performance_cache import get_or_compute
    from core.config import Config

    detail = get_or_compute(
        "host_connections_detail",
        Config.PROCESS_CONN_CACHE_TTL,
        analyze_host_connections,
    )
    if not detail.get("available"):
        return None, {"available": False, "updated_at": detail.get("updated_at")}
    meta = {
        "available": True,
        "value": detail["display_primary"],
        "label": detail["display_primary_label"],
        "definition": detail["definition"],
        "source": detail["source"],
        "updated_at": detail["updated_at"],
        "established_remote": detail["established_remote"],
        "risk_level": detail["risk_level"],
    }
    return detail["display_primary"], meta
