"""
T1 — Telemetría comportamental real (psutil / registro / SCM).
Sin firmas; solo inventario observable en user-mode.
"""
from __future__ import annotations

import platform
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Set

import psutil

from utils.logger import logger


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def collect_process_telemetry(*, limit: int = 220) -> Dict[str, Any]:
    procs: List[Dict[str, Any]] = []
    names: Set[str] = set()
    by_user: Dict[str, int] = {}
    n = 0
    for p in psutil.process_iter(["pid", "name", "exe", "username", "ppid", "create_time", "cpu_percent", "memory_percent"]):
        if n >= limit:
            break
        try:
            info = p.info
            name = (info.get("name") or "").lower()
            user = info.get("username") or "unknown"
            names.add(name)
            by_user[user] = by_user.get(user, 0) + 1
            procs.append(
                {
                    "pid": int(info["pid"]),
                    "name": name,
                    "exe": info.get("exe"),
                    "user": user,
                    "ppid": info.get("ppid"),
                    "create_time": info.get("create_time"),
                    "cpu": float(info.get("cpu_percent") or 0),
                    "mem": float(info.get("memory_percent") or 0),
                }
            )
            n += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError, KeyError):
            continue
    return {
        "count": len(procs),
        "names": sorted(names),
        "by_user": by_user,
        "sample": procs,
    }


def collect_connection_telemetry(*, limit: int = 400) -> Dict[str, Any]:
    remotes: List[str] = []
    by_status: Dict[str, int] = {}
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:160], "count": 0, "remotes": [], "by_status": {}}
    n = 0
    for c in conns:
        if n >= limit:
            break
        st = str(c.status or "NONE")
        by_status[st] = by_status.get(st, 0) + 1
        if c.raddr:
            remotes.append(f"{c.raddr.ip}:{c.raddr.port}")
        n += 1
    # unique remotes (cap)
    uniq = sorted(set(remotes))[:200]
    return {
        "ok": True,
        "count": len(conns),
        "sampled": n,
        "remotes": uniq,
        "remote_n": len(set(remotes)),
        "by_status": by_status,
    }


def collect_service_telemetry() -> Dict[str, Any]:
    running: Set[str] = set()
    all_names: Set[str] = set()
    if not hasattr(psutil, "win_service_iter"):
        return {"ok": False, "running": [], "all": [], "counts": {}}
    try:
        for s in psutil.win_service_iter():
            try:
                name = s.name().lower()
                all_names.add(name)
                if s.status() == "running":
                    running.add(name)
            except Exception:
                continue
    except Exception as exc:
        logger.debug("btde services: %s", exc)
        return {"ok": False, "error": str(exc)[:160], "running": [], "all": []}
    return {
        "ok": True,
        "running": sorted(running),
        "all": sorted(all_names),
        "counts": {"running": len(running), "all": len(all_names)},
    }


def collect_user_session_telemetry() -> Dict[str, Any]:
    users = []
    try:
        for u in psutil.users():
            users.append(
                {
                    "name": u.name,
                    "terminal": getattr(u, "terminal", None),
                    "started": getattr(u, "started", None),
                }
            )
    except Exception:
        pass
    return {"users": users, "users_n": len(users)}


def collect_resource_telemetry() -> Dict[str, Any]:
    try:
        cpu = float(psutil.cpu_percent(interval=0.15))
        mem = psutil.virtual_memory()
        disk_pct = None
        try:
            root = "C:\\" if platform.system() == "Windows" else "/"
            disk_pct = float(psutil.disk_usage(root).percent)
        except Exception:
            try:
                parts = psutil.disk_partitions(all=False)
                if parts:
                    disk_pct = float(psutil.disk_usage(parts[0].mountpoint).percent)
            except Exception:
                disk_pct = None
        return {
            "cpu_percent": cpu,
            "mem_percent": float(mem.percent),
            "disk_percent": disk_pct,
        }
    except Exception as exc:
        return {"error": str(exc)[:120]}


def collect_persistence_sample() -> Dict[str, Any]:
    """Run keys (HKCU/HKLM) — evidencia objetiva de persistencia registrada."""
    keys_found: List[Dict[str, str]] = []
    if platform.system() != "Windows":
        return {"ok": False, "entries": [], "count": 0}
    try:
        import winreg

        paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]
        for root, path in paths:
            try:
                key = winreg.OpenKey(root, path)
                i = 0
                while i < 40:
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        keys_found.append({"hive": path, "name": str(name), "value": str(val)[:300]})
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except OSError:
                continue
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:160], "entries": [], "count": 0}
    return {"ok": True, "entries": keys_found, "count": len(keys_found), "names": sorted({e["name"].lower() for e in keys_found})}


def collect_driver_count() -> Dict[str, Any]:
    """Conteo ligero vía psutil modules no aplica; usa driverquery count cacheado en rootkit o skip."""
    # Evitar driverquery costoso cada ciclo — solo en heavy vía engine
    return {"deferred": True}


def collect_full_snapshot(*, heavy: bool = False) -> Dict[str, Any]:
    snap = {
        "timestamp_utc": _utc(),
        "equipment": socket.gethostname(),
        "processes": collect_process_telemetry(limit=260 if heavy else 180),
        "connections": collect_connection_telemetry(limit=500 if heavy else 300),
        "services": collect_service_telemetry(),
        "sessions": collect_user_session_telemetry(),
        "resources": collect_resource_telemetry(),
        "persistence": collect_persistence_sample() if heavy else {"deferred": True},
        "heavy": heavy,
    }
    return snap
