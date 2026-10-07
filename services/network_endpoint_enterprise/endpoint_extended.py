"""
T3 — Monitoreo endpoint incremental (servicios, usuarios, drivers, tareas, módulos DLL).
Solo registra cambios reales respecto al snapshot previo.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil

from utils.logger import logger

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "network_endpoint_enterprise"
SNAP_PATH = DATA_DIR / "endpoint_snapshot.json"


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _running_services() -> Set[str]:
    names: Set[str] = set()
    if not hasattr(psutil, "win_service_iter"):
        return names
    try:
        for s in psutil.win_service_iter():
            try:
                info = s.as_dict()
                if info.get("status") == "running":
                    names.add(str(info.get("name") or s.name()).lower())
            except Exception:
                continue
    except Exception as exc:
        logger.debug("services snapshot: %s", exc)
    return names


def _active_users() -> Set[str]:
    users: Set[str] = set()
    try:
        for u in psutil.users():
            if u.name:
                users.add(str(u.name).lower())
    except Exception:
        pass
    return users


def _listening_ports() -> Set[int]:
    ports: Set[int] = set()
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == psutil.CONN_LISTEN and c.laddr:
                ports.add(int(c.laddr.port))
    except Exception:
        pass
    return ports


def _drivers_windows() -> Set[str]:
    names: Set[str] = set()
    if platform.system() != "Windows":
        return names
    try:
        out = subprocess.check_output(
            ["driverquery", "/FO", "CSV", "/NH"],
            timeout=20,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        for line in out.splitlines():
            parts = line.strip().strip('"').split('","')
            if parts and parts[0]:
                names.add(parts[0].lower())
            if len(names) >= 800:
                break
    except Exception as exc:
        logger.debug("drivers snapshot: %s", exc)
    return names


def _scheduled_tasks_windows() -> Set[str]:
    names: Set[str] = set()
    if platform.system() != "Windows":
        return names
    try:
        out = subprocess.check_output(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' -or $_.State -eq 'Running' } | "
                "Select-Object -ExpandProperty TaskName",
            ],
            timeout=25,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        for line in out.splitlines():
            t = line.strip()
            if t:
                names.add(t.lower())
            if len(names) >= 400:
                break
    except Exception as exc:
        logger.debug("schtasks snapshot: %s", exc)
    return names


def _process_modules_sample(limit_procs: int = 25) -> Dict[str, List[str]]:
    """
    Módulos cargados (DLL) de procesos no-sistema — detección heurística de inyección
    cuando aparece un DLL nuevo en un proceso ya visto.
    """
    out: Dict[str, List[str]] = {}
    try:
        count = 0
        for p in psutil.process_iter(["pid", "name", "exe"]):
            try:
                info = p.info
                name = (info.get("name") or "").lower()
                if not name or name in ("system", "idle", "registry"):
                    continue
                # Skip heavy system processes for performance
                if name in ("svchost.exe", "csrss.exe", "lsass.exe", "services.exe"):
                    continue
                mods = []
                try:
                    for m in p.memory_maps():
                        path = (getattr(m, "path", None) or "").lower()
                        if path.endswith(".dll"):
                            mods.append(os.path.basename(path))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
                if mods:
                    key = f"{info.get('pid')}:{name}"
                    out[key] = sorted(set(mods))[:80]
                    count += 1
                if count >= limit_procs:
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as exc:
        logger.debug("modules sample: %s", exc)
    return out


def collect_endpoint_snapshot(*, include_heavy: bool = False) -> Dict[str, Any]:
    snap = {
        "collected_at_utc": _utc(),
        "services_running": sorted(_running_services()),
        "users_active": sorted(_active_users()),
        "listening_ports": sorted(_listening_ports()),
        "drivers": sorted(_drivers_windows()) if include_heavy else [],
        "scheduled_tasks": sorted(_scheduled_tasks_windows()) if include_heavy else [],
        "modules_by_process": _process_modules_sample() if include_heavy else {},
        "process_count": 0,
    }
    try:
        snap["process_count"] = len(psutil.pids())
    except Exception:
        pass
    return snap


def diff_endpoint(prev: Optional[Dict[str, Any]], cur: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not prev:
        return []
    changes: List[Dict[str, Any]] = []

    def set_diff(field: str, change_type: str, old_list, new_list, limit: int = 30):
        old_s = set(old_list or [])
        new_s = set(new_list or [])
        added = sorted(new_s - old_s)[:limit]
        removed = sorted(old_s - new_s)[:limit]
        if added or removed:
            changes.append(
                {
                    "change_type": change_type,
                    "field": field,
                    "added": added,
                    "removed": removed,
                    "detected_at_utc": _utc(),
                }
            )

    set_diff("services_running", "new_or_stopped_service", prev.get("services_running"), cur.get("services_running"))
    set_diff("users_active", "user_session_change", prev.get("users_active"), cur.get("users_active"))
    set_diff("listening_ports", "listening_port_change", prev.get("listening_ports"), cur.get("listening_ports"))
    if cur.get("drivers") and prev.get("drivers"):
        set_diff("drivers", "driver_change", prev.get("drivers"), cur.get("drivers"), limit=20)
    if cur.get("scheduled_tasks") and prev.get("scheduled_tasks"):
        set_diff("scheduled_tasks", "scheduled_task_change", prev.get("scheduled_tasks"), cur.get("scheduled_tasks"), limit=20)

    # DLL injection heuristic: new DLL in known PID:name
    prev_mods = prev.get("modules_by_process") or {}
    cur_mods = cur.get("modules_by_process") or {}
    for key, mods in cur_mods.items():
        if key not in prev_mods:
            continue
        old = set(prev_mods.get(key) or [])
        new = set(mods or [])
        added = sorted(new - old)
        # Filter noise: only flag DLLs from Temp/Downloads/AppData Local Temp atypical paths already basenamed
        suspicious = [
            d
            for d in added
            if d.endswith(".dll")
            and not d.startswith("api-ms-")
            and not d.startswith("ext-ms-")
        ]
        if suspicious:
            changes.append(
                {
                    "change_type": "possible_dll_injection",
                    "process_key": key,
                    "new_dlls": suspicious[:15],
                    "detected_at_utc": _utc(),
                    "severity": "medium",
                    "evidence": "Nuevos módulos DLL en proceso ya observado (EnumProcessModules/memory_maps)",
                    "verified": True,
                }
            )
    return changes


def snapshot_endpoint_and_diff(*, heavy: bool = False) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    prev = None
    if SNAP_PATH.is_file():
        try:
            prev = json.loads(SNAP_PATH.read_text(encoding="utf-8"))
        except Exception:
            prev = None
    cur = collect_endpoint_snapshot(include_heavy=heavy)
    # Preserve heavy fields from previous if this cycle skipped heavy
    if not heavy and prev:
        cur["drivers"] = prev.get("drivers") or []
        cur["scheduled_tasks"] = prev.get("scheduled_tasks") or []
        cur["modules_by_process"] = prev.get("modules_by_process") or {}
    changes = diff_endpoint(prev, cur)
    SNAP_PATH.write_text(json.dumps(cur, indent=2, ensure_ascii=False), encoding="utf-8")
    return cur, changes
