"""
T4 — Análisis de memoria de proceso (mapas, RWX, DLL sospechosas).
Datos reales vía psutil.memory_maps / Windows cuando hay acceso.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import psutil

from utils.logger import logger

SUSPICIOUS_DLL_NAMES = {
    "reflective_dll.dll",
    "inject.dll",
}


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def analyze_process_maps(pid: int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    meta: Dict[str, Any] = {"pid": pid, "maps": 0, "access_denied": False}
    try:
        proc = psutil.Process(pid)
        name = proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
        meta["error"] = str(exc)[:120]
        meta["access_denied"] = True
        return findings, meta

    try:
        maps = proc.memory_maps(grouped=False)
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        meta["access_denied"] = True
        meta["limitation"] = "memory_maps AccessDenied — requiere privilegios / proceso no protegido"
        return findings, meta
    except Exception as exc:
        meta["error"] = str(exc)[:160]
        return findings, meta

    meta["maps"] = len(maps)
    rwx = []
    weird_dlls = []
    for m in maps:
        path = (getattr(m, "path", None) or "").lower()
        perms = (getattr(m, "perms", None) or "").lower()
        # psutil perms like 'r--', 'rw-', 'rwx'
        if "x" in perms and "w" in perms:
            rwx.append({"path": path or "[anonymous]", "perms": perms, "rss": getattr(m, "rss", None)})
        base = os.path.basename(path) if path else ""
        if base in SUSPICIOUS_DLL_NAMES or (
            path
            and path.endswith(".dll")
            and any(x in path for x in ("\\temp\\", "\\downloads\\", "\\appdata\\local\\temp\\"))
        ):
            weird_dlls.append({"path": path, "perms": perms})

    if rwx:
        findings.append(
            {
                "finding_type": "rwx_memory_region",
                "severity": "high",
                "confidence": "medium",
                "evidence": {
                    "pid": pid,
                    "process": name,
                    "rwx_count": len(rwx),
                    "sample": rwx[:10],
                    "note": "Páginas RWX observadas vía memory_maps (posible shellcode/inject)",
                },
                "timestamp_utc": _utc(),
                "verified": True,
                "source": "endpoint_enterprise.memory_analysis",
            }
        )
    if weird_dlls:
        findings.append(
            {
                "finding_type": "suspicious_dll_mapping",
                "severity": "high",
                "confidence": "high",
                "evidence": {"pid": pid, "process": name, "dlls": weird_dlls[:15]},
                "timestamp_utc": _utc(),
                "verified": True,
                "source": "endpoint_enterprise.memory_analysis",
            }
        )
    return findings, meta


def analyze_sample_processes(*, limit: int = 15) -> List[Dict[str, Any]]:
    """Muestrea procesos no-sistema para no saturar CPU."""
    out: List[Dict[str, Any]] = []
    skip = {"system", "idle", "registry", "smss.exe", "csrss.exe", "wininit.exe"}
    n = 0
    for p in psutil.process_iter(["pid", "name"]):
        if n >= limit:
            break
        try:
            name = (p.info.get("name") or "").lower()
            if name in skip or name in ("svchost.exe",):
                continue
            findings, _meta = analyze_process_maps(int(p.info["pid"]))
            out.extend(findings)
            n += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
            continue
    return out
