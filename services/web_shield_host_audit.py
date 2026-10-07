"""Auditoría verificable de proxy, DNS, hosts y extensiones locales — Web Shield."""
from __future__ import annotations

import hashlib
import os
import platform
import subprocess
from typing import Any, Dict, List, Optional

from utils.logger import logger

_HOSTS_PATH = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "drivers", "etc", "hosts")


def _hash_file(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except Exception:
        return None


def read_hosts_snapshot() -> Dict[str, Any]:
    if not os.path.isfile(_HOSTS_PATH):
        return {"path": _HOSTS_PATH, "available": False}
    try:
        with open(_HOSTS_PATH, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        entries = []
        for line in lines:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            entries.append(s[:500])
        return {
            "path": _HOSTS_PATH,
            "available": True,
            "sha256": _hash_file(_HOSTS_PATH),
            "entry_count": len(entries),
            "entries_sample": entries[:15],
        }
    except Exception as exc:
        return {"path": _HOSTS_PATH, "available": False, "error": str(exc)}


def read_windows_proxy() -> Dict[str, Any]:
    if platform.system().lower() != "windows":
        return {"available": False, "reason": "Solo Windows en este nodo"}
    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        )
        enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
        proxy_server = winreg.QueryValueEx(key, "ProxyServer")[0] if enable else ""
        winreg.CloseKey(key)
        return {
            "available": True,
            "proxy_enabled": bool(enable),
            "proxy_server": proxy_server or None,
            "source": "registry:Internet Settings",
        }
    except Exception as exc:
        return {"available": False, "error": str(exc)}


def read_dns_servers() -> Dict[str, Any]:
    """DNS normalizado — sin raw_excerpt (no exponer stdout a UI/API)."""
    from services.network_dns_service import get_live_dns_info

    return get_live_dns_info()


def list_browser_extension_folders() -> Dict[str, Any]:
    """Solo cuenta carpetas bajo rutas estándar — sin analizar contenido privado del navegador."""
    local = os.environ.get("LOCALAPPDATA", "")
    paths = [
        os.path.join(local, "Google", "Chrome", "User Data", "Default", "Extensions"),
        os.path.join(local, "Microsoft", "Edge", "User Data", "Default", "Extensions"),
    ]
    out: List[Dict[str, Any]] = []
    for p in paths:
        if not os.path.isdir(p):
            continue
        try:
            ids = [d for d in os.listdir(p) if os.path.isdir(os.path.join(p, d))]
            out.append({
                "browser_path": p,
                "extension_folder_count": len(ids),
                "sample_ids": ids[:5],
            })
        except Exception as exc:
            out.append({"browser_path": p, "error": str(exc)})
    return {
        "available": bool(out),
        "browsers": out,
        "note": "Conteo de carpetas de extensiones; no implica malware sin análisis adicional.",
    }


def full_host_audit() -> Dict[str, Any]:
    return {
        "hosts": read_hosts_snapshot(),
        "proxy": read_windows_proxy(),
        "dns": read_dns_servers(),
        "extensions": list_browser_extension_folders(),
    }
