"""
Integración best-effort con firewall del sistema operativo (Windows netsh).
Complementa IPBloqueada en SQLite — no reemplaza el registro central.
Requiere elevación de administrador en Windows para aplicar reglas.
"""
from __future__ import annotations

import platform
import subprocess
from typing import Any, Dict

from utils.logger import logger


def _rule_name(ip: str) -> str:
    safe = str(ip).replace(".", "-").replace(":", "-")[:40]
    return f"NOVUS-Block-IP-{safe}"


def block_ip_os(ip: str) -> Dict[str, Any]:
    """Intenta bloquear IP entrante vía netsh advfirewall (Windows)."""
    if not ip or str(ip) in ("127.0.0.1", "localhost", "::1"):
        return {"status": "skipped", "detail": "IP local no bloqueable", "os_rule": None}
    if platform.system() != "Windows":
        return {"status": "skipped", "detail": "Firewall OS solo implementado en Windows", "os_rule": None}
    rule = _rule_name(ip)
    try:
        proc = subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule}",
                "dir=in", "action=block", f"remoteip={ip}", "enable=yes",
            ],
            capture_output=True, text=True, timeout=15,
        )
        if proc.returncode == 0:
            return {"status": "done", "detail": f"Regla {rule} aplicada", "os_rule": rule}
        detail = (proc.stderr or proc.stdout or "").strip()[:300]
        if "requiere elevación" in detail.lower() or "elevation" in detail.lower():
            return {"status": "skipped", "detail": "Requiere elevación de administrador", "os_rule": rule}
        return {"status": "failed", "detail": detail or f"exit={proc.returncode}", "os_rule": rule}
    except Exception as exc:
        logger.debug("os_firewall block_ip: %s", exc)
        return {"status": "failed", "detail": str(exc), "os_rule": rule}


def unblock_ip_os(ip: str) -> Dict[str, Any]:
    """Elimina regla de bloqueo OS si existe."""
    if platform.system() != "Windows":
        return {"status": "skipped", "detail": "Solo Windows"}
    rule = _rule_name(ip)
    try:
        proc = subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"],
            capture_output=True, text=True, timeout=15,
        )
        if proc.returncode == 0:
            return {"status": "done", "detail": f"Regla {rule} eliminada"}
        return {"status": "skipped", "detail": (proc.stderr or proc.stdout or "")[:200]}
    except Exception as exc:
        return {"status": "failed", "detail": str(exc)}


def get_os_firewall_status() -> Dict[str, Any]:
    """Estado del firewall Windows vía netsh."""
    if platform.system() != "Windows":
        return {"platform": platform.system(), "available": False}
    try:
        proc = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True, text=True, timeout=10,
        )
        return {
            "platform": "Windows",
            "available": True,
            "exit_code": proc.returncode,
            "output": (proc.stdout or "")[:500],
        }
    except Exception as exc:
        return {"platform": "Windows", "available": False, "error": str(exc)}
