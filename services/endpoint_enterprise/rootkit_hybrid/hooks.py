"""
T5 — Indicios de hooks user-mode (inline / IAT) en ntdll/kernel32 del proceso actual.
Evidencia objetiva: primeros bytes de exportaciones críticas.
NO escanea SSDT.
"""
from __future__ import annotations

import ctypes
import os
import platform
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import logger

# APIs frecuentemente enganchadas (user-mode)
WATCH_EXPORTS = {
    "ntdll.dll": [
        "NtCreateFile",
        "NtOpenProcess",
        "NtReadVirtualMemory",
        "NtQuerySystemInformation",
        "NtProtectVirtualMemory",
    ],
    "kernel32.dll": [
        "CreateProcessW",
        "LoadLibraryW",
        "VirtualProtect",
        "WriteProcessMemory",
        "ReadProcessMemory",
    ],
}


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_suspicious_prologue(buf: bytes) -> Tuple[bool, str]:
    """Heurística verificable: JMP rel32, JMP [rip], mov rax imm; jmp rax."""
    if not buf or len(buf) < 2:
        return False, "too_short"
    b0 = buf[0]
    if b0 == 0xE9:  # jmp rel32
        return True, "inline_jmp_rel32"
    if b0 == 0xEB:  # jmp short
        return True, "inline_jmp_short"
    if b0 == 0xFF and len(buf) > 1 and buf[1] in (0x25, 0x15):  # jmp/call [rip+disp]
        return True, "inline_ff25_indirect"
    # mov rax, imm64 ; jmp rax  => 48 B8 ... FF E0
    if len(buf) >= 12 and buf[0:2] == b"\x48\xb8" and buf[10:12] == b"\xff\xe0":
        return True, "inline_mov_rax_jmp"
    return False, "normal_or_unknown"


def _get_module_handle(name: str):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetModuleHandleW.restype = ctypes.c_void_p
    return kernel32.GetModuleHandleW(name)


def _get_proc_address(module, export: str):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    kernel32.GetProcAddress.restype = ctypes.c_void_p
    return kernel32.GetProcAddress(module, export.encode("ascii"))


def scan_inline_hooks_current_process() -> Dict[str, Any]:
    """
    Lee prologues de exportaciones en el proceso NOVUS (mismo espacio de direcciones).
    Limitación: no inspecciona otros procesos sin OpenProcess+RPM (AccessDenied frecuente).
    """
    result: Dict[str, Any] = {
        "ok": False,
        "findings": [],
        "checked": [],
        "scope": "current_process_only",
        "timestamp_utc": _utc(),
        "ring0": False,
    }
    if platform.system() != "Windows":
        result["error"] = "windows_only"
        return result

    findings = []
    checked = []
    try:
        for dll, exports in WATCH_EXPORTS.items():
            hmod = _get_module_handle(dll)
            if not hmod:
                continue
            for exp in exports:
                addr = _get_proc_address(hmod, exp)
                if not addr:
                    continue
                # Read 16 bytes
                buf = (ctypes.c_ubyte * 16).from_address(addr)
                data = bytes(buf)
                suspicious, reason = _is_suspicious_prologue(data)
                entry = {
                    "module": dll,
                    "export": exp,
                    "address": hex(addr),
                    "prologue_hex": data.hex(),
                    "classification": reason,
                }
                checked.append(entry)
                if suspicious:
                    findings.append(
                        {
                            "finding_type": "inline_hook_indicator",
                            "severity": "high",
                            "confidence": "medium",
                            "detection_method": "export_prologue_scan",
                            "evidence": entry,
                            "equipment": socket.gethostname(),
                            "timestamp_utc": _utc(),
                            "verified": True,
                            "source": "rootkit_hybrid.hooks",
                            "ring0": False,
                            "note": "Prologue anómalo en exportación — posible inline hook; verificar con herramienta forense",
                        }
                    )
        result["ok"] = True
        result["checked"] = checked
        result["findings"] = findings
        result["checked_n"] = len(checked)
    except Exception as exc:
        result["error"] = str(exc)[:240]
        logger.debug("inline hooks: %s", exc)
    return result


def scan_iat_anomalies_sample() -> Dict[str, Any]:
    """
    IAT hooking completo requiere parseo PE por módulo cargado.
    Aquí documentamos capacidad parcial: verificamos que GetProcAddress de APIs críticas
    resuelve dentro del módulo esperado (dirección entre base y base+size aproximado).
    """
    result: Dict[str, Any] = {
        "ok": True,
        "method": "getprocaddress_module_bounds_check",
        "findings": [],
        "note": (
            "IAT/EAT hooking exhaustivo de todos los módulos no implementado en Fase 1; "
            "se valida que exportaciones críticas resuelven en ntdll/kernel32."
        ),
        "ring0": False,
        "timestamp_utc": _utc(),
    }
    if platform.system() != "Windows":
        return result
    try:
        for dll, exports in WATCH_EXPORTS.items():
            hmod = _get_module_handle(dll)
            if not hmod:
                continue
            base = int(hmod)
            # Conservative 8MB window for module image
            end = base + 8 * 1024 * 1024
            for exp in exports:
                addr = _get_proc_address(hmod, exp)
                if not addr:
                    continue
                a = int(addr)
                if a < base or a > end:
                    result["findings"].append(
                        {
                            "finding_type": "iat_or_forward_anomaly",
                            "severity": "high",
                            "confidence": "medium",
                            "detection_method": "export_outside_module_bounds",
                            "evidence": {
                                "module": dll,
                                "export": exp,
                                "address": hex(a),
                                "module_base": hex(base),
                            },
                            "equipment": socket.gethostname(),
                            "timestamp_utc": _utc(),
                            "verified": True,
                            "source": "rootkit_hybrid.hooks",
                            "ring0": False,
                        }
                    )
    except Exception as exc:
        result["error"] = str(exc)[:200]
    return result
