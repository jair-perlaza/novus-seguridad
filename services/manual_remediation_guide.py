"""
Guía de remediación manual — datos reales del hallazgo, sin instrucciones genéricas.
"""
from __future__ import annotations

import os
import platform
import re
import subprocess
from typing import Any, Dict, List, Optional

import psutil

from utils.host_data import get_local_ip, format_ip_or_unavailable
from utils.logger import logger

NO_DATA = "Sin datos disponibles"


def _port_from_finding(finding: dict) -> Optional[int]:
    ev = finding.get("evidencia") or {}
    port = ev.get("puerto") or finding.get("port")
    if port is not None:
        try:
            return int(port)
        except (TypeError, ValueError):
            pass
    m = re.search(r"PORT-(\d+)", str(finding.get("id") or ""), re.I)
    return int(m.group(1)) if m else None


def _pid_from_finding(finding: dict) -> Optional[int]:
    ev = finding.get("evidencia") or {}
    pid = ev.get("pid")
    if pid is not None:
        try:
            return int(pid)
        except (TypeError, ValueError):
            pass
    m = re.search(r"PROC-(\d+)", str(finding.get("id") or ""), re.I)
    return int(m.group(1)) if m else None


def _port_owner_details(port: int) -> List[dict]:
    owners = []
    seen = set()
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr and conn.laddr.port == port and conn.status == "LISTEN" and conn.pid:
                if conn.pid in seen:
                    continue
                seen.add(conn.pid)
                detail = {"pid": conn.pid}
                try:
                    proc = psutil.Process(conn.pid)
                    detail["proceso"] = proc.name()
                    detail["ruta_ejecutable"] = proc.exe()
                    detail["cmdline"] = " ".join(proc.cmdline() or [])
                except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
                    detail["error"] = str(exc)
                svc = _windows_service_for_pid(conn.pid)
                if svc:
                    detail["nombre_servicio"] = svc
                owners.append(detail)
    except (psutil.AccessDenied, psutil.Error) as exc:
        logger.debug("port owner details: %s", exc)
    return owners


def _windows_service_for_pid(pid: int) -> Optional[str]:
    if platform.system() != "Windows":
        return None
    try:
        result = subprocess.run(
            ["tasklist", "/svc", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if str(pid) in line:
                parts = line.split('","')
                if len(parts) >= 2:
                    svc = parts[1].strip('"').strip()
                    if svc and svc != "N/A":
                        return svc
    except Exception:
        pass
    return None


def build_help_buttons(finding: dict) -> List[dict]:
    """Botones funcionales — cada uno mapea a launch-tool en backend."""
    buttons: List[dict] = []
    fid = str(finding.get("id") or "")
    ev = finding.get("evidencia") or {}
    port = _port_from_finding(finding)
    pid = _pid_from_finding(finding)

    if "PORT" in fid and port:
        buttons.append({"id": "firewall", "label": "Abrir Firewall", "tool": "wf.msc"})
        buttons.append({"id": "services", "label": "Abrir Servicios", "tool": "services.msc"})
        owners = _port_owner_details(port)
        if owners:
            pid = owners[0].get("pid") or pid
            exe = owners[0].get("ruta_ejecutable")
            if exe and os.path.isdir(os.path.dirname(exe)):
                buttons.append({
                    "id": "open_folder",
                    "label": "Abrir ubicación del ejecutable",
                    "tool": "explorer_select",
                    "path": exe,
                })

    if pid:
        buttons.append({"id": "taskmgr", "label": "Abrir Administrador de tareas", "tool": "taskmgr"})
        try:
            proc = psutil.Process(pid)
            exe = proc.exe()
            if exe:
                buttons.append({
                    "id": "open_folder",
                    "label": "Abrir carpeta del proceso",
                    "tool": "explorer_select",
                    "path": exe,
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    archivo = ev.get("archivo") or finding.get("file") or finding.get("componente")
    if archivo and os.path.exists(str(archivo)):
        folder = os.path.dirname(str(archivo)) or str(archivo)
        buttons.append({
            "id": "open_file_folder",
            "label": "Abrir carpeta del archivo",
            "tool": "explorer",
            "path": folder,
        })

    if finding.get("tipo") == "firewall_disabled" or "firewall" in str(finding.get("nombre") or "").lower():
        buttons.append({"id": "firewall", "label": "Abrir Firewall", "tool": "wf.msc"})
        buttons.append({"id": "secpol", "label": "Abrir Política de seguridad", "tool": "secpol.msc"})

    buttons.append({"id": "settings", "label": "Abrir Configuración", "tool": "ms-settings:"})
    buttons.append({"id": "defender", "label": "Abrir Windows Defender", "tool": "windowsdefender:"})

    seen = set()
    unique = []
    for b in buttons:
        key = (b.get("tool"), b.get("path"))
        if key not in seen:
            seen.add(key)
            unique.append(b)
    return unique


def build_manual_guide(
    finding: dict,
    strategies_attempted: Optional[List[dict]] = None,
    failure_reasons: Optional[List[str]] = None,
) -> dict:
    """Guía manual específica derivada de evidencia real."""
    fid = str(finding.get("id") or "")
    ev = finding.get("evidencia") or {}
    port = _port_from_finding(finding)
    pid = _pid_from_finding(finding)
    owners = _port_owner_details(port) if port else []

    archivo = ev.get("archivo") or finding.get("file") or finding.get("componente") or NO_DATA
    proceso = ev.get("proceso") or finding.get("nombre") or NO_DATA
    ruta_exe = ev.get("ruta") or NO_DATA
    servicio = NO_DATA
    ventana = NO_DATA
    config_mod = NO_DATA
    pasos: List[dict] = []

    if "PORT" in fid and port:
        owner = owners[0] if owners else {}
        proceso = owner.get("proceso") or proceso
        pid = owner.get("pid") or pid
        ruta_exe = owner.get("ruta_ejecutable") or ruta_exe
        servicio = owner.get("nombre_servicio") or NO_DATA
        ventana = "Firewall de Windows con seguridad avanzada (wf.msc) o Servicios (services.msc)"
        config_mod = f"Regla de firewall bloqueando TCP puerto {port} entrante, o detener servicio '{servicio}'"
        pasos = [
            {
                "orden": 1,
                "titulo": "Identificar el servicio dueño del puerto",
                "instruccion": (
                    f"En Servicios (services.msc), busque el servicio '{servicio}' "
                    f"o el proceso '{proceso}' (PID {pid}) que escucha en puerto {port}."
                ),
                "verificar_despues": False,
            },
            {
                "orden": 2,
                "titulo": "Detener servicio o bloquear puerto",
                "instruccion": (
                    f"Opción A: Detenga el servicio '{servicio}' si no es necesario.\n"
                    f"Opción B: En wf.msc → Reglas de entrada → Nueva regla → Puerto → TCP {port} → Bloquear."
                ),
                "verificar_despues": True,
            },
            {
                "orden": 3,
                "titulo": "Verificación NOVUS",
                "instruccion": "Pulse 'Verificar remediación manual' para que NOVUS re-escaneé el puerto.",
                "verificar_despues": True,
            },
        ]

    elif "PROC" in fid and pid:
        try:
            proc = psutil.Process(pid)
            proceso = proc.name()
            ruta_exe = proc.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        ventana = "Administrador de tareas → Detalles"
        config_mod = f"Finalizar proceso {proceso} (PID {pid}) y eliminar persistencia si aplica"
        pasos = [
            {
                "orden": 1,
                "titulo": "Abrir Administrador de tareas",
                "instruccion": f"Localice PID {pid} — proceso '{proceso}' en ruta {ruta_exe}.",
                "verificar_despues": False,
            },
            {
                "orden": 2,
                "titulo": "Finalizar proceso",
                "instruccion": f"Clic derecho → Finalizar tarea en PID {pid} ({proceso}).",
                "verificar_despues": True,
            },
            {
                "orden": 3,
                "titulo": "Verificación NOVUS",
                "instruccion": "Pulse 'Verificar remediación manual'.",
                "verificar_despues": True,
            },
        ]

    elif finding.get("tipo") == "firewall_disabled":
        ventana = "Firewall de Windows con seguridad avanzada"
        config_mod = "Activar firewall en perfiles Dominio, Privado y Público"
        pasos = [
            {
                "orden": 1,
                "titulo": "Abrir Firewall",
                "instruccion": "Panel de control → Sistema y seguridad → Firewall → Activar/desactivar.",
                "verificar_despues": False,
            },
            {
                "orden": 2,
                "titulo": "Activar todos los perfiles",
                "instruccion": "Marque 'Activar' en Dominio, Privado y Público.",
                "verificar_despues": True,
            },
            {
                "orden": 3,
                "titulo": "Verificación NOVUS",
                "instruccion": "Pulse 'Verificar remediación manual'.",
                "verificar_despues": True,
            },
        ]

    elif ev.get("archivo"):
        ventana = "Explorador de archivos — Propiedades → Seguridad"
        config_mod = f"Restringir permisos de '{archivo}'"
        pasos = [
            {
                "orden": 1,
                "titulo": "Abrir ubicación del archivo",
                "instruccion": f"Navegue a {archivo} → Propiedades → Seguridad.",
                "verificar_despues": False,
            },
            {
                "orden": 2,
                "titulo": "Restringir permisos",
                "instruccion": "Elimine permisos excesivos (Everyone/Usuarios autenticados con escritura).",
                "verificar_despues": True,
            },
            {
                "orden": 3,
                "titulo": "Verificación NOVUS",
                "instruccion": "Pulse 'Verificar remediación manual'.",
                "verificar_despues": True,
            },
        ]

    motivo = NO_DATA
    if failure_reasons:
        motivo = "; ".join(failure_reasons)

    return {
        "titulo": "No fue posible corregir automáticamente esta vulnerabilidad.",
        "motivo_fallo_automatico": motivo,
        "estrategias_intentadas": strategies_attempted or [],
        "donde_esta_el_problema": finding.get("recurso_afectado") or finding.get("causa_probable") or NO_DATA,
        "archivo_afectado": archivo,
        "puerto_abierto": port if port else NO_DATA,
        "servicio_ejecutandose": servicio,
        "proceso_activo": proceso,
        "pid": pid if pid else NO_DATA,
        "ruta_ejecutable": ruta_exe,
        "configuracion_modificar": config_mod,
        "ventana_windows": ventana,
        "ruta_exacta": ruta_exe if ruta_exe != NO_DATA else (f"Puerto {port} en {format_ip_or_unavailable(get_local_ip())}" if port else NO_DATA),
        "nombre_servicio": servicio,
        "nombre_proceso": proceso,
        "riesgo_asociado": finding.get("impacto_potencial") or NO_DATA,
        "dificultad": finding.get("dificultad") or NO_DATA,
        "tiempo_estimado": finding.get("tiempo_correccion") or NO_DATA,
        "pasos_manuales": pasos,
        "botones_ayuda": build_help_buttons(finding),
        "kernel_ofrece": "Acompañarte paso a paso durante la remediación.",
    }


def get_manual_step(finding: dict, step_index: int = 0) -> dict:
    """Paso N de la guía manual (0-based)."""
    guide = build_manual_guide(finding)
    pasos = guide.get("pasos_manuales") or []
    if step_index < 0 or step_index >= len(pasos):
        return {"status": "complete", "message": "Todos los pasos completados. Ejecute verificación final."}
    step = pasos[step_index]
    return {
        "status": "step",
        "step_index": step_index,
        "total_steps": len(pasos),
        "step": step,
        "botones_ayuda": guide.get("botones_ayuda") or [],
        "finding_id": finding.get("id"),
    }
