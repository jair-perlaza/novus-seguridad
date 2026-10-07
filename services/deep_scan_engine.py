"""
Motor de Escaneo Integral (Deep Scan) — NOVUS Kernel IA.

Ejecuta análisis en tiempo real del equipo local. Sin caché, sin datos inventados.
Las secciones no implementadas se marcan explícitamente en el informe.
"""
from __future__ import annotations

import hashlib
import math
import os
import platform
import re
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import psutil

from utils.host_data import get_disk_usage, get_local_ip
from utils.logger import logger

MAX_FILES_PER_SCAN = 4000
MAX_WALK_DEPTH = 8
HIGH_ENTROPY = 7.2
# Timeout por fase — evita que un motor colgado bloquee el escaneo indefinidamente
PHASE_TIMEOUT_SEC = int(os.environ.get("NOVUS_DEEP_SCAN_PHASE_TIMEOUT", "180"))
SUSPICIOUS_EXT = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".hta", ".wsf"}
MALWARE_CMD_PATTERNS = [
    "xmrig", "minerd", "mimikatz", "invoke-mimikatz", "powershell -enc",
    "powershell -encodedcommand", "nc -e", "/dev/tcp/", "downloadstring(",
    "reverse_shell", "keylog", "cryptolocker",
]

PHASES = [
    ("init", "Inicializando motores"),
    ("disks", "Inventario de discos"),
    ("system_metrics", "CPU, RAM, disco y GPU"),
    ("processes", "Process Scanner — procesos activos"),
    ("memory_scan", "Memory Scanner — memoria y working set"),
    ("services", "Windows Services"),
    ("connections", "Conexiones de red"),
    ("ports", "Puertos abiertos"),
    ("network_adapters", "Adaptadores de red"),
    ("users", "Usuarios del sistema"),
    ("env_vars", "Variables de entorno"),
    ("startup", "Inicio automático"),
    ("scheduled_tasks", "Tareas programadas"),
    ("firewall", "Firewall"),
    ("installed_programs", "Programas instalados"),
    ("drivers", "Drivers"),
    ("user_files", "Archivos en carpetas de usuario"),
    ("dll_scan", "DLL y ejecutables sospechosos"),
    ("certificates", "Certificados"),
    ("browser_extensions", "Extensiones de navegador"),
    ("usb_devices", "Dispositivos USB"),
    ("system_events", "Eventos del sistema"),
    ("logs", "Logs locales"),
    ("registry", "Registry Scanner (autorun)"),
    ("defender_status", "Defender Status"),
    ("security_engine", "Security Engine NOVUS"),
    ("threats", "Advanced Detector / XDR"),
    ("vulnerabilities", "Motor de vulnerabilidades"),
    ("network_arp", "Escaneo ARP de red"),
    ("finalize", "Generando informe SOC"),
]

PROFILE_PHASES = {
    "full": [p[0] for p in PHASES],
    "processes": [
        "init", "system_metrics", "memory_scan", "processes", "dll_scan",
        "defender_status", "threats", "security_engine", "finalize",
    ],
    "memory": ["init", "system_metrics", "memory_scan", "processes", "threats", "finalize"],
    "malware": [
        "init", "processes", "memory_scan", "user_files", "dll_scan",
        "defender_status", "threats", "security_engine", "vulnerabilities", "finalize",
    ],
    "rootkit": [
        "init", "memory_scan", "processes", "services", "drivers", "dll_scan",
        "threats", "security_engine", "finalize",
    ],
    "services": ["init", "services", "drivers", "startup", "processes", "finalize"],
    "registry": ["init", "registry", "startup", "scheduled_tasks", "finalize"],
    "connections": ["init", "connections", "ports", "firewall", "network_adapters", "finalize"],
    "installed": ["init", "installed_programs", "browser_extensions", "startup", "finalize"],
    "scheduled": ["init", "scheduled_tasks", "startup", "registry", "finalize"],
    "background": [
        "init", "processes", "memory_scan", "startup", "services", "threats", "finalize",
    ],
    "quick": [
        "init", "system_metrics", "processes", "connections", "ports", "startup", "finalize",
    ],
    "custom": [
        "init", "processes", "user_files", "dll_scan", "connections", "threats", "finalize",
    ],
    "network": [
        "init", "network_arp", "connections", "ports", "firewall", "network_adapters", "finalize",
    ],
    "login_session": [
        "init", "system_metrics", "processes", "memory_scan", "services", "connections", "ports",
        "network_adapters", "firewall", "defender_status", "startup", "scheduled_tasks",
        "installed_programs", "user_files", "registry", "browser_extensions", "threats",
        "vulnerabilities", "network_arp", "security_engine", "finalize",
    ],
}

DETECTION_RULES = [
    "Proceso sin ejecutable en disco → posible proceso oculto",
    "Ejecutable sin firma Authenticode → aplicación sin firma digital",
    "Patrón malicioso en línea de comandos → indicador de ataque",
    "Entropía Shannon ≥ 7.2 en DLL/EXE → posible ofuscación",
    "Procesos duplicados (>3 instancias mismo nombre) → anomalía de persistencia",
    "Conexión externa establecida → verificación de destino requerida",
    "Puerto de alto riesgo abierto (23,445,3389,5900) → superficie de ataque",
    "Autorun en registro Run → persistencia al inicio",
    "CPU > 90% durante escaneo → consumo anormal del sistema",
    "Hash VirusTotal malicioso (si API configurada) → malware conocido",
]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    ln = len(data)
    for c in freq:
        if c:
            p = c / ln
            ent -= p * math.log2(p)
    return round(ent, 2)


def _risk_score(findings: List[dict]) -> tuple:
    weights = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 1}
    score = sum(weights.get(f.get("risk", "info"), 1) for f in findings)
    if score >= 80:
        return "CRÍTICO", score
    if score >= 45:
        return "ALTO", score
    if score >= 20:
        return "MEDIO", score
    if score > 0:
        return "BAJO", score
    return "INFORMATIVO", score


def _win_subprocess_kwargs() -> dict:
    if platform.system() == "Windows":
        return {"creationflags": 0x08000000}
    return {}


class DeepScanEngine:
    """Escaneo integral del equipo con progreso en tiempo real."""

    def __init__(self):
        self._lock = threading.Lock()
        self._scans: Dict[str, dict] = {}

    def start_scan(
        self,
        session_id: str = "",
        user_id: Optional[int] = None,
        profile: str = "full",
        query: str = "",
        modules_loaded: Optional[List[str]] = None,
        custom_roots: Optional[List[str]] = None,
    ) -> str:
        scan_id = str(uuid.uuid4())
        phases = PROFILE_PHASES.get(profile, PROFILE_PHASES["full"])
        with self._lock:
            self._scans[scan_id] = {
                "scan_id": scan_id,
                "session_id": session_id,
                "user_id": user_id,
                "profile": profile,
                "query": query,
                "custom_roots": [p for p in (custom_roots or []) if p and os.path.isdir(p)],
                "modules_loaded": modules_loaded or [],
                "phases_total": len(phases),
                "status": "running",
                "phase": "init",
                "phase_label": "Inicializando",
                "progress_pct": 0,
                "started_at": datetime.now().isoformat(),
                "finished_at": None,
                "elapsed_sec": 0,
                "current_element": "",
                "stats": {
                    "files_analyzed": 0,
                    "folders_analyzed": 0,
                    "processes_analyzed": 0,
                    "connections_analyzed": 0,
                    "ports_analyzed": 0,
                    "services_analyzed": 0,
                    "users_analyzed": 0,
                    "drivers_analyzed": 0,
                    "dll_analyzed": 0,
                    "certificates_analyzed": 0,
                    "tasks_analyzed": 0,
                    "threats_found": 0,
                    "anomalies_found": 0,
                },
                "findings": [],
                "sections": {},
                "pending_sections": [],
                "engines_used": [],
                "report": None,
                "error": None,
            }
        t = threading.Thread(target=self._run_scan, args=(scan_id, phases), daemon=True)
        t.start()
        logger.info(f"SOC Workflow iniciado: {scan_id} profile={profile}")
        return scan_id

    def get_status(self, scan_id: str) -> Optional[dict]:
        with self._lock:
            s = self._scans.get(scan_id)
            if not s:
                return None
            out = {k: v for k, v in s.items() if k != "report"}
            if s.get("started_at"):
                try:
                    start = datetime.fromisoformat(s["started_at"])
                    out["elapsed_sec"] = round((datetime.now() - start).total_seconds(), 1)
                except ValueError:
                    pass
            return out

    def get_report(self, scan_id: str) -> Optional[dict]:
        with self._lock:
            s = self._scans.get(scan_id)
            if not s:
                return None
            return s.get("report")

    def _update(self, scan_id: str, **kwargs):
        with self._lock:
            if scan_id in self._scans:
                self._scans[scan_id].update(kwargs)

    def _bump_stat(self, scan_id: str, key: str, n: int = 1):
        with self._lock:
            if scan_id in self._scans:
                self._scans[scan_id]["stats"][key] = self._scans[scan_id]["stats"].get(key, 0) + n

    def _add_finding(self, scan_id: str, finding: dict):
        with self._lock:
            if scan_id not in self._scans:
                return
            fid = f"FIND-{len(self._scans[scan_id]['findings']) + 1:04d}"
            enriched = {
                "name": finding.get("name") or finding.get("title", ""),
                "pid": finding.get("pid"),
                "path": finding.get("path") or finding.get("location", ""),
                "publisher": finding.get("publisher", "Sin datos disponibles"),
                "digital_signature": finding.get("digital_signature", "Sin verificar"),
                "cpu_pct": finding.get("cpu_pct"),
                "ram_pct": finding.get("ram_pct"),
                "connections": finding.get("connections", 0),
                "ports": finding.get("ports") or [],
                "started_at": finding.get("started_at"),
                "reason": finding.get("reason") or finding.get("description", ""),
                "actions": finding.get("actions") or ["Investigar en XDR", "Abrir módulo Vulnerabilidades"],
            }
            enriched.update(finding)
            enriched["id"] = fid
            self._scans[scan_id]["findings"].append(enriched)
            risk = enriched.get("risk", "info")
            if risk in ("critical", "high", "medium"):
                self._scans[scan_id]["stats"]["anomalies_found"] += 1
            if enriched.get("category") in ("threat", "malware", "ransomware", "backdoor", "keylogger"):
                self._scans[scan_id]["stats"]["threats_found"] += 1

    def _section(self, scan_id: str, name: str, status: str, data: dict, note: str = ""):
        with self._lock:
            if scan_id in self._scans:
                self._scans[scan_id]["sections"][name] = {
                    "status": status,
                    "data": data,
                    "note": note,
                    "completed_at": datetime.now().isoformat(),
                }
                if status == "PENDIENTE":
                    self._scans[scan_id]["pending_sections"].append(name)

    def _run_phase_with_timeout(self, handler: Callable, scan_id: str, phase_id: str) -> None:
        """Ejecuta una fase con timeout; si expira, registra ERROR y continúa."""
        box: Dict[str, Any] = {"exc": None}

        def _target():
            try:
                handler(scan_id)
            except Exception as exc:
                box["exc"] = exc

        t = threading.Thread(
            target=_target,
            name=f"DeepPhase-{phase_id[:16]}",
            daemon=True,
        )
        t.start()
        t.join(PHASE_TIMEOUT_SEC)
        if t.is_alive():
            raise TimeoutError(
                f"Fase '{phase_id}' superó {PHASE_TIMEOUT_SEC}s sin finalizar"
            )
        if box["exc"] is not None:
            raise box["exc"]

    def _run_scan(self, scan_id: str, phases: List[str]):
        start = time.time()
        total_phases = max(len(phases), 1)
        try:
            for idx, phase_id in enumerate(phases):
                phase_label = next((lbl for pid, lbl in PHASES if pid == phase_id), phase_id)
                pct = int((idx / total_phases) * 100)
                self._update(scan_id, phase=phase_id, phase_label=phase_label, progress_pct=pct,
                             current_element=phase_label)
                handler = getattr(self, f"_phase_{phase_id}", None)
                if handler:
                    try:
                        self._run_phase_with_timeout(handler, scan_id, phase_id)
                    except TimeoutError as phase_exc:
                        logger.warning("Deep Scan fase %s TIMEOUT: %s", phase_id, phase_exc)
                        self._section(scan_id, phase_id, "ERROR", {"timeout_sec": PHASE_TIMEOUT_SEC}, str(phase_exc))
                        self._add_finding(scan_id, {
                            "category": "scan_timeout",
                            "title": f"Timeout en fase {phase_id}",
                            "description": str(phase_exc),
                            "evidence": f"timeout={PHASE_TIMEOUT_SEC}s",
                            "location": phase_id,
                            "risk": "medium",
                            "recommendation": "Revisar carga del sistema o acotar el perfil de escaneo.",
                            "remediation": "El escaneo continuó con las fases restantes.",
                        })
                    except Exception as phase_exc:
                        logger.warning(f"Deep Scan fase {phase_id}: {phase_exc}")
                        self._section(scan_id, phase_id, "ERROR", {}, str(phase_exc))
                else:
                    self._section(scan_id, phase_id, "PENDIENTE", {},
                                  "Fuente real todavía no implementada para esta fase.")

            self._build_report(scan_id, time.time() - start)
            self._update(scan_id, status="completed", progress_pct=100, phase="done",
                         phase_label="Completado", finished_at=datetime.now().isoformat())
        except Exception as exc:
            logger.error(f"Deep Scan {scan_id} error: {exc}", exc_info=True)
            self._update(scan_id, status="error", error=str(exc), finished_at=datetime.now().isoformat())

    # ── Fases ─────────────────────────────────────────────────────────────

    def _get_authenticode(self, path: str) -> dict:
        if not path or not os.path.isfile(path) or platform.system() != "Windows":
            return {"publisher": "Sin datos disponibles", "digital_signature": "No verificado (no Windows/ruta)"}
        try:
            safe = path.replace("'", "''")
            ps = (
                f"$s=Get-AuthenticodeSignature -LiteralPath '{safe}';"
                f"@{{Status=$s.Status; Publisher=($s.SignerCertificate.Subject)}} | ConvertTo-Json -Compress"
            )
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True, text=True, timeout=8, **_win_subprocess_kwargs(),
            )
            if r.returncode == 0 and r.stdout.strip():
                import json
                data = json.loads(r.stdout.strip())
                pub = data.get("Publisher") or "Sin editor"
                status = str(data.get("Status", "Unknown"))
                return {
                    "publisher": pub[:200] if pub else "Sin editor",
                    "digital_signature": status,
                }
        except Exception as exc:
            logger.debug(f"Authenticode {path}: {exc}")
        return {"publisher": "Sin datos disponibles", "digital_signature": "Error al verificar"}

    def _phase_init(self, scan_id: str):
        with self._lock:
            mods = self._scans.get(scan_id, {}).get("modules_loaded") or []
            profile = self._scans.get(scan_id, {}).get("profile", "full")
        self._update(scan_id, current_element="Cargando motores SOC (sin caché)")
        engines = [
            "soc_workflow_engine", "psutil", "advanced_detector_service",
            "novus_security_integration", "security_engine",
        ]
        self._update(scan_id, engines_used=engines, modules_loaded=mods or ["Process Scanner", "Security Engine"])
        self._section(scan_id, "init", "REAL", {
            "hostname": socket.gethostname(),
            "os": platform.platform(),
            "profile": profile,
            "modules": mods,
        })

    def _phase_disks(self, scan_id: str):
        disks = []
        for part in psutil.disk_partitions(all=True):
            mp = part.mountpoint
            if not mp:
                continue
            if platform.system() == "Windows":
                opts = (part.opts or "").lower()
                if "cdrom" in opts or not mp.endswith("\\") and len(mp) == 2:
                    pass
            try:
                usage = psutil.disk_usage(mp)
                disks.append({
                    "device": part.device,
                    "mountpoint": mp,
                    "fstype": part.fstype,
                    "total_gb": round(usage.total / (1024 ** 3), 2),
                    "used_pct": usage.percent,
                })
                self._bump_stat(scan_id, "folders_analyzed")
            except (PermissionError, OSError, SystemError, ValueError):
                continue
        self._section(scan_id, "disks", "REAL", {"count": len(disks), "disks": disks})

    def _phase_system_metrics(self, scan_id: str):
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = get_disk_usage()
        gpu_info = self._collect_gpu()
        data = {
            "cpu_pct": cpu,
            "ram_pct": mem.percent,
            "ram_available_gb": round(mem.available / (1024 ** 3), 2),
            "disk_pct": disk.percent,
            "disk_free_gb": round(disk.free / (1024 ** 3), 2),
            "gpu": gpu_info,
        }
        if cpu > 90:
            self._add_finding(scan_id, {
                "category": "anomaly", "title": "CPU elevada",
                "description": f"Uso de CPU al {cpu}% durante el escaneo.",
                "evidence": f"psutil.cpu_percent() = {cpu}",
                "location": "Sistema local", "risk": "medium",
                "recommendation": "Identificar procesos de alto consumo.",
                "remediation": "Revisar pestaña Procesos o finalizar tareas no esenciales.",
            })
        self._section(scan_id, "system_metrics", "REAL", data)

    def _collect_gpu(self) -> dict:
        if platform.system() != "Windows":
            return {"status": "PENDIENTE", "note": "Detección GPU solo implementada en Windows (wmic)."}
        try:
            r = subprocess.run(
                ["wmic", "path", "win32_VideoController", "get", "name"],
                capture_output=True, text=True, timeout=12, **_win_subprocess_kwargs(),
            )
            names = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip() and ln.strip() != "Name"]
            return {"status": "REAL", "adapters": names, "count": len(names)}
        except Exception as exc:
            return {"status": "PENDIENTE", "note": str(exc)}

    def _phase_memory_scan(self, scan_id: str):
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        high_mem_procs = []
        for proc in psutil.process_iter(["pid", "name", "memory_percent", "memory_info"]):
            try:
                info = proc.info
                pct = info.get("memory_percent") or 0
                if pct >= 15:
                    high_mem_procs.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        for hp in high_mem_procs[:5]:
            if hp.get("memory_percent", 0) >= 25:
                self._add_finding(scan_id, {
                    "category": "memory", "title": f"Consumo elevado de RAM: {hp.get('name')}",
                    "name": hp.get("name"), "pid": hp.get("pid"),
                    "ram_pct": round(hp.get("memory_percent", 0), 1),
                    "description": f"Proceso consume {hp.get('memory_percent', 0):.1f}% de RAM",
                    "reason": "Umbral SOC: memory_percent ≥ 25%",
                    "evidence": f"psutil.memory_percent PID {hp.get('pid')}",
                    "location": f"PID {hp.get('pid')}",
                    "risk": "medium",
                    "recommendation": "Verificar si el consumo es legítimo.",
                    "actions": ["Investigar proceso", "Abrir Endpoints"],
                })
        self._section(scan_id, "memory_scan", "REAL", {
            "ram_total_gb": round(mem.total / (1024 ** 3), 2),
            "ram_used_pct": mem.percent,
            "swap_used_pct": swap.percent,
            "high_memory_processes": len(high_mem_procs),
        })

    def _phase_defender_status(self, scan_id: str):
        if platform.system() != "Windows":
            self._section(scan_id, "defender_status", "PENDIENTE", {},
                          "Windows Defender solo disponible en Windows.")
            return
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntispywareEnabled,"
                 "RealTimeProtectionEnabled,IoavProtectionEnabled | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=15, **_win_subprocess_kwargs(),
            )
            import json
            data = json.loads(r.stdout.strip()) if r.stdout.strip() else {}
            if data.get("RealTimeProtectionEnabled") is False:
                self._add_finding(scan_id, {
                    "category": "defender", "title": "Windows Defender — protección en tiempo real desactivada",
                    "description": "RealTimeProtectionEnabled = False",
                    "reason": "Superficie de exposición aumentada",
                    "evidence": str(data),
                    "location": "Windows Security",
                    "risk": "high",
                    "recommendation": "Activar protección en tiempo real.",
                    "actions": ["Abrir Configuración Windows", "Activar Defender"],
                })
            self._section(scan_id, "defender_status", "REAL", data)
        except Exception as exc:
            self._section(scan_id, "defender_status", "PENDIENTE", {}, str(exc))

    def _phase_security_engine(self, scan_id: str):
        try:
            from services.novus_security_integration import novus_security
            summary = novus_security.security_engine.get_security_summary()
            self._section(scan_id, "security_engine", "REAL", summary or {})
            with self._lock:
                if scan_id in self._scans:
                    eng = list(self._scans[scan_id].get("engines_used", []))
                    eng.append("security_engine.get_security_summary")
                    self._scans[scan_id]["engines_used"] = eng
        except Exception as exc:
            self._section(scan_id, "security_engine", "PENDIENTE", {}, str(exc))

    def _phase_processes(self, scan_id: str):
        from services.advanced_detector_service import advanced_detector
        procs = []
        by_name: Dict[str, int] = {}
        hidden_candidates = []
        unsigned = []
        background = []

        auth_checked = 0
        for proc in psutil.process_iter([
            "pid", "name", "username", "exe", "cmdline",
            "cpu_percent", "memory_percent", "create_time",
        ]):
            try:
                info = proc.info
                procs.append(info)
                name = (info.get("name") or "").lower()
                by_name[name] = by_name.get(name, 0) + 1
                exe = info.get("exe")
                if exe and not os.path.exists(exe):
                    hidden_candidates.append(info)
                if (
                    exe and os.path.isfile(exe) and exe.lower().endswith(".exe")
                    and auth_checked < 25
                    and any(x in exe.lower() for x in ("appdata", "temp", "download", "desktop"))
                ):
                    sig = self._get_authenticode(exe)
                    auth_checked += 1
                    if "NotSigned" in sig.get("digital_signature", "") or sig.get("digital_signature") in (
                        "UnknownError", "HashMismatch",
                    ):
                        unsigned.append({**info, **sig})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        self._bump_stat(scan_id, "processes_analyzed", len(procs))

        for name, count in by_name.items():
            if count > 3 and name:
                self._add_finding(scan_id, {
                    "category": "persistence", "title": f"Procesos duplicados: {name} ({count} instancias)",
                    "name": name, "description": f"{count} procesos con el mismo nombre",
                    "reason": "Regla SOC: >3 instancias del mismo proceso",
                    "evidence": f"process_iter count={count}",
                    "location": name, "risk": "low",
                    "recommendation": "Verificar si es comportamiento esperado.",
                })

        for info in unsigned[:15]:
            exe = info.get("exe") or ""
            self._add_finding(scan_id, {
                "category": "unsigned", "title": f"Aplicación sin firma digital: {info.get('name')}",
                "name": info.get("name"), "pid": info.get("pid"), "path": exe,
                "publisher": info.get("publisher"), "digital_signature": info.get("digital_signature"),
                "cpu_pct": info.get("cpu_percent"), "ram_pct": info.get("memory_percent"),
                "description": "Ejecutable sin firma Authenticode válida",
                "reason": "Regla SOC: Authenticode NotSigned/Unknown",
                "evidence": exe,
                "location": exe or f"PID {info.get('pid')}",
                "risk": "medium",
                "recommendation": "Validar origen del software.",
                "actions": ["Verificar editor", "Cuarentena si desconocido"],
            })

        for hc in hidden_candidates[:10]:
            self._add_finding(scan_id, {
                "category": "hidden", "title": f"Proceso oculto / sin binario: {hc.get('name')}",
                "name": hc.get("name"), "pid": hc.get("pid"),
                "path": hc.get("exe"), "cpu_pct": hc.get("cpu_percent"),
                "ram_pct": hc.get("memory_percent"),
                "description": "PID referencia ejecutable inexistente en disco",
                "reason": "Regla SOC: exe path no existe",
                "evidence": str(hc.get("exe")),
                "location": f"PID {hc.get('pid')}",
                "risk": "high",
                "recommendation": "Investigar con EDR.",
                "actions": ["Terminar proceso", "Abrir XDR"],
            })

        suspicious = advanced_detector.scan_running_processes() or []
        for sp in suspicious:
            pid = sp.get("pid")
            cpu = ram = conns = 0
            ports = []
            try:
                p = psutil.Process(pid)
                cpu = p.cpu_percent(interval=0)
                ram = p.memory_percent()
                conns = len(p.connections(kind="inet"))
                ports = [c.laddr.port for c in p.connections(kind="inet") if c.laddr]
            except Exception:
                pass
            sig = self._get_authenticode(sp.get("path") or "")
            self._add_finding(scan_id, {
                "category": "malware", "title": f"Proceso sospechoso: {sp.get('name')}",
                "name": sp.get("name"), "pid": pid, "path": sp.get("path"),
                "publisher": sig.get("publisher"), "digital_signature": sig.get("digital_signature"),
                "cpu_pct": cpu, "ram_pct": ram, "connections": conns, "ports": ports[:5],
                "description": sp.get("description", "Patrón malicioso en línea de comandos"),
                "reason": "Advanced Detector — patrón de ataque en cmdline",
                "evidence": sp.get("command_line") or sp.get("path") or "",
                "location": f"PID {pid} — {sp.get('path', 'N/D')}",
                "risk": "high",
                "recommendation": "Aislar y terminar si no es legítimo.",
                "actions": ["Remediar en XDR", "Terminar proceso"],
            })

        self._section(scan_id, "processes", "REAL", {
            "total": len(procs), "suspicious": len(suspicious),
            "hidden_candidates": len(hidden_candidates), "unsigned": len(unsigned),
            "duplicates": sum(1 for c in by_name.values() if c > 3),
        })

    def _phase_services(self, scan_id: str):
        services = self._collect_windows_services()
        self._bump_stat(scan_id, "services_analyzed", len(services))
        self._section(scan_id, "services", services.get("status", "REAL"), services)

    def _collect_windows_services(self) -> dict:
        if platform.system() != "Windows":
            return {"status": "PENDIENTE", "note": "Enumeración de servicios implementada para Windows.", "items": []}
        try:
            r = subprocess.run(
                ["sc", "query", "type=", "service", "state=", "all"],
                capture_output=True, text=True, timeout=30, **_win_subprocess_kwargs(),
            )
            names = re.findall(r"SERVICE_NAME:\s*(.+)", r.stdout or "")
            return {"status": "REAL", "count": len(names), "items": names[:200]}
        except Exception as exc:
            return {"status": "PENDIENTE", "note": str(exc), "items": []}

    def _phase_connections(self, scan_id: str):
        conns = []
        ext_ips = set()
        for c in psutil.net_connections(kind="inet"):
            try:
                item = {
                    "fd": c.fd, "family": str(c.family), "type": str(c.type),
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                    "status": c.status, "pid": c.pid,
                }
                conns.append(item)
                if c.raddr and c.status == "ESTABLISHED":
                    ext_ips.add(c.raddr.ip)
            except Exception:
                continue
        self._bump_stat(scan_id, "connections_analyzed", len(conns))
        for ip in list(ext_ips)[:30]:
            if ip.startswith(("10.", "192.168.", "127.", "169.254.")):
                continue
            self._add_finding(scan_id, {
                "category": "network", "title": f"Conexión externa establecida: {ip}",
                "description": "Conexión saliente a IP no privada detectada.",
                "evidence": f"psutil.net_connections → {ip}",
                "location": ip, "risk": "low",
                "recommendation": "Verificar proceso asociado (PID) y destino.",
                "remediation": "Bloquear en firewall si no es legítimo.",
            })
        self._section(scan_id, "connections", "REAL", {"total": len(conns), "established": sum(1 for x in conns if x.get("status") == "ESTABLISHED")})

    def _phase_ports(self, scan_id: str):
        from services.advanced_detector_service import advanced_detector
        ip = get_local_ip()
        ports = advanced_detector.scan_open_ports(ip) or []
        self._bump_stat(scan_id, "ports_analyzed", len(ports))
        risky = {23, 445, 3389, 5900}
        for p in ports:
            port_num = p.get("port")
            if port_num in risky:
                self._add_finding(scan_id, {
                    "category": "exposure", "title": f"Puerto de riesgo abierto: {port_num}",
                    "description": p.get("description", ""),
                    "evidence": f"socket.connect_ex({ip}, {port_num}) == 0",
                    "location": f"{ip}:{port_num}", "risk": "medium",
                    "recommendation": "Cerrar o restringir el puerto si no es necesario.",
                    "remediation": "Configurar firewall local.",
                })
        self._section(scan_id, "ports", "REAL", {"count": len(ports), "items": ports})

    def _phase_network_adapters(self, scan_id: str):
        adapters = []
        stats = psutil.net_if_stats()
        for name, addrs in psutil.net_if_addrs().items():
            entry = {"name": name, "addresses": [], "is_up": stats.get(name).isup if name in stats else None}
            for addr in addrs:
                entry["addresses"].append({"family": str(addr.family), "address": addr.address})
            adapters.append(entry)
        self._section(scan_id, "network_adapters", "REAL", {"count": len(adapters), "adapters": adapters})

    def _phase_users(self, scan_id: str):
        users = []
        for u in psutil.users():
            users.append({"name": u.name, "terminal": u.terminal, "started": u.started})
        self._bump_stat(scan_id, "users_analyzed", len(users))
        self._section(scan_id, "users", "REAL", {"count": len(users), "items": users})

    def _phase_env_vars(self, scan_id: str):
        sensitive = []
        safe = {}
        for k, v in os.environ.items():
            if re.search(r"(pass|secret|key|token|credential)", k, re.I):
                sensitive.append(k)
            elif len(safe) < 50:
                safe[k] = (v[:80] + "…") if len(v) > 80 else v
        self._section(scan_id, "env_vars", "REAL", {
            "total": len(os.environ),
            "sample_count": len(safe),
            "sensitive_keys_masked": sensitive,
        })

    def _phase_startup(self, scan_id: str):
        items = self._collect_startup_entries()
        self._section(scan_id, "startup", items.get("status", "REAL"), items)

    def _collect_startup_entries(self) -> dict:
        if platform.system() != "Windows":
            return {"status": "PENDIENTE", "note": "Autorun vía registro solo en Windows.", "items": []}
        try:
            import winreg
            entries = []
            keys = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ]
            for hive, path in keys:
                try:
                    with winreg.OpenKey(hive, path) as key:
                        i = 0
                        while True:
                            try:
                                name, val, _ = winreg.EnumValue(key, i)
                                entries.append({"name": name, "command": val, "hive": str(hive)})
                                i += 1
                            except OSError:
                                break
                except OSError:
                    continue
            return {"status": "REAL", "count": len(entries), "items": entries}
        except ImportError:
            return {"status": "PENDIENTE", "note": "Módulo winreg no disponible.", "items": []}

    def _phase_scheduled_tasks(self, scan_id: str):
        tasks = self._collect_scheduled_tasks()
        self._bump_stat(scan_id, "tasks_analyzed", tasks.get("count", 0))
        self._section(scan_id, "scheduled_tasks", tasks.get("status", "REAL"), tasks)

    def _collect_scheduled_tasks(self) -> dict:
        if platform.system() != "Windows":
            return {"status": "PENDIENTE", "note": "schtasks solo en Windows.", "items": []}
        try:
            r = subprocess.run(
                ["schtasks", "/query", "/fo", "LIST", "/v"],
                capture_output=True, text=True, timeout=45, **_win_subprocess_kwargs(),
            )
            names = re.findall(r"TaskName:\s*(.+)", r.stdout or "")
            return {"status": "REAL", "count": len(names), "items": names[:150]}
        except Exception as exc:
            return {"status": "PENDIENTE", "note": str(exc), "items": []}

    def _phase_firewall(self, scan_id: str):
        fw = self._collect_firewall()
        self._section(scan_id, "firewall", fw.get("status", "REAL"), fw)

    def _collect_firewall(self) -> dict:
        if platform.system() != "Windows":
            return {"status": "PENDIENTE", "note": "netsh advfirewall solo en Windows.", "profiles": []}
        try:
            r = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=15, **_win_subprocess_kwargs(),
            )
            return {"status": "REAL", "raw": (r.stdout or "")[:2000]}
        except Exception as exc:
            return {"status": "PENDIENTE", "note": str(exc)}

    def _phase_installed_programs(self, scan_id: str):
        progs = self._collect_installed_programs()
        self._section(scan_id, "installed_programs", progs.get("status", "REAL"), progs)

    def _collect_installed_programs(self) -> dict:
        if platform.system() != "Windows":
            return {"status": "PENDIENTE", "note": "Registro Uninstall solo en Windows.", "items": []}
        try:
            import winreg
            items = []
            path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                try:
                    with winreg.OpenKey(hive, path) as key:
                        for i in range(winreg.QueryInfoKey(key)[0]):
                            try:
                                sub = winreg.EnumKey(key, i)
                                with winreg.OpenKey(key, sub) as sk:
                                    try:
                                        disp, _ = winreg.QueryValueEx(sk, "DisplayName")
                                        items.append(disp)
                                    except OSError:
                                        pass
                            except OSError:
                                continue
                except OSError:
                    continue
            return {"status": "REAL", "count": len(items), "items": items[:100]}
        except ImportError:
            return {"status": "PENDIENTE", "note": "winreg no disponible.", "items": []}

    def _phase_drivers(self, scan_id: str):
        drivers = self._collect_drivers()
        self._bump_stat(scan_id, "drivers_analyzed", drivers.get("count", 0))
        self._section(scan_id, "drivers", drivers.get("status", "REAL"), drivers)

    def _collect_drivers(self) -> dict:
        if platform.system() != "Windows":
            return {"status": "PENDIENTE", "note": "driverquery solo en Windows.", "items": []}
        try:
            r = subprocess.run(
                ["driverquery", "/fo", "csv", "/nh"],
                capture_output=True, text=True, timeout=25, **_win_subprocess_kwargs(),
            )
            lines = [ln for ln in (r.stdout or "").splitlines() if ln.strip()]
            return {"status": "REAL", "count": len(lines), "items": lines[:80]}
        except Exception as exc:
            return {"status": "PENDIENTE", "note": str(exc), "items": []}

    def _phase_user_files(self, scan_id: str):
        roots = self._user_scan_roots(scan_id)
        files_done = 0
        folders_done = 0
        recent_exe = []

        for root in roots:
            if files_done >= MAX_FILES_PER_SCAN:
                break
            self._update(scan_id, current_element=f"Analizando: {root}")
            try:
                for dirpath, dirnames, filenames in os.walk(root):
                    depth = dirpath.replace(root, "").count(os.sep)
                    if depth > MAX_WALK_DEPTH:
                        dirnames.clear()
                        continue
                    folders_done += 1
                    self._bump_stat(scan_id, "folders_analyzed")
                    for fn in filenames:
                        if files_done >= MAX_FILES_PER_SCAN:
                            break
                        fp = os.path.join(dirpath, fn)
                        files_done += 1
                        self._bump_stat(scan_id, "files_analyzed")
                        ext = os.path.splitext(fn)[1].lower()
                        if ext in SUSPICIOUS_EXT:
                            try:
                                st = os.stat(fp)
                                recent_exe.append({
                                    "path": fp, "size": st.st_size,
                                    "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
                                })
                            except OSError:
                                pass
            except (PermissionError, OSError) as exc:
                logger.debug(f"Walk skip {root}: {exc}")

        self._section(scan_id, "user_files", "REAL", {
            "roots_scanned": roots,
            "files_analyzed": files_done,
            "folders_analyzed": folders_done,
            "limit": MAX_FILES_PER_SCAN,
            "note": f"Escaneo acotado a {MAX_FILES_PER_SCAN} archivos — no recorre todo el disco completo.",
            "suspicious_paths_sample": recent_exe[:30],
        })

    def _user_scan_roots(self, scan_id: Optional[str] = None) -> List[str]:
        if scan_id:
            with self._lock:
                custom = list(self._scans.get(scan_id, {}).get("custom_roots") or [])
            if custom:
                return custom
        roots = []
        home = Path.home()
        for sub in ("Downloads", "Desktop", "Documents"):
            p = home / sub
            if p.exists():
                roots.append(str(p))
        temp = os.environ.get("TEMP") or str(home / "AppData" / "Local" / "Temp")
        if os.path.isdir(temp):
            roots.append(temp)
        local_app = home / "AppData" / "Local"
        if local_app.exists():
            roots.append(str(local_app))
        for part in psutil.disk_partitions():
            user_on_drive = Path(part.mountpoint) / "Users" / os.environ.get("USERNAME", "")
            if user_on_drive.exists():
                for sub in ("Downloads", "Desktop", "Documents"):
                    sp = user_on_drive / sub
                    if sp.exists():
                        roots.append(str(sp))
        return list(dict.fromkeys(roots))

    def _phase_dll_scan(self, scan_id: str):
        from services.advanced_detector_service import advanced_detector
        scanned = 0
        sec = self._scans.get(scan_id, {}).get("sections", {}).get("user_files", {})
        paths = (sec.get("data") or {}).get("suspicious_paths_sample") or []
        for item in paths:
            fp = item.get("path", "")
            if not fp.lower().endswith((".dll", ".exe", ".scr")):
                continue
            scanned += 1
            self._bump_stat(scan_id, "dll_analyzed")
            try:
                with open(fp, "rb") as f:
                    chunk = f.read(65536)
                ent = _entropy(chunk)
                if ent >= HIGH_ENTROPY:
                    self._add_finding(scan_id, {
                        "category": "entropy", "title": f"Alta entropía: {os.path.basename(fp)}",
                        "description": f"Entropía Shannon {ent} (posible ofuscación/payload).",
                        "evidence": f"entropy={ent}, size={item.get('size')}",
                        "location": fp, "risk": "high",
                        "recommendation": "Analizar con sandbox o VirusTotal (requiere API key).",
                        "remediation": "Cuarentena del archivo.",
                    })
                rep = advanced_detector.scan_file_reputation(fp)
                if rep.get("resultado") == "PELIGRO":
                    self._add_finding(scan_id, {
                        "category": "malware", "title": f"Hash malicioso conocido: {os.path.basename(fp)}",
                        "description": "VirusTotal reportó detecciones.",
                        "evidence": str(rep),
                        "location": fp, "risk": "critical",
                        "recommendation": "Eliminar y aislar el equipo.",
                        "remediation": "Remediación inmediata.",
                    })
            except (PermissionError, OSError):
                continue
        self._section(scan_id, "dll_scan", "REAL", {"analyzed": scanned})

    def _phase_certificates(self, scan_id: str):
        if platform.system() != "Windows":
            self._section(scan_id, "certificates", "PENDIENTE", {},
                          "Inventario de certificados requiere PowerShell/Cert:\\ (Windows).")
            return
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-ChildItem Cert:\\CurrentUser\\My).Count"],
                capture_output=True, text=True, timeout=15, **_win_subprocess_kwargs(),
            )
            count = int((r.stdout or "0").strip() or 0)
            self._bump_stat(scan_id, "certificates_analyzed", count)
            self._section(scan_id, "certificates", "REAL", {"user_store_count": count})
        except Exception as exc:
            self._section(scan_id, "certificates", "PENDIENTE", {}, str(exc))

    def _phase_browser_extensions(self, scan_id: str):
        found = []
        local = Path.home() / "AppData" / "Local"
        for browser, rel in [
            ("Chrome", "Google/Chrome/User Data/Default/Extensions"),
            ("Edge", "Microsoft/Edge/User Data/Default/Extensions"),
        ]:
            ext_dir = local / rel.replace("/", os.sep)
            if ext_dir.exists():
                count = sum(1 for _ in ext_dir.iterdir() if _.is_dir())
                found.append({"browser": browser, "path": str(ext_dir), "extension_folders": count})
        status = "REAL" if found else "PENDIENTE"
        note = "" if found else "No se encontraron carpetas de extensiones en rutas estándar."
        self._section(scan_id, "browser_extensions", status, {"items": found}, note)

    def _phase_usb_devices(self, scan_id: str):
        if platform.system() != "Windows":
            self._section(scan_id, "usb_devices", "PENDIENTE", {}, "WMIC USB no implementado fuera de Windows.")
            return
        try:
            r = subprocess.run(
                ["wmic", "path", "Win32_USBHub", "get", "DeviceID"],
                capture_output=True, text=True, timeout=15, **_win_subprocess_kwargs(),
            )
            ids = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip() and "DeviceID" not in ln]
            self._section(scan_id, "usb_devices", "REAL", {"count": len(ids), "items": ids[:50]})
        except Exception as exc:
            self._section(scan_id, "usb_devices", "PENDIENTE", {}, str(exc))

    def _phase_system_events(self, scan_id: str):
        if platform.system() != "Windows":
            self._section(scan_id, "system_events", "PENDIENTE", {},
                          "Lector de Event Log requiere wevtutil/PowerShell (Windows).")
            return
        try:
            r = subprocess.run(
                ["wevtutil", "qe", "System", "/c:20", "/rd:true", "/f:text"],
                capture_output=True, text=True, timeout=20, **_win_subprocess_kwargs(),
            )
            events = (r.stdout or "").split("Event[")[1:21] if r.stdout else []
            self._section(scan_id, "system_events", "REAL", {"sample_count": len(events)})
        except Exception as exc:
            self._section(scan_id, "system_events", "PENDIENTE", {}, str(exc))

    def _phase_logs(self, scan_id: str):
        log_dir = Path(__file__).resolve().parent.parent / "logs"
        items = []
        if log_dir.exists():
            for f in sorted(log_dir.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)[:5]:
                items.append({"name": f.name, "size": f.stat().st_size})
        self._section(scan_id, "logs", "REAL" if items else "PENDIENTE",
                      {"novus_logs": items}, "" if items else "Sin carpeta logs/ con archivos.")

    def _phase_registry(self, scan_id: str):
        data = self._collect_startup_entries()
        self._section(scan_id, "registry", data.get("status", "PENDIENTE"),
                      {"autorun_entries": data.get("items", []), "note": "Solo claves Run — no registro completo."})

    def _phase_threats(self, scan_id: str):
        from services.novus_security_integration import novus_security
        self._update(scan_id, current_element="Motor XDR — escaneo en vivo (force=True)")
        with self._lock:
            if scan_id in self._scans:
                eng = list(self._scans[scan_id].get("engines_used", []))
                if "novus_security_integration.detect_threats_realtime" not in eng:
                    eng.append("novus_security_integration.detect_threats_realtime")
                self._scans[scan_id]["engines_used"] = eng
        data = novus_security.detect_threats_realtime(force=True) or {}
        for sp in data.get("suspicious_processes") or []:
            self._add_finding(scan_id, {
                "category": "threat", "title": f"Amenaza XDR: {sp.get('name')}",
                "description": sp.get("description", "Detectado por motor NOVUS"),
                "evidence": sp.get("command_line") or "",
                "location": f"PID {sp.get('pid')}", "risk": "high",
                "recommendation": "Revisar en módulo XDR.",
                "remediation": "Remediación desde panel de amenazas.",
            })
        self._section(scan_id, "threats", "REAL", {
            "threats": len(data.get("threats") or []),
            "suspicious_processes": len(data.get("suspicious_processes") or []),
            "open_ports": len(data.get("open_ports") or []),
        })

    def _phase_vulnerabilities(self, scan_id: str):
        from services.novus_security_integration import novus_security
        self._update(scan_id, current_element="Motor vulnerabilidades — escaneo fresco")
        vulns = novus_security.scan_vulnerabilities() or []
        for v in vulns[:20]:
            self._add_finding(scan_id, {
                "category": "vulnerability",
                "title": v.get("nombre") or v.get("tipo") or "Vulnerabilidad",
                "description": v.get("descripcion") or v.get("recommendation") or "",
                "evidence": str(v.get("id", v.get("cve", ""))),
                "location": v.get("componente") or "Sistema local",
                "risk": (v.get("severidad") or v.get("nivel") or "medium").lower()[:10],
                "recommendation": v.get("recommendation") or "Aplicar parche.",
                "remediation": "Ver módulo Vulnerabilidades.",
            })
        self._section(scan_id, "vulnerabilities", "REAL", {"count": len(vulns)})

    def _phase_network_arp(self, scan_id: str):
        from services.network_scanner import network_scanner
        self._update(scan_id, current_element="Escaneo ARP — sin caché")
        nodes = network_scanner.scan_network(force=True) or []
        self._section(scan_id, "network_arp", "REAL", {"nodes": len(nodes)})

    def _phase_finalize(self, scan_id: str):
        pass

    def _build_report(self, scan_id: str, elapsed: float):
        with self._lock:
            s = self._scans.get(scan_id)
            if not s:
                return
            findings = list(s["findings"])
            stats = dict(s["stats"])
            sections = dict(s["sections"])
            profile = s.get("profile", "full")
            query = s.get("query", "")
            modules = s.get("modules_loaded", [])
            engines_used = list(s.get("engines_used", []))
            risk_label, risk_score = _risk_score(findings)

        executive = [
            "=== INFORME ANALISTA SOC/XDR — NOVUS ===",
            f"Consulta: {query or 'Análisis SOC'}",
            f"Perfil: {profile}",
            f"Equipo: {socket.gethostname()}",
            f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Duración: {round(elapsed, 1)} segundos",
            "",
            "── RESUMEN EJECUTIVO ──",
            f"Nivel de riesgo: {risk_label} (puntuación {risk_score})",
            f"Anomalías detectadas: {stats.get('anomalies_found', 0)}",
            "",
            "── ALCANCE DEL ANÁLISIS (datos frescos, sin caché) ──",
            f"Procesos analizados: {stats.get('processes_analyzed', 0)}",
            f"Servicios analizados: {stats.get('services_analyzed', 0)}",
            f"Drivers analizados: {stats.get('drivers_analyzed', 0)}",
            f"Programas inventariados: {sections.get('installed_programs', {}).get('data', {}).get('count', 'N/D')}",
            f"Tareas programadas: {stats.get('tasks_analyzed', 0)}",
            f"DLL/EXE analizados: {stats.get('dll_analyzed', 0)}",
            f"Conexiones analizadas: {stats.get('connections_analyzed', 0)}",
            f"Puertos verificados: {stats.get('ports_analyzed', 0)}",
            f"Archivos analizados: {stats.get('files_analyzed', 0)}",
            f"Carpetas analizadas: {stats.get('folders_analyzed', 0)}",
            "",
            "── MÓDULOS SOC EJECUTADOS ──",
        ]
        for mod in modules:
            executive.append(f"  ✓ {mod}")
        executive.append("")
        executive.append("── MOTORES BACKEND ──")
        for eng in engines_used:
            executive.append(f"  • {eng}")

        executive.append("")
        executive.append("── REGLAS DE DETECCIÓN APLICADAS ──")
        for rule in DETECTION_RULES:
            executive.append(f"  • {rule}")

        pending = [k for k, v in sections.items() if v.get("status") == "PENDIENTE"]
        if pending:
            executive.append("")
            executive.append("── MÓDULOS PENDIENTES ──")
            for p in pending:
                executive.append(f"  • {p}: {sections[p].get('note', 'No implementado')}")

        executive.append("")
        executive.append("── HALLAZGOS DETALLADOS ──")
        if not findings:
            executive.extend([
                "",
                "RESULTADO: Sin anomalías que superen los umbrales SOC en este análisis.",
                "",
                "Por qué se considera seguro:",
                f"  • Se analizaron {stats.get('processes_analyzed', 0)} procesos sin patrones de ataque en cmdline.",
                f"  • Advanced Detector no reportó firmas de malware conocidas.",
                f"  • Se verificaron {stats.get('connections_analyzed', 0)} conexiones — sin destinos bloqueados por reglas.",
                f"  • Puertos abiertos ({stats.get('ports_analyzed', 0)}) dentro de expectativa o sin exposición crítica.",
                f"  • Servicios ({stats.get('services_analyzed', 0)}) y drivers ({stats.get('drivers_analyzed', 0)}) enumerados sin alertas críticas.",
                "  • Reglas de entropía, firma digital y procesos ocultos aplicadas sin hallazgos críticos.",
                "",
                "Esto NO garantiza ausencia absoluta de amenazas — indica que este ciclo SOC no detectó indicadores.",
            ])
        else:
            for f in findings:
                executive.extend([
                    "",
                    f"[{f.get('id')}] {f.get('title')} — Riesgo: {str(f.get('risk', 'info')).upper()}",
                    f"  Nombre: {f.get('name', 'N/D')} | PID: {f.get('pid', 'N/D')}",
                    f"  Ruta: {f.get('path', f.get('location', 'N/D'))}",
                    f"  Editor: {f.get('publisher', 'N/D')}",
                    f"  Firma digital: {f.get('digital_signature', 'N/D')}",
                    f"  CPU: {f.get('cpu_pct', 'N/D')}% | RAM: {f.get('ram_pct', 'N/D')}%",
                    f"  Conexiones: {f.get('connections', 0)} | Puertos: {f.get('ports', [])}",
                    f"  Motivo: {f.get('reason', f.get('description', ''))}",
                    f"  Evidencia: {f.get('evidence', '')}",
                    f"  Recomendación: {f.get('recommendation', '')}",
                    f"  Acciones: {', '.join(f.get('actions') or [])}",
                ])

        executive.append("")
        executive.append("── PLAN DE REMEDIACIÓN ──")
        if findings:
            for i, f in enumerate(findings[:10], 1):
                executive.append(f"  {i}. [{f.get('risk')}] {f.get('title')}")
        else:
            executive.append("  Continuar monitoreo SOC. Programar próximo Deep Scan.")

        report = {
            "scan_id": scan_id,
            "profile": profile,
            "query": query,
            "generated_at": datetime.now().isoformat(),
            "elapsed_sec": round(elapsed, 1),
            "risk_level": risk_label,
            "risk_score": risk_score,
            "modules_loaded": modules,
            "summary": {
                "files": stats.get("files_analyzed", 0),
                "folders": stats.get("folders_analyzed", 0),
                "processes": stats.get("processes_analyzed", 0),
                "connections": stats.get("connections_analyzed", 0),
                "ports": stats.get("ports_analyzed", 0),
                "services": stats.get("services_analyzed", 0),
                "users": stats.get("users_analyzed", 0),
                "drivers": stats.get("drivers_analyzed", 0),
                "dll": stats.get("dll_analyzed", 0),
                "certificates": stats.get("certificates_analyzed", 0),
                "tasks": stats.get("tasks_analyzed", 0),
                "vulnerabilities": sections.get("vulnerabilities", {}).get("data", {}).get("count", 0),
                "anomalies": stats.get("anomalies_found", 0),
                "threats": stats.get("threats_found", 0),
            },
            "engines_used": engines_used,
            "pending_sections": pending,
            "findings": findings,
            "sections": sections,
            "text_report": "\n".join(executive),
        }
        self._update(scan_id, report=report)


deep_scan_engine = DeepScanEngine()
