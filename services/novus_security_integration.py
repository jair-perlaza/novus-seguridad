"""
NOVUS Security Integration Service
Integrates AdvancedDetector and NovusSecurityEngine as the central security motor
"""
import os
import tempfile
import threading
import time
import psutil
import socket
import platform
from datetime import datetime
from typing import Optional
from core.config import Config
from utils.logger import logger
from utils.host_data import get_local_ip, format_ip_or_unavailable, get_disk_usage
from utils.security_helpers import count_node_findings, get_compromised_nodes, compute_risk_summary, get_node_id
from services.advanced_detector_service import AdvancedDetector
from security_engine import NovusSecurityEngine
from database import SessionLocal, Log, Alerta, Vulnerabilidad


class NovusSecurityIntegration:
    """
    Central security motor for NOVUS
    Integrates AdvancedDetector and NovusSecurityEngine
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        self.advanced_detector = AdvancedDetector()
        self.security_engine = NovusSecurityEngine()
        self._db = None
        self._threat_cache = {
            "threats": [],
            "suspicious_processes": [],
            "open_ports": [],
            "vulnerabilities": [],
            "vulnerabilities_pending": [],
            "total_threats": None,
            "last_scan": None,
        }
        self._last_threat_scan_time = 0
        self._last_vuln_scan_time = 0
        self._threat_scan_lock = threading.Lock()
        self._threat_scanning = False
        self._fs_activity_state = {
            "last_check": 0.0,
            "last_mtimes": {},
            "last_net_sent": None,
            "last_net_check": 0.0,
        }
        self._vault = None
        
        logger.info("NOVUS Security Integration initialized")

    @property
    def vault(self):
        """Instancia lazy de CryptoVault (crypto_vault.py) — uso en logs y eventos."""
        if self._vault is None:
            try:
                from crypto_vault import CryptoVault
                self._vault = CryptoVault()
                logger.info("CryptoVault conectado al motor de seguridad")
            except Exception as exc:
                logger.warning(f"CryptoVault no disponible: {exc}")
        return self._vault

    @property
    def db(self):
        if self._db is None:
            self._db = SessionLocal()
        return self._db
    
    def scan_system_health(self):
        """
        Return raw runtime metrics and real scan findings only.
        """
        try:
            cpu = psutil.cpu_percent(interval=0.5)
            memoria = psutil.virtual_memory()
            disco = get_disk_usage()

            suspicious_processes = self.advanced_detector.scan_running_processes()
            open_ports = self.advanced_detector.scan_open_ports()

            return {
                "cpu_usage": cpu,
                "memory_usage": memoria.percent,
                "disk_usage": disco.percent,
                "suspicious_processes": suspicious_processes,
                "open_ports": open_ports,
                "suspicious_process_count": len(suspicious_processes),
                "open_port_count": len(open_ports),
            }
        except Exception as e:
            logger.error(f"Error scanning system health: {e}")
            return {
                "status": "error",
                "message": str(e),
                "suspicious_processes": [],
                "open_ports": [],
                "suspicious_process_count": None,
                "open_port_count": None,
            }
    
    def _trim_threat_cache_payload(self, result: dict) -> dict:
        """Limita retención en RAM de listas grandes del escaneo."""
        if not isinstance(result, dict):
            return result
        out = dict(result)
        procs = out.get("suspicious_processes") or []
        if len(procs) > 40:
            out["suspicious_processes"] = procs[:40]
        ports = out.get("open_ports") or []
        if len(ports) > 80:
            out["open_ports"] = ports[:80]
        vulns = out.get("vulnerabilities") or []
        if len(vulns) > 120:
            out["vulnerabilities"] = vulns[:120]
        return out

    def detect_threats_realtime(self, force=False):
        """
        Real-time threat detection using both engines
        Returns active threats and alerts
        """
        current_time = time.time()
        if not force and (current_time - self._last_threat_scan_time) < Config.THREAT_SCAN_INTERVAL:
            return dict(self._threat_cache)

        if self._threat_scanning:
            return dict(self._threat_cache)

        with self._threat_scan_lock:
            if self._threat_scanning:
                return dict(self._threat_cache)
            self._threat_scanning = True

        try:
            result = self._run_threat_detection()
            result = self._trim_threat_cache_payload(result)
            self._threat_cache = result
            self._last_threat_scan_time = time.time()
            try:
                from services.alert_reconciliation_service import reconcile_stale_security_alerts
                reconcile_stale_security_alerts()
            except Exception as rec_exc:
                logger.debug("Post-scan reconciliation: %s", rec_exc)
            return dict(result)
        finally:
            self._threat_scanning = False

    def get_cached_threat_count(self):
        """Return verified threat count only — sin evidencia no cuenta."""
        total = self._threat_cache.get("total_threats")
        if total is not None:
            return total
        if not self._threat_cache.get("last_scan"):
            return None
        return self._count_verified_threats(
            self._threat_cache.get("threats"),
            self._threat_cache.get("suspicious_processes"),
        )

    @staticmethod
    def _count_verified_threats(threats, suspicious_processes) -> int:
        """Solo amenazas con evidencia verificable."""
        count = 0
        for threat in threats or []:
            details = threat.get("details") or {}
            if not isinstance(details, dict) or not details:
                continue
            if details.get("verified") is not True:
                continue
            if details.get("status") in ("SECURE", "STABLE", "OPERATIONAL", "OBSERVATION"):
                continue
            ttype = str(threat.get("type") or "").lower()
            if ttype == "mitm" and details.get("status") == "SECURE":
                continue
            evidence_text = details.get("evidence") or details.get("message")
            if not evidence_text and ttype != "ransomware":
                continue
            count += 1
        return count

    def _run_threat_detection(self):
        """Execute a full threat detection pass and return structured results."""
        try:
            # Use AdvancedDetector for process and port scanning
            suspicious_processes = self.advanced_detector.scan_running_processes()
            open_ports = self.advanced_detector.scan_open_ports()
            
            # Use SecurityEngine for advanced threat analysis
            threats = []
            
            activity = self._collect_filesystem_activity()
            ransom_result = self.security_engine.monitor_filesystem_activity(activity)
            if ransom_result.get("verified"):
                threat_entry = {
                    "type": "ransomware",
                    "severity": "critical",
                    "details": ransom_result,
                }
                threats.append(threat_entry)
                self._register_runtime_threat(
                    "RANSOMWARE",
                    "monitor_filesystem_activity",
                    "CRITICAL",
                    ransom_result,
                )

            connection_metadata = self._get_tls_connection_metadata()
            if connection_metadata:
                mitm_result = self.security_engine.verify_tunnel_integrity(connection_metadata)
                mitm_result = dict(mitm_result or {})
                status = str(mitm_result.get("status") or "")
                # Never promote NOT_VERIFIABLE / trust-store failures as confirmed LIVE MITM
                if status in ("SECURE", "STABLE", "OPERATIONAL", "NOT_VERIFIABLE"):
                    pass
                elif mitm_result.get("verified") is True and mitm_result.get("anomalies"):
                    # Require stronger signal than local CA noise
                    anomalies = [str(a) for a in (mitm_result.get("anomalies") or [])]
                    if any("NOT_VERIFIABLE" in a for a in anomalies):
                        mitm_result["verified"] = False
                        mitm_result["confidence"] = "NOT_AVAILABLE"
                        mitm_result["data_state"] = "NOT_VERIFIABLE"
                    else:
                        mitm_result.setdefault(
                            "evidence",
                            "; ".join(anomalies)[:500],
                        )
                        mitm_result.setdefault("confidence", "NOT_AVAILABLE")
                        threat_entry = {
                            "type": "mitm",
                            "severity": "high",
                            "details": mitm_result,
                        }
                        threats.append(threat_entry)
                        self._register_runtime_threat("MITM", "network_monitor", "HIGH", mitm_result)

            for auth_threat in self._detect_auth_anomalies():
                threats.append(auth_threat)
                det = auth_threat.get("details") or {}
                self._register_runtime_threat(
                    auth_threat.get("type", "auth_anomaly").upper(),
                    "audit_logs",
                    auth_threat.get("severity", "medium").upper(),
                    det,
                )
            
            for threat in threats:
                self._log_threat(threat)
            
            total_threats = self._count_verified_threats(threats, suspicious_processes)
            vulnerabilities = self._collect_vulnerabilities_during_threat_scan(
                suspicious_processes,
                open_ports,
            )
            result = {
                "threats": threats,
                "suspicious_processes": suspicious_processes,
                "open_ports": open_ports,
                "vulnerabilities": vulnerabilities,
                "total_threats": total_threats,
                "last_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_audit": {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "execution_count": int(getattr(self, "_threat_scan_exec_count", 0) or 0) + 1,
                    "duration_ms": None,
                    "source": "novus_security_integration._run_threat_detection",
                },
            }
            self._threat_scan_exec_count = result["scan_audit"]["execution_count"]
            try:
                from services.alert_channel_service import dispatch_threat_alerts
                dispatch_threat_alerts(threats, suspicious_processes)
            except Exception as alert_exc:
                logger.debug("dispatch_threat_alerts: %s", alert_exc)
            return result
        except Exception as e:
            logger.error("Error detecting threats: %s", e)
            return {
                "threats": [],
                "suspicious_processes": [],
                "open_ports": [],
                "vulnerabilities": [],
                "total_threats": None,
                "last_scan": None,
            }

    def _collect_vulnerabilities_during_threat_scan(
        self,
        suspicious_processes: list,
        open_ports: list,
    ) -> list:
        """
        Actualiza vulnerabilidades dentro de un escaneo de amenazas sin re-entrar
        en scan_vulnerabilities() (evita recursión con motores/ASPE/UCE).
        """
        try:
            raw = self.collect_raw_vulnerabilities(
                prefetched_processes=suspicious_processes,
                prefetched_ports=open_ports,
            )
            from services.vulnerability_analyst_service import classify_verify_and_enrich

            classified = classify_verify_and_enrich(raw)
            activas = classified["activas"]
            pendientes = classified["pendientes_verificacion"]
            if len(activas) > 120:
                activas = activas[:120]
            if len(pendientes) > 80:
                pendientes = pendientes[:80]

            self._threat_cache["vulnerabilities"] = activas
            self._threat_cache["vulnerabilities_pending"] = pendientes
            self._threat_cache["vulnerabilities_audit"] = {
                "total_raw": classified["total_raw"],
                "activas_verificadas": len(activas),
                "pendientes": len(pendientes),
                "rechazados": len(classified.get("rechazados") or []),
                "motores": [
                    "advanced_detector.scan_open_ports",
                    "advanced_detector.scan_running_processes",
                    "vulnerability_scanner.check_system_vulnerabilities",
                ],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._last_vuln_scan_time = time.time()
            return activas
        except Exception as exc:
            logger.error("Vulnerability collect during threat scan: %s", exc)
            return list(self._threat_cache.get("vulnerabilities") or [])
    
    def reset_runtime_telemetry_cache(self, reason: str = "environment_change") -> None:
        """Vacía caché de escaneo en memoria — no reutilizar hallazgos de otro entorno."""
        logger.info("Threat cache reset: %s", reason)
        self._threat_cache = {
            "threats": [],
            "suspicious_processes": [],
            "open_ports": [],
            "vulnerabilities": [],
            "vulnerabilities_pending": [],
            "total_threats": None,
            "last_scan": None,
        }
        self._last_threat_scan_time = 0
        self._last_vuln_scan_time = 0

    def invalidate_vulnerability_cache(self):
        """Invalida caché de vulnerabilidades para forzar re-análisis en vivo."""
        self._threat_cache["vulnerabilities"] = []
        self._threat_cache["vulnerabilities_pending"] = []

    def collect_raw_vulnerabilities(
        self,
        prefetched_processes: Optional[list] = None,
        prefetched_ports: Optional[list] = None,
    ) -> list:
        """
        Recolecta hallazgos únicamente de motores en vivo.
        Excluye registros SQLite estáticos (DB-VULN) sin re-verificación del motor.
        """
        from services.config_service import get_pentest_limits
        limits = get_pentest_limits()
        vulnerabilities = []
        local_ip = get_local_ip()
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        suspicious_processes = (
            prefetched_processes
            if prefetched_processes is not None
            else self.advanced_detector.scan_running_processes()
        )
        for proc in suspicious_processes[: limits["process_limit"]]:
            pid = proc.get("pid")
            if not pid:
                continue
            cmd = proc.get("command_line") or proc.get("path") or ""
            if not cmd or cmd.strip().lower() == "proceso en ejecución":
                continue
            vulnerabilities.append({
                "id": f"FIND-PROC-{pid}",
                "nombre": f"Proceso sospechoso detectado: {proc['name']}",
                "ip": format_ip_or_unavailable(local_ip),
                "riesgo": "DETECTADO",
                "estado": "Activa",
                "descripcion": cmd,
                "severidad": "Detectada",
                "fuente": "scan_running_processes",
                "motor": "advanced_detector.scan_running_processes",
                "confianza": "MEDIA",
                "fecha_analisis": ts,
                "evidencia": {
                    "pid": pid,
                    "proceso": proc.get("name"),
                    "ruta": proc.get("path"),
                    "command_line": proc.get("command_line"),
                },
            })

        open_ports = (
            prefetched_ports
            if prefetched_ports is not None
            else self.advanced_detector.scan_open_ports(local_ip)
        )
        for port in open_ports[: limits["port_limit"]]:
            port_num = port.get("port")
            if port_num is None:
                continue
            vulnerabilities.append({
                "id": f"FIND-PORT-{port_num}",
                "nombre": f"Puerto abierto detectado: {port_num}",
                "ip": port.get("target_ip") or format_ip_or_unavailable(local_ip),
                "riesgo": "DETECTADO",
                "estado": "Activa",
                "descripcion": port.get("description") or f"Puerto {port_num} abierto",
                "severidad": "Detectada",
                "fuente": "scan_open_ports",
                "motor": "advanced_detector.scan_open_ports",
                "confianza": "ALTA",
                "fecha_analisis": ts,
                "evidencia": {
                    "puerto": port_num,
                    "descripcion": port.get("description"),
                    "target_ip": port.get("target_ip") or local_ip,
                },
            })

        try:
            from vulnerability_scanner import vulnerability_scanner
            if limits.get("run_pkg_scan", True):
                for item in vulnerability_scanner.check_system_vulnerabilities() or []:
                    evidence = item.get("evidence") or {}
                    if not evidence and not item.get("file"):
                        continue
                    if not evidence:
                        evidence = {
                            "archivo": item.get("file"),
                            "permisos_medidos": item.get("permissions"),
                        }
                    if not any(evidence.values()):
                        continue
                    vulnerabilities.append({
                        "id": f"SYS-{item.get('type', 'vuln')}-{item.get('type', 'x')}-{len(vulnerabilities)}",
                        "nombre": item.get("description") or item.get("type", "Hallazgo de sistema"),
                        "tipo": item.get("type"),
                        "ip": format_ip_or_unavailable(local_ip),
                        "riesgo": (item.get("severity") or "DETECTADO").upper(),
                        "estado": "Activa",
                        "descripcion": item.get("recommendation") or item.get("description", ""),
                        "severidad": item.get("severity", "Detectada"),
                        "fuente": "vulnerability_scanner",
                        "evidencia": evidence,
                        "motor": item.get("motor") or "vulnerability_scanner.check_system_vulnerabilities",
                        "confianza": item.get("confidence") or "ALTA",
                        "fecha_analisis": item.get("timestamp") or ts,
                    })
        except Exception as vs_err:
            logger.debug(f"vulnerability_scanner: {vs_err}")

        try:
            persist = self.advanced_detector.detect_windows_persistence()
            if isinstance(persist, list):
                for idx, item in enumerate(persist):
                    vulnerabilities.append({
                        "id": f"FIND-PERSIST-{item.get('type', idx)}",
                        "nombre": f"Mecanismo de persistencia: {item.get('type', 'desconocido')}",
                        "ip": format_ip_or_unavailable(local_ip),
                        "riesgo": "OBSERVACION",
                        "estado": "Activa",
                        "descripcion": f"Persistencia Windows detectada ({item.get('type')})",
                        "severidad": "Observación",
                        "fuente": "detect_windows_persistence",
                        "motor": "advanced_detector.detect_windows_persistence",
                        "confianza": "MEDIA",
                        "fecha_analisis": ts,
                        "evidencia": item,
                    })
        except Exception as pe:
            logger.debug(f"persistence scan: {pe}")

        return vulnerabilities

    def get_cached_vulnerabilities(self) -> list:
        """Hallazgos activos del último escaneo sin disparar uno nuevo."""
        cached = self._threat_cache.get("vulnerabilities")
        if cached is not None:
            return list(cached)
        return []

    def scan_vulnerabilities(
        self,
        force=False,
        prefetched_processes: Optional[list] = None,
        prefetched_ports: Optional[list] = None,
    ):
        """
        Return only verified-active findings from live scans.
        Hallazgos sin evidencia completa → pendientes_verificacion (no activas).
        """
        current_time = time.time()
        if not force:
            cached = self._threat_cache.get("vulnerabilities")
            if cached is not None and (
                current_time - self._last_vuln_scan_time
            ) < Config.THREAT_SCAN_INTERVAL:
                return list(cached)

        try:
            raw = self.collect_raw_vulnerabilities(
                prefetched_processes=prefetched_processes,
                prefetched_ports=prefetched_ports,
            )

            try:
                from services.security_report_service import auto_generate_for_findings
                auto_generate_for_findings(raw)
            except Exception as report_error:
                logger.error(f"Auto-report generation error: {report_error}")

            from services.vulnerability_analyst_service import classify_verify_and_enrich
            classified = classify_verify_and_enrich(raw)

            activas = classified["activas"]
            pendientes = classified["pendientes_verificacion"]
            if len(activas) > 120:
                activas = activas[:120]
            if len(pendientes) > 80:
                pendientes = pendientes[:80]

            self._threat_cache["vulnerabilities"] = activas
            self._threat_cache["vulnerabilities_pending"] = pendientes
            self._threat_cache["vulnerabilities_audit"] = {
                "total_raw": classified["total_raw"],
                "activas_verificadas": len(activas),
                "pendientes": len(pendientes),
                "rechazados": len(classified.get("rechazados") or []),
                "motores": [
                    "advanced_detector.scan_open_ports",
                    "advanced_detector.scan_running_processes",
                    "vulnerability_scanner.check_system_vulnerabilities",
                ],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

            self._last_vuln_scan_time = time.time()

            if force:
                return classified
            return activas
        except Exception as e:
            logger.error(f"Error scanning vulnerabilities: {e}")
            return [] if not force else {"activas": [], "pendientes_verificacion": [], "rechazados": []}
    
    def monitor_endpoints(self):
        """
        Real-time endpoint monitoring
        Returns endpoint status with real metrics
        """
        try:
            nombre_equipo = socket.gethostname()
            sistema_op = platform.system()
            arquitectura = platform.machine()
            uso_memoria = psutil.virtual_memory()
            cpu_actual = psutil.cpu_percent(interval=0)
            ip_local = get_local_ip() or format_ip_or_unavailable(None)
            
            # Get MAC address
            try:
                import uuid
                mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,8*6,8)][::-1])
            except:
                mac = "Unknown"
            
            # Get active processes with connections
            procesos_con_conexiones = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    conexiones = len(proc.connections())
                    if conexiones > 0:
                        procesos_con_conexiones.append({
                            "pid": proc_info['pid'],
                            "nombre": proc_info['name'],
                            "cpu": proc_info.get('cpu_percent', 0),
                            "memoria": proc_info.get('memory_percent', 0),
                            "conexiones": conexiones
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Get system health
            system_health = self.scan_system_health()
            
            findings_count = (
                system_health.get('suspicious_process_count', 0) or 0
            ) + (
                system_health.get('open_port_count', 0) or 0
            )

            from utils.endpoint_status import local_host_status

            endpoint = {
                "nombre": nombre_equipo,
                "ip": ip_local,
                "mac": mac,
                "tipo": sistema_op,
                "cpu": f"{cpu_actual:.1f}%",
                "ram": f"{uso_memoria.percent:.1f}%",
                "arquitectura": arquitectura,
                "procesos_activos": len(procesos_con_conexiones),
                "uptime": f"{(datetime.now().timestamp() - psutil.boot_time()) / 3600:.1f}h",
                "estado": local_host_status(),
                "hallazgos": findings_count,
                "riesgo": "Sin hallazgos" if findings_count == 0 else f"{findings_count} hallazgos detectados"
            }
            
            return {
                "endpoint": endpoint,
                "procesos": procesos_con_conexiones[:10],
                "system_health": system_health
            }
        except Exception as e:
            logger.error(f"Error monitoring endpoints: {e}")
            return {
                "endpoint": {},
                "procesos": [],
                "system_health": {}
            }
    
    def execute_automation(self, action_type, params=None):
        """
        Execute automation actions using both engines
        Actions: memory_optimize, process_terminate, playbook_create
        """
        try:
            if action_type == "memory_optimize":
                return self._optimize_memory()
            elif action_type == "process_terminate":
                return self._terminate_process(params.get('pid'))
            elif action_type == "playbook_create":
                return self._create_playbook(params)
            else:
                return {
                    "status": "error",
                    "message": f"Unknown action type: {action_type}"
                }
        except Exception as e:
            logger.error(f"Error executing automation: {e}")
            return {
                "status": "error",
                "message": str(e)
            }
    
    def _optimize_memory(self):
        """Optimize system memory"""
        try:
            memoria = psutil.virtual_memory()
            
            # Clean temporary files
            temp_dir = tempfile.gettempdir()
            cleaned_files = 0
            try:
                for filename in os.listdir(temp_dir):
                    filepath = os.path.join(temp_dir, filename)
                    try:
                        if os.path.isfile(filepath):
                            os.remove(filepath)
                            cleaned_files += 1
                    except:
                        pass
            except:
                pass
            
            # Get memory after cleanup
            memoria_after = psutil.virtual_memory()
            
            result = {
                "status": "success",
                "message": "Memory optimization completed",
                "memory_before": f"{memoria.percent:.1f}pct",
                "memory_after": f"{memoria_after.percent:.1f}pct",
                "cleaned_files": cleaned_files,
                "freed_memory": f"{memoria.percent - memoria_after.percent:.1f}pct"
            }
            
            self._log_automation("memory_optimize", result)
            return result
        except Exception as e:
            logger.error(f"Error optimizing memory: {e}")
            return {
                "status": "error",
                "message": str(e)
            }
    
    def _terminate_process(self, pid):
        """Terminate a process by PID"""
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc.terminate()
            
            result = {
                "status": "success",
                "message": f"Process {pid} ({proc_name}) terminated",
                "pid": pid,
                "process_name": proc_name
            }
            
            self._log_automation("process_terminate", result)
            return result
        except psutil.NoSuchProcess:
            return {
                "status": "error",
                "message": f"Process {pid} not found"
            }
        except psutil.AccessDenied:
            return {
                "status": "error",
                "message": f"Access denied to terminate process {pid}"
            }
        except Exception as e:
            logger.error(f"Error terminating process: {e}")
            return {
                "status": "error",
                "message": str(e)
            }
    
    def _create_playbook(self, params):
        """Create an automation playbook in database."""
        try:
            from services import playbook_service
            playbook = playbook_service.create_playbook({
                "nombre": params.get("nombre", "New Playbook"),
                "trigger": params.get("trigger", "manual"),
                "accion": params.get("accion", "log"),
                "prioridad": params.get("prioridad", "Medio"),
                "estado": "Activo",
            })
            result = {
                "status": "success",
                "message": "Playbook created successfully",
                "playbook": playbook,
            }
            self._log_automation("playbook_create", result)
            return result
        except Exception as e:
            logger.error(f"Error creating playbook: {e}")
            return {
                "status": "error",
                "message": str(e)
            }
    
    def _collect_filesystem_activity(self):
        """Collect real filesystem activity indicators from temp and user profile dirs."""
        scan_dirs = [tempfile.gettempdir()]
        if platform.system() == "Windows":
            for env_key in ("USERPROFILE", "LOCALAPPDATA"):
                path = os.environ.get(env_key)
                if path and os.path.isdir(path):
                    scan_dirs.append(path)
        else:
            home = os.path.expanduser("~")
            for sub in ("Downloads", "Desktop", "tmp"):
                path = os.path.join(home, sub)
                if os.path.isdir(path):
                    scan_dirs.append(path)

        now = time.time()
        current_mtimes = {}
        high_entropy_files = []

        try:
            for scan_dir in scan_dirs:
                for filename in os.listdir(scan_dir)[:40]:
                    filepath = os.path.join(scan_dir, filename)
                    if not os.path.isfile(filepath):
                        continue
                    try:
                        mtime = os.path.getmtime(filepath)
                        current_mtimes[filepath] = mtime
                        entropy = self.advanced_detector.calculate_entropy(filepath)
                        if entropy >= 7.9:
                            high_entropy_files.append({
                                "path": filepath,
                                "entropy": entropy,
                                "file": filename,
                            })
                    except Exception:
                        continue
        except Exception as e:
            logger.error(f"Error collecting filesystem activity: {e}")

        state = self._fs_activity_state
        prev_mtimes = state.get("last_mtimes") or {}
        last_check = state.get("last_check") or 0
        elapsed = max(now - last_check, 1.0) if last_check else 0
        files_modified_per_sec = 0.0
        if elapsed > 0 and prev_mtimes:
            modified = sum(
                1 for path, mt in current_mtimes.items()
                if prev_mtimes.get(path) != mt or path not in prev_mtimes
            )
            files_modified_per_sec = modified / elapsed

        outbound_mbps = 0.0
        net_io = psutil.net_io_counters()
        prev_net = state.get("last_net_sent")
        prev_net_ts = state.get("last_net_check") or 0
        if prev_net is not None and prev_net_ts:
            net_elapsed = max(now - prev_net_ts, 0.1)
            bytes_delta = max(net_io.bytes_sent - prev_net, 0)
            outbound_mbps = (bytes_delta * 8) / (net_elapsed * 1_000_000)

        self._fs_activity_state = {
            "last_check": now,
            "last_mtimes": current_mtimes,
            "last_net_sent": net_io.bytes_sent,
            "last_net_check": now,
        }

        max_entropy = max((item["entropy"] for item in high_entropy_files), default=0)
        return {
            "data_entropy": max_entropy,
            "high_entropy_file_count": len(high_entropy_files),
            "high_entropy_files": high_entropy_files[:10],
            "files_modified_per_sec": round(files_modified_per_sec, 2),
            "header_integrity_violation": False,
            "outbound_traffic_mbps": round(outbound_mbps, 2),
            "files_sampled": len(current_mtimes),
        }

    def _get_tls_connection_metadata(self):
        """
        Metadatos TLS reales vía handshake (network_endpoint_enterprise.tls_probe).
        Nunca fuerza is_secure=True sin sonda exitosa.
        """
        try:
            from services.network_endpoint_enterprise.tls_probe import build_tls_connection_metadata

            return build_tls_connection_metadata()
        except Exception:
            return None

    def _detect_auth_anomalies(self) -> list:
        """Detecta fuerza bruta y credential stuffing — solo ventana temporal con log IDs."""
        from services.auth_anomaly_evidence_service import build_verified_auth_threats

        threats = build_verified_auth_threats(self.db)
        for auth_threat in threats:
            det = auth_threat.get("details") or {}
            ip = det.get("ip")
            if ip:
                self._auto_contain_auth_ip(ip, det, auth_threat.get("type", "brute_force"))
                try:
                    from services.auth_protection_service import auth_protection
                    auth_protection.apply_ip_block_from_scan(ip, det, auth_threat.get("type", "brute_force"))
                except Exception:
                    pass
        return threats

    def _auto_contain_auth_ip(self, ip: str, evidence: dict, threat_type: str) -> None:
        """Contención activa con evidencia — IP en lista de bloqueo + registro trazable."""
        if not evidence.get("verified"):
            return
        try:
            from database import SessionLocal, IPBloqueada
            from services.defense_evidence_registry import record_defense_event

            db = SessionLocal()
            try:
                existing = db.query(IPBloqueada).filter(IPBloqueada.direccion_ip == str(ip)).first()
                if not existing:
                    db.add(IPBloqueada(
                        direccion_ip=str(ip),
                        razon=f"Auth anomaly — {threat_type}",
                    ))
                    db.commit()
                    outcome = "success"
                else:
                    outcome = "skipped"
            finally:
                db.close()

            record_defense_event(
                phase="contain",
                action="block_ip_auth_anomaly",
                motor="novus_security_integration",
                outcome=outcome,
                threat_type=threat_type,
                evidence=evidence,
                reversible=True,
                revert_key=str(ip),
                detail=evidence.get("evidence"),
                confidence="Alta",
            )
        except Exception as exc:
            logger.debug("_auto_contain_auth_ip: %s", exc)

    def answer_kernel_query(self, question: str, user_email: Optional[str] = None) -> Optional[str]:
        """Responde consultas Kernel sobre amenazas runtime del motor central."""
        q = (question or "").lower()
        triggers = (
            "amenaza", "threat", "ransomware", "malware", "runtime",
            "proceso sospechoso", "brute", "credential", "spyware", "troyano",
        )
        if not any(t in q for t in triggers):
            return None
        try:
            from services.auth_protection_service import auth_protection
            auth_reply = auth_protection.answer_kernel_query(question)
            if auth_reply:
                return auth_reply
        except Exception:
            pass
        data = self.detect_threats_realtime()
        threats = data.get("threats") or []
        procs = data.get("suspicious_processes") or []
        vulns = data.get("vulnerabilities") or []
        if not threats and not procs:
            return (
                "No hay amenazas runtime activas en el último escaneo del motor central. "
                f"Vulnerabilidades en caché: {len(vulns)}."
            )
        lines = ["**Amenazas runtime — motor central NOVUS**"]
        for threat in threats[:6]:
            det = threat.get("details") or {}
            ev = det.get("evidence") if isinstance(det, dict) else str(det)[:120]
            lines.append(
                f"- {str(threat.get('type', '?')).upper()} "
                f"({threat.get('severity', '?')}): {ev or det}"
            )
        if procs:
            lines.append(f"- Procesos sospechosos detectados: {len(procs)}")
        lines.append(f"- Último escaneo: {data.get('last_scan') or 'N/D'}")
        return "\n".join(lines)

    def _register_runtime_threat(self, threat_type, source, severity, details):
        """Append threat to in-memory registry with consistent structure (canonical detection owner: NSI)."""
        from utils.verifiable_evidence import passes_runtime_threat_gate
        from services.platform_event_contract import SCOPE_HOST, SCOPE_PLATFORM, normalize_detection

        candidate = {
            "type": threat_type,
            "source": source,
            "severity": severity,
            "details": details,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        ok, reason = passes_runtime_threat_gate(candidate)
        if not ok:
            logger.debug("Runtime threat omitida (sin evidencia verificable): %s — %s", threat_type, reason)
            return

        details_dict = details if isinstance(details, dict) else {"raw": details}
        conf = None
        if isinstance(details_dict, dict):
            conf = details_dict.get("confidence") or details_dict.get("confianza")
        # Escaneo host: platform-scoped (no inventar tenant del caller HTTP)
        try:
            from services.tenant_scope_service import get_platform_tenant_id
            platform_tid = get_platform_tenant_id()
        except Exception:
            platform_tid = None

        detection = normalize_detection(
            source=source or "novus_security_integration",
            detection_type=str(threat_type or "threat").upper(),
            evidence=details_dict,
            severity=severity,
            confidence=conf,
            status="DETECTED",
            tenant_id=platform_tid,
            scope=SCOPE_PLATFORM if platform_tid else SCOPE_HOST,
            ip=details_dict.get("ip") if isinstance(details_dict, dict) else None,
        )
        # Propagar IDs al dict original (misma referencia) para _log_threat / consumers
        if isinstance(details, dict):
            details["event_id"] = detection.get("event_id")
            details["correlation_id"] = detection.get("correlation_id")
            details["scope"] = detection.get("scope")
            details["tenant_id"] = detection.get("tenant_id")
            details["detection_type"] = detection.get("detection_type")
            details["canonical"] = True
            details_dict = details


        entry = {
            'time': datetime.now().strftime("%H:%M:%S"),
            'threat_type': threat_type,
            'source': source,
            'severity': severity,
            'details': details_dict,
            'verified': True,
            'evidence': details_dict.get('evidence') if isinstance(details_dict, dict) else details,
            'event_id': detection.get('event_id'),
            'correlation_id': detection.get('correlation_id'),
            'scope': detection.get('scope'),
            'tenant_id': detection.get('tenant_id'),
            'detection_type': detection.get('detection_type'),
            'confidence': detection.get('confidence'),
        }
        self.security_engine.threat_registry.append(entry)
        try:
            from services.threat_intelligence_service import threat_intelligence
            threat_intelligence.ingest_runtime_threat(entry)
        except Exception as ti_exc:
            logger.debug(f"ThreatIntel runtime ingest: {ti_exc}")

        # Log cifrado + coordinator; Alerta canónica la escribe _log_threat (emit_alerta=False)
        try:
            self.security_engine.register_threat_event(
                self.db,
                self.vault,
                f"RUNTIME_{threat_type}",
                {
                    "severity": severity,
                    "source": source,
                    "details": details_dict,
                    "verified": True,
                    "event_id": detection.get("event_id"),
                    "correlation_id": detection.get("correlation_id"),
                    "scope": detection.get("scope"),
                    "tenant_id": detection.get("tenant_id"),
                    "detection_type": detection.get("detection_type"),
                    "threat_type": threat_type,
                    "type": threat_type,
                    "confidence": detection.get("confidence"),
                },
                emit_alerta=False,
                notify_coordinator=True,
            )
        except Exception as exc:
            logger.debug(f"register_threat_event: {exc}")

        if entry.get("verified") or (isinstance(details_dict, dict) and details_dict.get("evidence")):
            if getattr(self, "_threat_scanning", False):
                return
            try:
                from services.active_defense_orchestrator import active_defense
                active_defense.handle_runtime_threat(entry)
            except Exception as ad_exc:
                logger.debug(f"Active defense: {ad_exc}")
                try:
                    from services.adaptive_sector_protection_engine import aspe
                    from services.alerts_canonical_service import humanize_evidence_for_client
                    _human = humanize_evidence_for_client(
                        details_dict,
                        details_dict,
                    )
                    aspe.evaluate_incident(
                        {
                            "id": detection.get("event_id") or f"RUNTIME-{threat_type}-{entry['time']}",
                            "tipo": threat_type,
                            "threat_type": threat_type,
                            "motor": source,
                            "descripcion": _human.get("evidence_summary") or threat_type,
                            "evidencia": details_dict,
                            "verified": entry.get("verified"),
                            "confianza": "Alta" if severity in ("HIGH", "CRITICAL", "CRITICO") else "Media",
                            "event_id": detection.get("event_id"),
                            "scope": detection.get("scope"),
                            "tenant_id": detection.get("tenant_id"),
                        },
                        source="runtime_threat",
                    )
                except Exception as aspe_exc:
                    logger.debug(f"ASPE runtime threat: {aspe_exc}")

    def _log_threat(self, threat):
        """Log threat to database (Alerta canónica + Log cifrado) — solo con evidencia verificable."""
        try:
            from utils.ip_validation import is_documentation_ip, text_contains_documentation_ip

            details = threat.get("details") or {}
            if isinstance(details, dict):
                ip = details.get("ip")
                if is_documentation_ip(ip) or text_contains_documentation_ip(str(details.get("evidence", ""))):
                    logger.info("Alerta omitida: IP de documentación RFC 5737 (origen test/lab)")
                    return
                if not (details.get("verified") or details.get("evidence")):
                    logger.debug("Alerta omitida: sin evidencia verificable en details")
                    return
            else:
                if text_contains_documentation_ip(str(details)):
                    return

            import json
            import hashlib
            from datetime import timedelta
            from services.alerts_canonical_service import humanize_evidence_for_client
            from services.platform_event_contract import SCOPE_HOST, SCOPE_PLATFORM, normalize_detection

            details_dict = details if isinstance(details, dict) else {"raw": details}
            try:
                from services.tenant_scope_service import get_platform_tenant_id
                platform_tid = get_platform_tenant_id()
            except Exception:
                platform_tid = None

            event_id = threat.get("event_id") or details_dict.get("event_id")
            detection = normalize_detection(
                source=threat.get("source") or "novus_security_integration",
                detection_type=str(threat.get("type") or "threat").upper(),
                evidence=details_dict,
                severity=threat.get("severity"),
                confidence=threat.get("confidence") or details_dict.get("confidence"),
                status="DETECTED",
                tenant_id=threat.get("tenant_id") or platform_tid,
                scope=threat.get("scope") or (SCOPE_PLATFORM if platform_tid else SCOPE_HOST),
                event_id=event_id,
                ip=details_dict.get("ip") if isinstance(details_dict, dict) else None,
            )
            event_id = detection.get("event_id")

            titulo = f"{threat['type'].upper()} Threat Detected"
            human = humanize_evidence_for_client(details_dict, details_dict)
            descripcion = human.get("evidence_summary") or titulo
            evidence_fp = hashlib.sha256(
                f"{threat.get('type')}|{details_dict.get('ip')}|{descripcion[:160]}".encode()
            ).hexdigest()[:16]

            recent_rows = (
                self.db.query(Alerta)
                .filter(Alerta.titulo == titulo)
                .order_by(Alerta.id.desc())
                .limit(8)
                .all()
            )
            for recent in recent_rows:
                if not recent or not recent.fecha:
                    continue
                try:
                    last_dt = datetime.strptime(recent.fecha[:19], "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    continue
                if datetime.now() - last_dt >= timedelta(minutes=5):
                    continue
                prev = {}
                try:
                    if recent.evidencia_json:
                        prev = json.loads(recent.evidencia_json)
                except Exception:
                    prev = {}
                if prev.get("event_id") and prev.get("event_id") == event_id:
                    return
                if prev.get("dedupe_fp") == evidence_fp:
                    return
                if recent.descripcion == descripcion:
                    return

            evidence_payload = dict(details_dict)
            evidence_payload.update({
                "event_id": event_id,
                "correlation_id": detection.get("correlation_id"),
                "scope": detection.get("scope"),
                "tenant_id": detection.get("tenant_id"),
                "detection_type": detection.get("detection_type"),
                "source": detection.get("source"),
                "confidence": detection.get("confidence"),
                "verified": True,
                "dedupe_fp": evidence_fp,
                "canonical": True,
            })
            evidence_json = json.dumps(evidence_payload, ensure_ascii=False)
            ip_val = details_dict.get("ip") if isinstance(details_dict, dict) else None
            alerta = Alerta(
                titulo=titulo,
                descripcion=descripcion,
                nivel=threat["severity"],
                fecha=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ip_afectada=ip_val,
                motor=threat.get("source") or (details_dict.get("source") if isinstance(details_dict, dict) else None),
                fuente="novus_security_integration",
                confianza=(
                    detection.get("confidence")
                    if detection.get("confidence") not in (None, "NOT_AVAILABLE", "NO DISPONIBLE")
                    else ("Alta" if str(threat.get("severity", "")).upper() in ("HIGH", "CRITICAL", "CRITICO") else "Media")
                ),
                estado="activo",
                evidencia_json=evidence_json,
                activa=True,
            )
            if hasattr(alerta, "tenant_id"):
                # Host/platform detections: stamp platform tenant only — never invent per-request tenant
                alerta.tenant_id = detection.get("tenant_id")
            self.db.add(alerta)
            from database import registrar_log_seguridad
            registrar_log_seguridad(
                self.db,
                f"THREAT_{threat.get('type', 'unknown').upper()}",
                descripcion,
                vault=self.vault,
            )
            self.db.commit()
        except Exception as e:
            logger.error(f"Error logging threat: {e}")
            self.db.rollback()
    
    def _log_automation(self, action, result):
        """Log automation action to database"""
        try:
            from database import registrar_log_seguridad
            registrar_log_seguridad(
                self.db,
                f"automation_{action}",
                str(result),
                vault=self.vault,
            )
            self.db.commit()
        except Exception as e:
            logger.error(f"Error logging automation: {e}")
            self.db.rollback()
    
    def get_cached_security_summary(self):
        """Lightweight dashboard summary using cached scans and live psutil metrics."""
        try:
            cpu = psutil.cpu_percent(interval=0)
            memoria = psutil.virtual_memory()
            disco = get_disk_usage()
            cached = dict(self._threat_cache)
            suspicious = cached.get('suspicious_processes', [])
            open_ports = cached.get('open_ports', [])
            vulnerabilities = cached.get('vulnerabilities', [])

            from utils.endpoint_status import local_host_status

            return {
                "system_health": {
                    "cpu_usage": cpu,
                    "memory_usage": memoria.percent,
                    "disk_usage": disco.percent,
                    "suspicious_process_count": len(suspicious),
                    "open_port_count": len(open_ports),
                },
                "threats": cached,
                "vulnerabilities": vulnerabilities,
                "endpoints": {
                    "endpoint": {
                        "nombre": socket.gethostname(),
                        "ip": format_ip_or_unavailable(get_local_ip()),
                        "estado": local_host_status(),
                    }
                },
                "security_engine_summary": self.security_engine.get_security_summary(),
            }
        except Exception as e:
            logger.error(f"Error getting cached security summary: {e}")
            return {
                "system_health": {},
                "threats": dict(self._threat_cache),
                "vulnerabilities": [],
                "endpoints": {},
                "security_engine_summary": {},
            }

    def get_security_summary(self):
        """Get comprehensive security summary for dashboard"""
        try:
            system_health = self.scan_system_health()
            threats = self.detect_threats_realtime()
            vulnerabilities = self.scan_vulnerabilities()
            endpoints = self.monitor_endpoints()
            
            return {
                "system_health": system_health,
                "threats": threats,
                "vulnerabilities": vulnerabilities,
                "endpoints": endpoints,
                "security_engine_summary": self.security_engine.get_security_summary()
            }
        except Exception as e:
            logger.error(f"Error getting security summary: {e}")
            return {
                "system_health": {},
                "threats": {},
                "vulnerabilities": [],
                "endpoints": {},
                "security_engine_summary": {}
            }


def start_background_threat_scanner():
    """Run periodic threat and vulnerability scans — results cached for APIs."""
    def scan_loop():
        cycle = 0
        boot_grace_cycles = int(os.environ.get("NOVUS_THREAT_BOOT_GRACE_CYCLES", "2"))
        vuln_every_n = max(1, int(os.environ.get("NOVUS_VULN_SCAN_EVERY_N", "4")))
        while True:
            try:
                cycle += 1
                from services.resource_backpressure_service import (
                    should_run_background,
                    CAT_SECURITY_LIGHT,
                    CAT_HEAVY_AGG,
                )

                if cycle > boot_grace_cycles and should_run_background(CAT_SECURITY_LIGHT):
                    cache = dict(novus_security._threat_cache or {})
                    stale = not cache.get("last_scan")
                    novus_security.detect_threats_realtime(force=stale or cycle % 2 == 0)
                elif cycle > boot_grace_cycles:
                    logger.debug("Threat scan deferred — backpressure")

                if (
                    cycle > boot_grace_cycles
                    and cycle % vuln_every_n == 0
                    and should_run_background(CAT_HEAVY_AGG)
                ):
                    audit = (novus_security._threat_cache or {}).get("vulnerabilities_audit") or {}
                    force_vuln = not audit.get("timestamp")
                    novus_security.scan_vulnerabilities(force=force_vuln)

                try:
                    from services.active_defense_orchestrator import active_defense
                    active_defense.verify_and_reconcile_active_incidents()
                except Exception as rec_exc:
                    logger.debug("Active defense reconcile: %s", rec_exc)
                time.sleep(Config.THREAT_SCAN_INTERVAL)
            except Exception as e:
                logger.error(f"Background threat scanner error: {e}", exc_info=True)
                time.sleep(Config.THREAT_SCAN_INTERVAL)

    thread = threading.Thread(target=scan_loop, daemon=True, name="ThreatScanner")
    thread.start()
    logger.info("Background threat scanner started")


# Global instance
novus_security = NovusSecurityIntegration()
