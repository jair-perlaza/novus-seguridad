"""
AI Kernel Service for NOVUS
Autonomous response agent with resource monitoring and conversational assistant.
Integrates GuardIA (ai_engine.py) for heuristic analysis.
"""
import os
import re
import threading
import time
import uuid
import psutil
from datetime import datetime
from typing import Optional

from utils.logger import logger
from core.config import Config
from services.system_monitor import system_monitor
from services.network_scanner import network_scanner
from services.ai_orchestrator import kernel_orchestrator, MODULES

# GuardIA — motor heurístico existente (no reemplazar)
try:
    from ai_engine import GuardIA
except ImportError:
    GuardIA = None

MODULE_ROUTES = {
    "dashboard": "/",
    "inicio": "/",
    "network": "/network",
    "red": "/network",
    "vulnerabilidades": "/vulnerabilidades",
    "vuln": "/vulnerabilidades",
    "incidentes": "/incidentes",
    "xdr": "/amenazas",
    "amenazas": "/amenazas",
    "reportes": "/reportes",
    "informes": "/reportes",
    "configuracion": "/configuracion",
    "config": "/configuracion",
    "endpoints": "/endpoints",
    "web_shield": "/web-shield",
    "webshield": "/web-shield",
    "mail_shield": "/mail-shield",
    "correo": "/mail-shield",
    "siem": "/siem",
    "logs": "/siem",
    "automatizacion": "/automatizacion",
    "topology": "/topology",
    "topologia": "/topology",
}

ALLOWED_DATA_DIRS = [
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "data"),
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "reports"),
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "playbooks"),
]


class AIKernel:
    """
    AI-KERNEL: Autonomous Response Agent
    Monitors resources, detects intrusions, and manages files
    Optimized to reduce CPU usage with efficient polling
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        self._running = False
        self._thread = None
        self._logs = "Estado: Inicializando..."
        self._logs_lock = threading.Lock()
        self._sessions = {}
        self._sessions_lock = threading.Lock()
        self._guardia = GuardIA() if GuardIA else None
        self._activity = "idle"
        self._last_analysis_at: Optional[str] = None
        self._last_analysis_error: Optional[str] = None
    
    def start(self):
        """Start AI Kernel engine"""
        if self._running:
            logger.warning("AI Kernel already running")
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="AIKernel")
        self._thread.start()
        logger.info("AI Kernel started")
    
    def stop(self):
        """Stop AI Kernel engine"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("AI Kernel stopped")
    
    def _run_loop(self):
        """Main AI Kernel loop"""
        logger.info("AI-KERNEL: Sistema de Decisión Activo")
        
        while self._running:
            try:
                self._analyze_system()
                time.sleep(Config.AI_KERNEL_INTERVAL)
            except Exception as e:
                logger.error(f"AI Kernel error: {e}", exc_info=True)
                time.sleep(Config.AI_KERNEL_INTERVAL)
    
    def _analyze_system(self):
        """
        Analyze system state and take autonomous actions
        """
        try:
            # Get system metrics
            status = system_monitor.get_system_status()
            cpu_load = status.get('cpu', 0)
            mem_load = status.get('ram', 0)
            
            # Get network info
            network_nodes = network_scanner.get_cached_nodes()
            
            # Check for critical conditions
            if cpu_load > Config.CPU_CRITICAL_THRESHOLD or mem_load > Config.MEMORY_CRITICAL_THRESHOLD:
                logger.warning(f"[ALERTA IA] Carga crítica detectada (CPU: {cpu_load}pct, RAM: {mem_load}pct)")
                try:
                    from services.defense_coordinator import defense_coordinator

                    defense_coordinator.record_detection(
                        "ai_kernel",
                        "critical_resource_load",
                        {"cpu": cpu_load, "ram": mem_load, "nodes": len(network_nodes)},
                        phase="detect",
                        outcome="detected",
                        threat_type="generic",
                        detail=f"Carga crítica CPU={cpu_load}% RAM={mem_load}%",
                        confidence="Alta",
                    )
                    defense_coordinator.notify_kernel_incident(
                        "ai_kernel",
                        "KERNEL_RESOURCE_ALERT",
                        f"Carga crítica: CPU {cpu_load}% RAM {mem_load}%",
                        severity="high",
                    )
                except Exception as kern_exc:
                    logger.debug("AI kernel defense notify: %s", kern_exc)
            
            # Update logs
            with self._logs_lock:
                self._logs = f"Estado: Nominal | CPU: {cpu_load}pct | RAM: {mem_load}pct | Nodos: {len(network_nodes)}"
            self._last_analysis_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            self._last_analysis_error = None
            
        except Exception as e:
            self._last_analysis_error = str(e)[:200]
            logger.error(f"Error in system analysis: {e}", exc_info=True)
    
    def get_logs(self):
        """Get current AI Kernel logs"""
        with self._logs_lock:
            return self._logs
    
    def execute_command(self, command, target):
        """
        Execute supported automation commands using the security integration layer.
        """
        logger.info(f"[KERNEL] Recibida orden de IA: {command} sobre {target}")

        supported_actions = {
            'memory_optimize': 'memory_optimize',
            'optimize_memory': 'memory_optimize',
            'terminate_process': 'process_terminate',
            'kill_process': 'process_terminate',
        }

        action_type = supported_actions.get(str(command).strip().lower())
        if not action_type:
            return {
                "status": "unavailable",
                "message": f"Comando '{command}' sin fuente de datos real configurada",
                "timestamp": time.strftime("%H:%M:%S")
            }

        try:
            from services.novus_security_integration import novus_security

            params = {}
            if action_type == 'process_terminate':
                if not str(target).isdigit():
                    return {
                        "status": "error",
                        "message": "Se requiere un PID numérico para terminar un proceso",
                        "timestamp": time.strftime("%H:%M:%S")
                    }
                params = {'pid': int(target)}

            result = novus_security.execute_automation(action_type, params)
            result["timestamp"] = time.strftime("%H:%M:%S")
            return result
        except Exception as e:
            logger.error(f"Error executing AI command: {e}", exc_info=True)
            return {
                "status": "error",
                "message": str(e),
                "timestamp": time.strftime("%H:%M:%S")
            }
    
    def analyze_file(self, filepath):
        """
        Analyze file for security threats
        Args:
            filepath: Path to file
        Returns:
            Analysis result
        """
        import os
        
        try:
            if not os.path.exists(filepath):
                return {"status": "error", "message": "File not found"}
            
            size = os.path.getsize(filepath)
            return {
                "status": "success",
                "analysis": {
                    "size": f"{round(size/1024, 2)} KB",
                    "safe": "Sin datos disponibles",
                    "detected": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "note": "Análisis de malware requiere motor de firmas o VirusTotal configurado.",
                }
            }
        except Exception as e:
            logger.error(f"Error analyzing file: {e}", exc_info=True)
            return {"status": "error", "message": str(e)}
    
    def delete_file(self, filepath):
        """
        Delete file or directory
        Args:
            filepath: Path to file/directory
        Returns:
            Operation result
        """
        import os
        import shutil
        
        try:
            if not os.path.exists(filepath):
                return {"status": "error", "message": "Path not found"}
            
            if os.path.isfile(filepath):
                os.remove(filepath)
            else:
                shutil.rmtree(filepath)
            
            return {
                "status": "success",
                "message": f"Elemento eliminado: {filepath}"
            }
        except Exception as e:
            logger.error(f"Error deleting file: {e}", exc_info=True)
            return {"status": "error", "message": str(e)}

    # ------------------------------------------------------------------
    # Session memory & conversational assistant (Kernel IA habilitado)
    # ------------------------------------------------------------------

    def _get_session(self, session_id):
        with self._sessions_lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = {
                    "history": [],
                    "context": {},
                    "pending_confirm": None,
                    "created_at": datetime.now().isoformat(),
                }
            return self._sessions[session_id]

    def get_history(self, session_id, limit=50):
        session = self._get_session(session_id)
        return session["history"][-limit:]

    def _append_history(self, session_id, role, content, meta=None):
        session = self._get_session(session_id)
        entry = {
            "role": role,
            "content": content,
            "time": datetime.now().strftime("%H:%M:%S"),
            "meta": meta or {},
        }
        session["history"].append(entry)
        if len(session["history"]) > 100:
            session["history"] = session["history"][-100:]

    def get_status(self):
        with self._logs_lock:
            logs = self._logs
        running = bool(self._running)
        guardia_ok = self._guardia is not None
        interval = float(getattr(Config, "AI_KERNEL_INTERVAL", 60) or 60)

        if not running:
            operational = "STOPPED"
        elif self._last_analysis_error and not self._last_analysis_at:
            operational = "ERROR"
        elif not guardia_ok:
            operational = "DEGRADED"
        elif not self._last_analysis_at:
            operational = "IDLE"
        else:
            try:
                last_ts = datetime.strptime(self._last_analysis_at[:19], "%Y-%m-%dT%H:%M:%S")
                age_sec = (datetime.utcnow() - last_ts).total_seconds()
                operational = "ACTIVE" if age_sec <= interval * 2.5 else "IDLE"
            except Exception:
                operational = "IDLE"

        threat_evidence = False
        vuln_evidence = False
        try:
            from services.novus_security_integration import novus_security

            threat_evidence = bool(novus_security.get_cached_threat_count())
            cache = novus_security.get_security_cache() or {}
            vuln_evidence = bool(cache.get("vulnerabilities"))
        except Exception:
            pass

        btde_status = "NOT_IMPLEMENTED"
        try:
            from services.behavioral_threat_detection import get_btde_status

            st = get_btde_status() or {}
            if st.get("running") or st.get("active"):
                btde_status = "ACTIVE"
            elif st.get("status") not in (None, "NOT_IMPLEMENTED", "NOT VERIFIED"):
                btde_status = "STOPPED"
        except Exception:
            btde_status = "NOT_IMPLEMENTED"

        capabilities = {
            "context_refresh": {
                "status": "ACTIVE" if running else "STOPPED",
                "source": "system_monitor+network_scanner cache",
                "description": "Recopila telemetría real en sesión conversacional",
            },
            "threat_analysis": {
                "status": "ACTIVE" if threat_evidence else ("DEGRADED" if guardia_ok and running else "NO_DATA"),
                "source": "GuardIA heurístico + novus_security cache",
                "description": "Análisis de amenazas solo con evidencia de motor",
            },
            "vulnerability_analysis": {
                "status": "ACTIVE" if vuln_evidence else "NO_DATA",
                "source": "vulnerability_scanner cache",
                "description": "Sin vulnerabilidades en caché = NO_DATA, no simulación",
            },
            "anomaly_detection": {
                "status": btde_status,
                "source": "behavioral_threat_detection",
                "description": "BTDE lazy — no panel usuario",
            },
            "security_decision": {
                "status": "ACTIVE" if guardia_ok else "NOT_IMPLEMENTED",
                "source": "ai_engine.GuardIA",
                "description": "Reglas heurísticas GuardIA",
            },
            "automated_response": {
                "status": "DEGRADED" if running else "NOT_IMPLEMENTED",
                "source": "defense_coordinator record_detection",
                "description": "Respuesta limitada a alertas de recursos críticos",
            },
        }

        return {
            "kernel": "AIKernel",
            "operational_status": operational,
            "guardia": guardia_ok,
            "running": running,
            "activity": self._activity,
            "last_execution_at": self._last_analysis_at,
            "last_execution_error": self._last_analysis_error,
            "capabilities": capabilities,
            "note": "ACTIVE requiere hilo en ejecución y última tarea _analyze_system reciente; thread ≠ detección autónoma completa",
            "logs": logs,
            "sessions_active": len(self._sessions),
        }

    def refresh_context(self, session_id):
        """Load real NOVUS telemetry into session memory."""
        self._activity = "analyzing"
        ctx = {"refreshed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

        try:
            ctx["system"] = system_monitor.get_system_status()
        except Exception as exc:
            ctx["system"] = {"error": str(exc)}

        try:
            ctx["network_nodes"] = network_scanner.get_cached_nodes() or []
        except Exception as exc:
            ctx["network_nodes"] = []
            ctx["network_error"] = str(exc)

        try:
            from services.novus_security_integration import novus_security
            cache = novus_security._threat_cache or {}
            ctx["vulnerabilities"] = cache.get("vulnerabilities") or []
            ctx["threat_count"] = novus_security.get_cached_threat_count()
            ctx["suspicious_processes"] = cache.get("suspicious_processes") or []
            ctx["open_ports"] = cache.get("open_ports") or []
        except Exception as exc:
            ctx["vulnerabilities"] = []
            ctx["security_error"] = str(exc)

        try:
            from services.security_report_service import list_reports
            ctx["reports"] = list_reports(limit=10)
        except Exception as exc:
            ctx["reports"] = []

        try:
            from database import SessionLocal, Alerta
            db = SessionLocal()
            try:
                ctx["incidents"] = [
                    {"id": f"INC-{a.id:04d}", "tipo": a.titulo, "ip": a.ip_afectada, "descripcion": a.descripcion}
                    for a in db.query(Alerta).order_by(Alerta.id.desc()).limit(10).all()
                ]
            finally:
                db.close()
        except Exception as exc:
            ctx["incidents"] = []

        try:
            ctx["processes"] = [
                {"pid": p.info.get("pid"), "name": p.info.get("name"), "cpu": p.info.get("cpu_percent")}
                for p in list(psutil.process_iter(["pid", "name", "cpu_percent"]))[:15]
            ]
        except Exception as exc:
            ctx["processes"] = []

        session = self._get_session(session_id)
        session["context"] = ctx
        self._activity = "idle"
        return ctx

    def get_context(self, session_id, refresh=False):
        session = self._get_session(session_id)
        if refresh or not session.get("context"):
            return self.refresh_context(session_id)
        return session["context"]

    def _normalize(self, text):
        return re.sub(r"\s+", " ", str(text or "").lower().strip())

    def _match_intent(self, message):
        m = self._normalize(message)

        patterns = [
            (r"(explicar|explain|qué es|que es)", "explain"),
            (r"(abrir|ir a|open|mostrar).*(dashboard|network|red|vuln|xdr|reporte|config|incident|siem|endpoint|amenaza)", "navigate"),
            (r"(reporte|informe|historial|pdf)", "reports"),
            (r"(escanear|scan|analizar).*(red|network|arp)", "scan_network"),
            (r"(buscar|scan).*(vulnerabil|vuln|pentest)", "scan_vulnerabilities"),
            (r"(vulnerabil|vuln|pentest)", "scan_vulnerabilities"),
            (r"(malware|virus|rootkit|ransomware)", "scan_malware"),
            (r"(proceso|process)", "scan_processes"),
            (r"(puerto|port\b|ports\b)", "scan_ports"),
            (r"(firewall|cortafuego)", "analyze_firewall"),
            (r"(conexion|conexiones|connection)", "analyze_connections"),
            (r"(dispositivo|device|nodo|equipo)", "list_devices"),
            (r"(mail shield|mailshield|correo|phishing|bec\b)", "mail_shield"),
            (r"(web shield|webshield|navegaci|phishing|descarga sospechosa)", "web_shield"),
            (r"(incidente|alerta)", "list_incidents"),
            (r"(remediar|mitigar|parche)", "remediate"),
            (r"(buscar|search|encontrar)", "search"),
            (r"(carpeta|directorio|folder|data)", "browse_data"),
            (r"(sistema|system|salud|health)", "scan_system"),
            (r"(ayuda|help|comandos)", "help"),
        ]
        for pattern, intent in patterns:
            if re.search(pattern, m):
                return intent, m
        if m in MODULE_ROUTES:
            return "navigate", m
        return "general", m

    def _safe_path(self, path):
        abs_path = os.path.abspath(path)
        for allowed in ALLOWED_DATA_DIRS:
            if abs_path.startswith(os.path.abspath(allowed)):
                return abs_path
        return None

    def process_message(self, session_id, message, user_email=None, user_id=None, confirm_token=None):
        """Process user message — orquestador multi-módulo con datos reales."""
        session = self._get_session(session_id)

        if confirm_token and session.get("pending_confirm"):
            pending = session["pending_confirm"]
            if pending.get("token") == confirm_token:
                session["pending_confirm"] = None
                result = self._execute_confirmed(pending)
                self._append_history(session_id, "user", f"[Confirmado] {pending.get('label')}")
                self._append_history(session_id, "assistant", result.get("reply", ""), result)
                return result
            return {
                "reply": "Token de confirmación inválido o expirado.",
                "actions": [],
                "confirm_required": False,
            }

        self._append_history(session_id, "user", message)

        if self._guardia:
            risk = self._guardia.analizar_riesgo(message)
            if risk.get("nivel", 0) >= 8:
                reply = f"Entrada bloqueada por GuardIA: {risk.get('mensaje')}. Reformule su consulta."
                self._append_history(session_id, "assistant", reply)
                return {"reply": reply, "actions": [], "confirm_required": False, "risk": risk}

        normalized = self._normalize(message)

        # Ayuda explícita
        if re.search(r"\b(ayuda|help|comandos)\b", normalized):
            result = self._dispatch_intent(session_id, "help", message, normalized, {})
            self._append_history(session_id, "assistant", result.get("reply", ""), result)
            return result

        # Remediación con confirmación
        if re.search(r"\b(remediar|mitigar|parchear)\b", normalized):
            ctx = self.get_context(session_id)
            result = self._dispatch_intent(session_id, "remediate", message, normalized, ctx)
            self._append_history(session_id, "assistant", result.get("reply", ""), result)
            return result

        # Navegación directa (mensaje corto tipo "abrir network")
        if re.search(r"\b(abrir|ir a|mostrar|navegar)\b", normalized):
            url, key = kernel_orchestrator.resolve_navigation(message)
            if url:
                result = {
                    "reply": f"Abriendo módulo: {key.title()}",
                    "actions": [{"label": "Ir ahora", "type": "navigate", "url": url}],
                    "confirm_required": False,
                    "navigate": url,
                }
                self._append_history(session_id, "assistant", result.get("reply", ""), result)
                return result

        # --- Operador autónomo SOC/XDR: CONSULTA vs ACCIÓN (sin chatbot de resumen) ---
        from services.kernel_operator import kernel_operator

        self._activity = "operating"
        try:
            result = kernel_operator.process(
                session_id,
                message,
                user_id=user_id,
                user_email=user_email,
            )
            result.setdefault("actions", [])
            result.setdefault("confirm_required", False)
            if result.get("soc_workflow") or result.get("deep_scan"):
                self._activity = "soc_workflow"
            elif result.get("request_type") == "action":
                self._activity = "executing"
        except Exception as exc:
            logger.error(f"KernelOperator error: {exc}", exc_info=True)
            result = {
                "reply": f"Error en operador del Kernel IA: {exc}",
                "actions": [{"label": "Ayuda", "type": "quick", "message": "ayuda"}],
                "confirm_required": False,
            }
        finally:
            if not (result.get("defer_full_reply") or result.get("defer_reply")):
                self._activity = "idle"

        if result.get("defer_full_reply") or result.get("defer_reply") or result.get("working"):
            self._append_history(
                session_id,
                "assistant",
                "[Kernel] Análisis en ejecución — respuesta pendiente.",
                result,
            )
        else:
            self._append_history(session_id, "assistant", result.get("reply", ""), result)
        return result

    def _dispatch_intent(self, session_id, intent, message, normalized, ctx):
        actions = []

        if intent == "help":
            return {
                "reply": (
                    "Analista SOC/XDR NOVUS — no es un chatbot de resumen.\n\n"
                    "Flujo por consulta:\n"
                    "  1. Clasificar intención\n"
                    "  2. Ejecutar motores reales (force_refresh)\n"
                    "  3. Fusionar evidencias\n"
                    "  4. Generar informe SOC profesional\n\n"
                    "Ejemplos:\n"
                    "• «Escanea mi portátil» → Deep Scan por fases\n"
                    "• «¿Cómo está mi red?» → ARP + conexiones + informe\n"
                    "• «¿Cuántas vulnerabilidades?» → listado detallado + remediación\n"
                    "• «Limpia las amenazas» → escaneo + confirmación + remediación\n"
                    "• «Mi PC está lento» → procesos + memoria + servicios\n\n"
                    "Motores no disponibles (Radar, VirusTotal, SPF/DKIM) se indican explícitamente."
                ),
                "actions": [
                    {"label": "Escanear red", "type": "quick", "message": "escanear red"},
                    {"label": "Vulnerabilidades", "type": "quick", "message": "buscar vulnerabilidades"},
                    {"label": "Abrir Reportes", "type": "navigate", "url": "/reportes"},
                ],
                "confirm_required": False,
            }

        if intent == "navigate":
            for key, url in MODULE_ROUTES.items():
                if key in normalized:
                    return {
                        "reply": f"Abriendo módulo: {key.title()}",
                        "actions": [{"label": "Ir ahora", "type": "navigate", "url": url}],
                        "confirm_required": False,
                        "navigate": url,
                    }
            return {"reply": "Indique qué módulo desea abrir (Network, XDR, Reportes, etc.).", "actions": [], "confirm_required": False}

        if intent == "search":
            q = normalized.replace("buscar", "").replace("search", "").strip() or message
            return {
                "reply": f"Búsqueda global: «{q.strip()}». Use el buscador (Ctrl+K) o pulse el botón.",
                "actions": [{"label": "Buscar", "type": "search", "query": q.strip()}],
                "confirm_required": False,
            }

        if intent == "scan_network":
            self._activity = "scanning"
            try:
                from services.network_scan_coordinator import schedule_network_discovery

                scheduled = schedule_network_discovery(consumer="ai_kernel", force=False)
                nodes = network_scanner.get_cached_nodes() or []
                self.refresh_context(session_id)
                self._activity = "idle"
                if nodes:
                    lines = [f"• {n.get('name', 'N/D')} — {n.get('ip', 'Sin IP')} ({n.get('status', 'N/D')})" for n in nodes[:10]]
                    reply = f"Snapshot de red: {len(nodes)} dispositivo(s).\n" + "\n".join(lines)
                elif scheduled:
                    reply = "Descubrimiento de red programado en background. Consulte Network en unos segundos."
                else:
                    reply = "Descubrimiento ya en curso o reciente. Datos disponibles en Network cuando finalice."
                return {
                    "reply": reply,
                    "actions": [{"label": "Abrir Network", "type": "navigate", "url": "/network"}],
                    "confirm_required": False,
                    "data": {"count": len(nodes), "discovery_scheduled": scheduled},
                }
            except Exception as exc:
                self._activity = "idle"
                return {"reply": f"Error al programar escaneo de red: {exc}", "actions": [], "confirm_required": False}

        if intent == "scan_vulnerabilities":
            self._activity = "scanning"
            try:
                from services.novus_security_integration import novus_security
                vulns = novus_security.scan_vulnerabilities()[:10]
                self.refresh_context(session_id)
                self._activity = "idle"
                if not vulns:
                    return {"reply": "No se detectaron vulnerabilidades en el escaneo actual.", "actions": [{"label": "Abrir Vulnerabilidades", "type": "navigate", "url": "/vulnerabilidades"}], "confirm_required": False}
                lines = [f"• [{v.get('id')}] {v.get('nombre', 'N/D')}" for v in vulns]
                return {
                    "reply": f"{len(vulns)} hallazgo(s) detectado(s):\n" + "\n".join(lines),
                    "actions": [
                        {"label": "Ver detalle", "type": "navigate", "url": "/vulnerabilidades"},
                        {"label": "Sincronizar reportes", "type": "api", "endpoint": "/api/reports/sync", "method": "POST"},
                    ],
                    "confirm_required": False,
                }
            except Exception as exc:
                self._activity = "idle"
                return {"reply": f"Error en escaneo de vulnerabilidades: {exc}", "actions": [], "confirm_required": False}

        if intent == "scan_system":
            sys_data = ctx.get("system") or system_monitor.get_system_status()
            return {
                "reply": (
                    f"Análisis del sistema ({ctx.get('refreshed_at', 'ahora')}):\n"
                    f"• CPU: {sys_data.get('cpu', 'N/D')}%\n"
                    f"• RAM: {sys_data.get('ram', 'N/D')}%\n"
                    f"• Disco: {sys_data.get('disk', 'N/D')}%\n"
                    f"• Nodos red: {len(ctx.get('network_nodes', []))}\n"
                    f"• Vulnerabilidades abiertas: {len(ctx.get('vulnerabilities', []))}"
                ),
                "actions": [{"label": "Dashboard", "type": "navigate", "url": "/"}],
                "confirm_required": False,
            }

        if intent == "scan_processes":
            procs = ctx.get("processes") or []
            if not procs:
                self.refresh_context(session_id)
                procs = self._get_session(session_id)["context"].get("processes", [])
            suspicious = ctx.get("suspicious_processes") or []
            lines = [f"• PID {p.get('pid')} — {p.get('name')}" for p in procs[:8]]
            sus_lines = [f"• {s.get('name', 'N/D')} PID {s.get('pid')}" for s in suspicious[:5]]
            reply = "Procesos monitorizados:\n" + ("\n".join(lines) if lines else "Sin datos de procesos.")
            if sus_lines:
                reply += "\n\nProcesos sospechosos (detector):\n" + "\n".join(sus_lines)
            return {
                "reply": reply,
                "actions": [{"label": "Endpoints", "type": "navigate", "url": "/endpoints"}],
                "confirm_required": False,
            }

        if intent == "scan_ports":
            ports = ctx.get("open_ports") or []
            if not ports:
                try:
                    from services.advanced_detector_service import advanced_detector
                    from utils.host_data import get_local_ip
                    ports = advanced_detector.scan_open_ports(get_local_ip())[:10]
                except Exception:
                    ports = []
            if not ports:
                return {"reply": "Sin datos de puertos abiertos disponibles en este momento.", "actions": [], "confirm_required": False}
            lines = [f"• Puerto {p.get('port')} — {p.get('description', p.get('service', 'N/D'))}" for p in ports]
            return {"reply": "Puertos abiertos detectados:\n" + "\n".join(lines), "actions": [{"label": "Vulnerabilidades", "type": "navigate", "url": "/vulnerabilidades"}], "confirm_required": False}

        if intent == "scan_malware":
            sus = ctx.get("suspicious_processes") or []
            vulns = [v for v in (ctx.get("vulnerabilities") or []) if "PROC" in str(v.get("id", ""))]
            reply = "Análisis antimalware basado en telemetría local:\n"
            if sus:
                reply += f"• {len(sus)} proceso(s) sospechoso(s) en detector.\n"
            if vulns:
                reply += f"• {len(vulns)} hallazgo(s) de proceso en vulnerabilidades.\n"
            if not sus and not vulns:
                reply += "No se detectaron indicadores de malware/rootkit/ransomware en los datos actuales. Para análisis profundo configure VirusTotal API."
            return {
                "reply": reply,
                "actions": [{"label": "XDR / Amenazas", "type": "navigate", "url": "/amenazas"}, {"label": "Escanear de nuevo", "type": "quick", "message": "buscar vulnerabilidades"}],
                "confirm_required": False,
            }

        if intent == "analyze_connections":
            try:
                conns = psutil.net_connections(kind="inet")[:20]
                established = [c for c in conns if c.status == "ESTABLISHED"]
                reply = f"Conexiones activas: {len(established)} establecidas (muestra de {len(conns)}).\n"
                for c in established[:5]:
                    if c.laddr and c.raddr:
                        reply += f"• {c.laddr.ip}:{c.laddr.port} → {c.raddr.ip}:{c.raddr.port}\n"
                if not established:
                    reply += "Sin conexiones establecidas en la muestra."
            except Exception as exc:
                reply = f"No se pudieron leer conexiones: {exc}"
            return {"reply": reply, "actions": [{"label": "Network", "type": "navigate", "url": "/network"}], "confirm_required": False}

        if intent == "analyze_firewall":
            return {
                "reply": "NOVUS no administra el firewall del SO directamente. Revise puertos abiertos detectados y aplique reglas en el sistema operativo. Puedo listar puertos expuestos.",
                "actions": [{"label": "Ver puertos", "type": "quick", "message": "analizar puertos abiertos"}],
                "confirm_required": False,
            }

        if intent == "list_devices":
            nodes = ctx.get("network_nodes") or []
            if not nodes:
                return {"reply": "Sin dispositivos en caché. Ejecute un escaneo de red.", "actions": [{"label": "Escanear red", "type": "quick", "message": "escanear red"}], "confirm_required": False}
            lines = [f"• {n.get('ip')} — {n.get('name', 'N/D')} MAC {n.get('mac', 'N/D')}" for n in nodes[:12]]
            return {"reply": f"{len(nodes)} dispositivo(s):\n" + "\n".join(lines), "actions": [{"label": "Network", "type": "navigate", "url": "/network"}], "confirm_required": False}

        if intent == "mail_shield":
            from services.mail_shield_service import list_events, explain_for_kernel, get_integration_status
            integ = get_integration_status(None)
            events = list_events(limit=5)
            if "explic" in normalized and events:
                ex = explain_for_kernel(events[0]["id"])
                if ex:
                    return {
                        "reply": (
                            f"Mail Shield — {ex.get('what')}\n"
                            f"Asunto: {ex.get('mail_subject')}\n"
                            f"Remitente: {ex.get('sender')}\n"
                            f"Protección: {ex.get('protections')}\n"
                            f"Evidencia: {ex.get('evidence')}"
                        ),
                        "actions": [{"label": "Mail Shield", "type": "navigate", "url": "/mail-shield"}],
                        "confirm_required": False,
                    }
            if not integ.get("any_connected"):
                return {
                    "reply": integ.get("summary_message") or "Integración no configurada",
                    "actions": [{"label": "Mail Shield", "type": "navigate", "url": "/mail-shield"}],
                    "confirm_required": False,
                }
            if not events:
                return {
                    "reply": "Mail Shield conectado. No hay eventos registrados aún (solo correos analizados vía API oficial).",
                    "actions": [{"label": "Mail Shield", "type": "navigate", "url": "/mail-shield"}],
                    "confirm_required": False,
                }
            lines = [f"• #{e['id']} {e['event_type']} — {e.get('subject', '')[:50]}" for e in events]
            return {
                "reply": "Eventos Mail Shield:\n" + "\n".join(lines),
                "actions": [{"label": "Mail Shield", "type": "navigate", "url": "/mail-shield"}],
                "confirm_required": False,
            }

        if intent == "web_shield":
            from services.web_shield_service import list_events, explain_incident_for_kernel
            events = list_events(limit=5)
            if "explic" in normalized and events:
                ex = explain_incident_for_kernel(events[0]["id"])
                if ex:
                    reply = (
                        f"Web Shield — {ex.get('what')}\n"
                        f"Sitio: {ex.get('site') or 'N/D'}\n"
                        f"Riesgo: {ex.get('risk_score')} ({ex.get('severity')})\n"
                        f"Protección: {ex.get('protections') or 'registro'}\n"
                        f"Evidencia: {ex.get('evidence')}\n"
                        f"Recomendaciones: {'; '.join(ex.get('recommendations') or [])}"
                    )
                    return {
                        "reply": reply,
                        "actions": [{"label": "Web Shield", "type": "navigate", "url": "/web-shield"}],
                        "confirm_required": False,
                    }
            if not events:
                return {
                    "reply": "Web Shield activo. Aún no hay eventos registrados en este entorno (solo se muestran hechos reales).",
                    "actions": [{"label": "Abrir Web Shield", "type": "navigate", "url": "/web-shield"}],
                    "confirm_required": False,
                }
            lines = [f"• #{e['id']} {e['event_type']} — {e.get('domain') or e.get('url', '')[:60]}" for e in events]
            return {
                "reply": "Eventos Web Shield recientes:\n" + "\n".join(lines),
                "actions": [{"label": "Web Shield", "type": "navigate", "url": "/web-shield"}],
                "confirm_required": False,
            }

        if intent == "list_incidents":
            incs = ctx.get("incidents") or []
            if not incs:
                return {"reply": "No hay incidentes registrados en la base de datos.", "actions": [{"label": "Incidentes", "type": "navigate", "url": "/incidentes"}], "confirm_required": False}
            lines = [f"• {i.get('id')} — {i.get('tipo')} ({i.get('ip')})" for i in incs]
            return {"reply": "Incidentes recientes:\n" + "\n".join(lines), "actions": [{"label": "Abrir Incidentes", "type": "navigate", "url": "/incidentes"}], "confirm_required": False}

        if intent == "reports":
            reps = ctx.get("reports") or []
            if not reps:
                return {
                    "reply": "Sin reportes generados. Puedo sincronizar hallazgos para crear informes.",
                    "actions": [{"label": "Sincronizar", "type": "api", "endpoint": "/api/reports/sync", "method": "POST"}, {"label": "Reportes", "type": "navigate", "url": "/reportes"}],
                    "confirm_required": False,
                }
            lines = [f"• {r.get('id')} — {r.get('tipo')} [{r.get('severidad')}]" for r in reps[:8]]
            return {
                "reply": f"Historial ({len(reps)} informes):\n" + "\n".join(lines),
                "actions": [{"label": "Abrir Reportes", "type": "navigate", "url": "/reportes"}],
                "confirm_required": False,
            }

        if intent == "explain":
            vulns = ctx.get("vulnerabilities") or []
            incs = ctx.get("incidents") or []
            # Prefer explaining if user mentioned vulnerability/incident explicitly
            if "vulnerabil" in normalized or "vuln" in normalized:
                if vulns:
                    v = vulns[0]
                    return self._explain_vuln(v)
            if "incident" in normalized or "alerta" in normalized:
                if incs:
                    return self._explain_incident(incs[0])
            if vulns:
                return self._explain_vuln(vulns[0])
            if incs:
                return self._explain_incident(incs[0])
            return {"reply": "No hay vulnerabilidades ni incidentes en memoria para explicar. Ejecute un escaneo primero.", "actions": [{"label": "Escanear", "type": "quick", "message": "buscar vulnerabilidades"}], "confirm_required": False}

        if intent == "remediate":
            vulns = ctx.get("vulnerabilities") or []
            if not vulns:
                return {"reply": "Sin hallazgos para remediar.", "actions": [], "confirm_required": False}
            target = vulns[0].get("id")
            token = str(uuid.uuid4())[:8]
            self._get_session(session_id)["pending_confirm"] = {
                "token": token,
                "label": f"Remediar {target}",
                "action": "remediate",
                "payload": {"target_id": target, "target_type": "vulnerability"},
            }
            return {
                "reply": f"¿Confirma remediación del hallazgo {target}? Esta acción puede terminar procesos o registrar cambios.",
                "actions": [{"label": "Confirmar remediación", "type": "confirm", "token": token}],
                "confirm_required": True,
                "confirm_token": token,
            }

        if intent == "browse_data":
            items = []
            for d in ALLOWED_DATA_DIRS:
                if os.path.isdir(d):
                    for name in os.listdir(d)[:15]:
                        items.append(os.path.join(d, name))
            lines = [f"• {os.path.basename(p)}" for p in items[:12]]
            return {
                "reply": "Directorios de datos NOVUS:\n" + ("\n".join(lines) if lines else "Sin archivos listados."),
                "actions": [{"label": "Reportes", "type": "navigate", "url": "/reportes"}],
                "confirm_required": False,
            }

        # General — use context summary
        summary = (
            f"Kernel IA activo. Contexto de sesión ({ctx.get('refreshed_at', 'sin refrescar')}):\n"
            f"• Dispositivos: {len(ctx.get('network_nodes', []))}\n"
            f"• Vulnerabilidades: {len(ctx.get('vulnerabilities', []))}\n"
            f"• Incidentes: {len(ctx.get('incidents', []))}\n"
            f"• Reportes: {len(ctx.get('reports', []))}\n"
            "Escriba «ayuda» para ver comandos o use los botones rápidos."
        )
        return {
            "reply": summary,
            "actions": [
                {"label": "Escanear red", "type": "quick", "message": "escanear red"},
                {"label": "Vulnerabilidades", "type": "quick", "message": "vulnerabilidades"},
                {"label": "Ayuda", "type": "quick", "message": "ayuda"},
            ],
            "confirm_required": False,
        }

    def _execute_confirmed(self, pending):
        action = pending.get("action")
        payload = pending.get("payload") or {}

        if action == "clean_threats_batch":
            try:
                from services.remediation_engine import remediate_vulnerability
                threats = payload.get("threats") or []
                lines = ["═══ REMEDIACIÓN DE AMENAZAS — EJECUTANDO ═══", ""]
                results = []
                for i, t in enumerate(threats, 1):
                    tid = t.get("id")
                    lines.append(f"  [{i}/{len(threats)}] Remediando {tid} — {t.get('nombre', 'N/D')}...")
                    try:
                        r = remediate_vulnerability(tid)
                        results.append(r)
                        lines.append(f"    → {r.get('message', 'OK')} [{r.get('status', 'done')}]")
                    except Exception as exc:
                        lines.append(f"    → ERROR: {exc}")
                lines.extend(["", f"Completado: {len(results)}/{len(threats)} remediaciones ejecutadas."])
                return {
                    "reply": "\n".join(lines),
                    "actions": [{"label": "Ver reportes", "type": "navigate", "url": "/reportes"}],
                    "confirm_required": False,
                    "data": {"results": results},
                }
            except Exception as exc:
                return {"reply": f"Error en limpieza de amenazas: {exc}", "actions": [], "confirm_required": False}

        if action == "remediate":
            try:
                from services.remediation_engine import remediate_vulnerability, remediate_incident
                if payload.get("target_type") == "incident":
                    result = remediate_incident(payload["target_id"])
                else:
                    result = remediate_vulnerability(payload["target_id"])
                steps = result.get("steps", [])
                step_text = "\n".join(f"  → {s.get('label')} [{s.get('status')}]" for s in steps)
                return {
                    "reply": f"Remediación ejecutada.\n{result.get('message', '')}\n{step_text}",
                    "actions": [{"label": "Ver reporte", "type": "navigate", "url": f"/reportes?report={result.get('report_id', '')}"}] if result.get("report_id") else [],
                    "confirm_required": False,
                    "data": result,
                }
            except Exception as exc:
                return {"reply": f"Error en remediación: {exc}", "actions": [], "confirm_required": False}

        if action == "delete_file":
            path = self._safe_path(payload.get("path", ""))
            if not path:
                return {"reply": "Ruta no permitida. Solo directorios data/ de NOVUS.", "actions": [], "confirm_required": False}
            result = self.delete_file(path)
            return {"reply": result.get("message", str(result)), "actions": [], "confirm_required": False}

        if action == "terminate_process":
            result = self.execute_command("terminate_process", payload.get("pid"))
            return {"reply": result.get("message", str(result)), "actions": [], "confirm_required": False}

        return {"reply": "Acción no reconocida.", "actions": [], "confirm_required": False}

    def _explain_vuln(self, v):
        try:
            from services.vulnerability_analyst_service import answer_kernel_query
            vid = v.get("id") or ""
            reply = answer_kernel_query(
                f"Explica el hallazgo {vid}: causa, impacto, evidencia, confianza y remediación"
            )
            if reply:
                return {
                    "reply": reply,
                    "actions": [
                        {"label": "Ver vulnerabilidades", "type": "navigate", "url": "/vulnerabilidades"},
                        {"label": "Remediar", "type": "quick", "message": f"remediar hallazgo {vid}"},
                    ],
                    "confirm_required": False,
                }
        except Exception:
            pass
        return {
            "reply": (
                f"Explicación del hallazgo [{v.get('id')}]:\n"
                f"• Nombre: {v.get('nombre', 'N/D')}\n"
                f"• Descripción: {v.get('descripcion', 'Sin datos adicionales')}\n"
                f"• IP: {v.get('ip', 'N/D')}\n"
                f"• Fuente: {v.get('fuente', 'telemetría NOVUS')}\n"
                "Recomendación: revise el informe técnico en Reportes para pasos de remediación basados en evidencia."
            ),
            "actions": [
                {"label": "Ver vulnerabilidades", "type": "navigate", "url": "/vulnerabilidades"},
                {"label": "Remediar", "type": "quick", "message": "remediar hallazgo"},
            ],
            "confirm_required": False,
        }

    def _explain_incident(self, i):
        return {
            "reply": f"Incidente {i.get('id')}: {i.get('tipo')}\n{i.get('descripcion', 'Sin descripción adicional')}\nIP afectada: {i.get('ip', 'N/D')}",
            "actions": [{"label": "Mitigar", "type": "quick", "message": "mitigar incidente"}],
            "confirm_required": False,
        }


# Global AI Kernel instance
ai_kernel = AIKernel()


def start_ai_kernel():
    """Start AI Kernel service"""
    ai_kernel.start()
