"""
Operador autónomo de ciberseguridad NOVUS — Analista SOC/XDR Senior.

Flujo obligatorio por consulta:
  1. Comprender intención
  2. Identificar motores
  3. Ejecutarlos (force_refresh)
  4. Esperar resultados
  5. Cruzar evidencias
  6. Detectar inconsistencias
  7. Generar informe profesional

Prohibido: responder sin ejecutar motores / resumen Dashboard / caché / chatbot genérico.
"""
from __future__ import annotations

import re
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from services.ai_orchestrator import kernel_orchestrator
from services.soc_report_builder import build_soc_report
from utils.logger import logger

# ── Perfiles de acción ───────────────────────────────────────────────────────

ACTION_PROFILES = {
    "full": {
        "label": "Escaneo integral del equipo",
        "modules": [
            "Process Scanner", "Memory Scanner", "Startup Scanner", "Windows Services",
            "Drivers", "DLL Loader", "Registry Scanner", "Firewall Analyzer",
            "Open Ports", "Active Connections", "Installed Programs", "Scheduled Tasks",
            "Browser Extensions", "USB Devices", "Event Viewer", "Defender Status",
            "Certificate Store", "File Reputation", "Advanced Detector", "Security Engine",
        ],
        "sync": False,
    },
    "network": {
        "label": "Análisis de red (ARP + conexiones + firewall)",
        "modules": ["Network Scanner ARP", "Active Connections", "Open Ports", "Firewall Analyzer"],
        "sync": True,
    },
    "processes": {
        "label": "Inspección de procesos y aplicaciones",
        "modules": ["Process Scanner", "Memory Scanner", "DLL Loader", "Advanced Detector", "Defender Status"],
        "sync": True,
    },
    "memory": {
        "label": "Análisis de memoria",
        "modules": ["Memory Scanner", "Process Scanner"],
        "sync": False,
    },
    "malware": {
        "label": "Búsqueda de malware",
        "modules": ["Process Scanner", "File Reputation", "Advanced Detector", "Security Engine", "Defender Status"],
        "sync": False,
    },
    "rootkit": {
        "label": "Detección rootkit / procesos ocultos",
        "modules": ["Process Scanner", "Memory Scanner", "Drivers", "Windows Services", "Advanced Detector"],
        "sync": False,
    },
    "background": {
        "label": "Aplicaciones en segundo plano",
        "modules": ["Process Scanner", "Memory Scanner", "Startup Scanner"],
        "sync": True,
    },
    "connections": {
        "label": "Análisis de conexiones, DNS y conectividad",
        "modules": ["Active Connections", "Open Ports", "Firewall Analyzer", "Network Scanner ARP"],
        "sync": True,
    },
    "services": {
        "label": "Análisis de servicios y drivers",
        "modules": ["Windows Services", "Drivers", "Startup Scanner"],
        "sync": True,
    },
    "registry": {
        "label": "Análisis de registro y persistencia",
        "modules": ["Registry Scanner", "Startup Scanner", "Scheduled Tasks"],
        "sync": True,
    },
    "scheduled": {
        "label": "Tareas programadas",
        "modules": ["Scheduled Tasks", "Registry Scanner"],
        "sync": True,
    },
    "installed": {
        "label": "Programas instalados",
        "modules": ["Installed Programs", "Browser Extensions", "Startup Scanner"],
        "sync": True,
    },
    "vulnerabilities": {
        "label": "Análisis de vulnerabilidades",
        "modules": ["Vulnerability Scanner", "Advanced Detector", "Security Engine", "Firewall Analyzer"],
        "sync": True,
    },
}

ACTION_PATTERNS = [
    (r"deep\s*scan|escaneo\s+integral", "full", 25),
    (r"escanea\s+mi\s+(port[aá]til|laptop|computador|equipo|pc)", "full", 24),
    (r"analiza\s+(?:mi\s+)?(equipo|computador|port[aá]til|pc)(?!\s*\?)", "full", 23),
    (r"haz\s+un\s+an[aá]lisis\s+completo|an[aá]lisis\s+integral", "full", 22),
    (r"revisa\s+todo|analiza\s+todos\s+los\s+archivos", "full", 21),
    (r"seguridad.*(empresa|organizaci[oó]n)|empresa.*seguridad|postura.*seguridad", "full", 23),
    (r"analiza\s+mi\s+red|revisa\s+mi\s+red|escanea[r]?\s+(?:la\s+)?red\b|an[aá]lisis\s+real\s+de\s+red", "network", 22),
    (r"wifi|wi-?fi|conectado.*(wifi|red)|alguien.*(wifi|red)|intruso.*red", "network", 22),
    (r"revisa\s+mi\s+firewall|analiza\s+(?:mi\s+)?firewall|revisa\s+el\s+cortafuegos", "connections", 21),
    (r"genera\s+(?:un\s+)?(?:informe|reporte)|generar\s+reporte", "report", 22),
    (r"analiza\s+(?:este\s+)?correo|analiza\s+mis\s+correos|revisa\s+mis\s+correos|sincroniza\s+gmail|sync\s+gmail", "gmail", 21),
    (r"busca\s+procesos?\s+ocultos?|busca\s+rootkits?", "rootkit", 22),
    (r"busca\s+malware|buscar\s+virus|detecta\s+malware|tengo un virus|creo que.*virus|infectado", "malware", 21),
    (r"computador.*lento|pc.*lento|equipo.*lento|muy lento|va lento|est[aá] lento", "processes", 21),
    (r"no puedo entrar.*banco|banco.*no|acceso.*banco|p[aá]gina.*banco", "connections", 21),
    (r"analiza\s+memoria", "memory", 20),
    (r"busca\s+aplicaciones?\s+sospechosas?|sin\s+autorizaci[oó]n", "processes", 20),
    (r"segundo\s+plano|background", "background", 19),
    (r"revisa\s+procesos?|analiza[r]?\s+procesos?|busca[r]?\s+procesos?\s+sospechosos?", "processes", 19),
    (r"analiza[r]?\s+servicios?|revisa\s+servicios?", "services", 18),
    (r"busca[r]?\s+vulnerabil", "vulnerabilities", 20),
    (r"analiza\s+tareas?\s+programadas?", "scheduled", 18),
    (r"analiza\s+el\s+registro|revisa\s+el\s+registro|registro\s+(de\s+)?windows", "registry", 19),
    (r"analiza\s+conexiones?", "connections", 18),
    (r"analiza\s+programas?\s+instalados?", "installed", 17),
    (r"busca\s+anomal[ií]as", "full", 16),
    (r"\b(escanea|analiza|revisa|busca|detecta|verifica)\b.*\b(equipo|port[aá]til|pc|sistema)\b", "full", 15),
]

# Consultas analíticas que requieren ejecución de motores (no respuesta de chatbot)
ANALYSIS_QUERY_TO_ACTION = [
    (r"cu[aá]ntos?\s+dispositivos?.*red|dispositivos?.*(en|de)\s+mi\s+red", "network", 21),
    (r"wifi|wi-?fi|conectado.*wifi|alguien.*wifi|intruso.*wifi", "network", 22),
    (r"seguridad.*(empresa|organizaci[oó]n)|empresa.*seguridad", "full", 23),
    (r"tengo un virus|creo que.*virus|infectado|tengo malware", "malware", 22),
    (r"computador.*lento|pc.*lento|equipo.*lento|muy lento", "processes", 21),
    (r"no puedo entrar.*banco|banco.*no|acceso.*banco", "connections", 21),
    (r"dispositivos?\s+conectados?|qui[eé]n est[aá] conectado", "network", 20),
]

CLEAN_THREATS = re.compile(
    r"limpia.*amenazas|elimina.*amenazas|remover.*amenazas|cuarentena.*amenazas|"
    r"limpiar.*amenazas|eliminar.*amenazas",
    re.I,
)

ACTION_VERBS = re.compile(
    r"^\s*(?:¿)?\s*(escanea|escanear|analiza|analizar|revisa|revisar|busca|buscar|"
    r"detecta|detectar|verifica|verificar|genera|generar|sincroniza|ejecuta|haz|limpia|limpiar)\b",
    re.I,
)

QUERY_LEAD = re.compile(
    r"^\s*¿?\s*(c[oó]mo\s+est[aá]|cu[aá]ntas?|cu[aá]ntos?|cu[aá]l\s+es|qu[eé]\s+tal|"
    r"hay\s+|tiene\s+|dime\s+|mu[eé]strame\s+el\s+estado|cu[aá]l\s+es\s+el)",
    re.I,
)


def _normalize(text: str) -> str:
    t = str(text or "").lower().strip()
    t = t.replace("¿", "").replace("?", "").replace("¡", "").replace("!", "")
    return re.sub(r"\s+", " ", t)


def _build_action(profile: str, message: str, score: int = 15) -> Dict[str, Any]:
    if profile in ("report", "gmail"):
        meta = {
            "label": "Generación de informe" if profile == "report" else "Análisis Gmail OAuth",
            "modules": ["Report Engine"] if profile == "report" else ["Gmail Analyzer API"],
            "sync": True,
        }
        return {
            "type": "inline",
            "action_id": profile,
            "profile": None,
            "label": meta["label"],
            "modules": meta["modules"],
            "sync": meta.get("sync", False),
            "score": score,
            "query": message,
        }
    meta = ACTION_PROFILES.get(profile, ACTION_PROFILES["full"])
    return {
        "type": "workflow",
        "action_id": profile,
        "profile": profile,
        "label": meta["label"],
        "modules": meta["modules"],
        "sync": meta.get("sync", False),
        "query": message,
        "score": score,
    }


def resolve_action(message: str) -> Optional[Dict[str, Any]]:
    m = _normalize(message)
    if len(m) < 4:
        return None
    best_profile, best_score = None, 0
    for pattern, profile, weight in ACTION_PATTERNS:
        if re.search(pattern, m, re.I) and weight > best_score:
            best_score = weight
            best_profile = profile
    if not best_profile:
        return None
    return _build_action(best_profile, message, best_score)


def classify_request(message: str) -> Dict[str, Any]:
    """Determina CONSULTA vs ACCIÓN. Consultas analíticas → acción con motores."""
    raw = str(message or "").strip()
    m = _normalize(message)
    action = resolve_action(message)

    # Limpieza de amenazas → flujo especial (confirmación)
    if CLEAN_THREATS.search(m):
        return {"request_type": "clean_threats", "reason": "remediacion_amenazas"}

    # Consultas que requieren motores reales → ACCIÓN
    for pattern, profile, weight in ANALYSIS_QUERY_TO_ACTION:
        if re.search(pattern, m, re.I):
            return {
                "request_type": "action",
                "action": _build_action(profile, message, weight),
                "reason": "consulta_analitica_soc",
            }

    is_question = (
        "?" in raw
        or bool(QUERY_LEAD.search(m))
        or bool(re.match(r"^(cu[aá]nt|qu[eé]|c[oó]mo|cu[aá]l|hay)\b", m))
    )
    starts_with_action = bool(ACTION_VERBS.search(m))

    if is_question and not starts_with_action:
        return {"request_type": "query", "reason": "interrogativa_analisis_soc"}

    if action and (starts_with_action or action["score"] >= 17):
        return {"request_type": "action", "action": action, "reason": "verbo_accion_o_patron_soc"}

    if starts_with_action:
        prof = (action or {}).get("profile") or "processes"
        if prof == "full" and not re.search(r"\b(port[aá]til|equipo|pc|integral|completo)\b", m, re.I):
            prof = "processes"
        return {
            "request_type": "action",
            "action": _build_action(prof, message, 14),
            "reason": "verbo_accion_generico",
        }

    if action:
        return {"request_type": "action", "action": action, "reason": "patron_accion"}

    return {"request_type": "query", "reason": "default_consulta_soc"}


class KernelOperator:
    """Operador autónomo — Analista SOC/XDR Senior."""

    SYNC_TIMEOUT_SEC = 180

    def process(
        self,
        session_id: str,
        message: str,
        user_id: Optional[int] = None,
        user_email: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Delega al agente autónomo — cerebro operativo de NOVUS."""
        from services.kernel_agent import kernel_agent
        from services.ai_kernel import ai_kernel

        context = {}
        history = []
        try:
            context = ai_kernel.get_context(session_id) or {}
            history = ai_kernel.get_history(session_id, limit=12)
        except Exception:
            pass
        if user_email:
            from services.sector_profile_service import get_kernel_context_for_user
            context.update(get_kernel_context_for_user(user_email))

        return kernel_agent.process(
            session_id=session_id,
            message=message,
            user_id=user_id,
            user_email=user_email,
            context=context,
            history=history,
        )

    def _handle_query(self, session_id: str, message: str, user_id: Optional[int]) -> Dict[str, Any]:
        """
        CONSULTA SOC: ejecutar motores → fusionar evidencia → informe profesional.
        Nunca respuesta corta tipo chatbot.
        """
        started = datetime.now()
        timeline: List[str] = []
        timeline.append("Clasificación de intención del operador")

        intent = kernel_orchestrator.analyze_intent(message)
        pid = intent.get("primary_intent")

        # Intenciones de escaneo integral → workflow deep scan
        if pid in ("deep_scan", "full_computer_analysis", "enterprise_security"):
            action = resolve_action(message) or _build_action("full", message, 20)
            timeline.append(f"Intención {pid} → delegación a Deep Scan workflow")
            result = self._handle_action(session_id, message, action, user_id)
            result["request_type"] = "query"
            return result

        # Ejecutar acciones orquestadas (scan_network, scan_vulnerabilities, etc.)
        actions_executed = []
        for action_name in intent.get("actions") or []:
            timeline.append(f"Ejecutando acción: {action_name}")
            ar = kernel_orchestrator.execute_action(action_name, session_id, user_id=user_id)
            actions_executed.append(ar)

        # Ejecutar TODAS las capacidades con force_refresh
        caps = list(intent.get("capabilities") or [])
        if not caps:
            caps = ["security.threats", "security.vulnerabilities", "system.metrics"]
        timeline.append(f"Ejecutando {len(caps)} motor(es) con force_refresh=True")

        collected = kernel_orchestrator.collect_capabilities(
            caps, user_id=user_id, force_refresh=True
        )
        engines = collected.get("capabilities_executed") or []
        timeline.append(f"Motores completados: {len(engines)}")

        # Red/WiFi: forzar escaneo ARP si es intención de red
        if pid in ("network_status", "wifi_intrusion") and "network.scanner" in caps:
            timeline.append("Escaneo ARP forzado para inventario de dispositivos")
            ar = kernel_orchestrator.execute_action("scan_network", session_id, user_id=user_id)
            actions_executed.append(ar)
            # Re-colectar red con datos frescos
            net_data = kernel_orchestrator.collect_capabilities(
                ["network.scanner", "connections.active", "traffic.stats"],
                user_id=user_id,
                force_refresh=True,
            )
            for k, v in net_data.items():
                if k not in ("capabilities_executed", "capabilities_failed", "modules_queried", "gaps", "collected_at"):
                    collected[k] = v
            collected["capabilities_executed"] = list(dict.fromkeys(
                (collected.get("capabilities_executed") or []) + (net_data.get("capabilities_executed") or [])
            ))

        timeline.append("Fusión de evidencias y detección de inconsistencias")

        report = build_soc_report(
            intent=intent,
            data=collected,
            message=message,
            actions_executed=actions_executed,
            started_at=started,
            timeline=timeline,
        )

        return {
            "request_type": "query",
            "reply": report["reply"],
            "actions": report.get("actions", []),
            "confirm_required": False,
            "data_fresh": True,
            "engines_executed": engines,
            "risk_level": report.get("risk_level"),
            "soc_report": True,
            "intent": {
                "primary": pid,
                "label": intent.get("primary_label"),
                "capabilities": caps,
                "modules": collected.get("modules_queried"),
            },
            "data_snapshot": report.get("data_snapshot"),
        }

    def _handle_action(
        self,
        session_id: str,
        message: str,
        action: Dict[str, Any],
        user_id: Optional[int],
    ) -> Dict[str, Any]:
        """ACCIÓN: ejecutar workflow/motores → informe completo."""
        if action["type"] == "inline":
            return self._execute_inline(action["action_id"], message, user_id)

        profile = action.get("profile") or "full"
        modules = action.get("modules") or []

        from services.deep_scan_engine import deep_scan_engine

        scan_id = deep_scan_engine.start_scan(
            session_id,
            user_id,
            profile=profile,
            query=message,
            modules_loaded=modules,
        )

        if action.get("sync"):
            report = self._wait_for_report(scan_id, self.SYNC_TIMEOUT_SEC)
            if report:
                return {
                    "request_type": "action",
                    "action_id": action.get("action_id"),
                    "profile": profile,
                    "modules_executed": modules,
                    "engines_executed": report.get("engines_used", []),
                    "reply": report.get("text_report", "Informe generado."),
                    "scan_id": scan_id,
                    "task_completed": True,
                    "soc_workflow": True,
                    "soc_report": True,
                    "confirm_required": False,
                    "risk_level": report.get("risk_level"),
                    "intent": {
                        "primary": "action",
                        "label": action.get("label"),
                        "profile": profile,
                    },
                }

        return {
            "request_type": "action",
            "action_id": action.get("action_id"),
            "profile": profile,
            "modules_loaded": modules,
            "reply": (
                f"═══ TAREA SOC INICIADA ═══\n\n"
                f"Objetivo: {action.get('label')}\n\n"
                f"Motores cargados ({len(modules)}):\n"
                + "\n".join(f"  • {m}" for m in modules[:8])
                + (f"\n  ... y {len(modules) - 8} más" if len(modules) > 8 else "")
                + "\n\nEjecutando análisis real — el informe se entregará al finalizar.\n"
                "(Sin caché. Sin resumen de Dashboard.)"
            ),
            "scan_id": scan_id,
            "soc_workflow": True,
            "deep_scan": True,
            "defer_full_reply": True,
            "task_completed": False,
            "confirm_required": False,
            "actions": [
                {"label": "Ver progreso", "type": "deep_scan", "scan_id": scan_id},
            ],
            "intent": {
                "primary": "action",
                "label": action.get("label"),
                "profile": profile,
                "modules": modules,
            },
        }

    def _handle_clean_threats(
        self,
        session_id: str,
        message: str,
        user_id: Optional[int],
    ) -> Dict[str, Any]:
        """Buscar amenazas → mostrar → confirmar → remediar."""
        from services.ai_kernel import ai_kernel

        started = datetime.now()
        timeline = ["Escaneo de amenazas con force_refresh"]

        collected = kernel_orchestrator.collect_capabilities(
            ["security.threats", "security.vulnerabilities", "advanced_detector.malware"],
            user_id=user_id,
            force_refresh=True,
        )
        sec = collected.get("security") or {}
        vulns = collected.get("vulnerabilities") or []
        sus = sec.get("suspicious_processes") or []

        threats = []
        for sp in sus:
            threats.append({
                "id": f"PROC-{sp.get('pid')}",
                "tipo": "Proceso sospechoso",
                "nombre": sp.get("name"),
                "descripcion": sp.get("description") or sp.get("command_line", ""),
            })
        for v in vulns:
            if "PROC" in str(v.get("id", "")) or "PORT" in str(v.get("id", "")):
                threats.append({
                    "id": v.get("id"),
                    "tipo": v.get("tipo", "Hallazgo"),
                    "nombre": v.get("nombre"),
                    "descripcion": v.get("descripcion", ""),
                })

        lines = [
            "═══ LIMPIEZA DE AMENAZAS — ANÁLISIS PREVIO ═══",
            f"Motores ejecutados: security.threats, security.vulnerabilities, advanced_detector.malware",
            f"Amenazas/hallazgos detectados: {len(threats)}",
            "",
        ]

        if not threats:
            lines.extend([
                "RESULTADO: No se detectaron amenazas remediables en telemetría actual.",
                "Los motores XDR y vulnerabilidades no reportaron indicadores activos.",
            ])
            return {
                "request_type": "clean_threats",
                "reply": "\n".join(lines),
                "task_completed": True,
                "engines_executed": collected.get("capabilities_executed", []),
                "confirm_required": False,
            }

        for t in threats[:10]:
            lines.append(f"  • [{t['id']}] {t['nombre']} — {t['descripcion'][:80]}")

        lines.extend([
            "",
            "⚠ ACCIÓN DESTRUCTIVA: La remediación puede terminar procesos o modificar configuración.",
            "Confirme para ejecutar la limpieza.",
        ])

        token = str(uuid.uuid4())[:8]
        session = ai_kernel._get_session(session_id)
        session["pending_confirm"] = {
            "token": token,
            "label": f"Limpiar {len(threats)} amenaza(s)",
            "action": "clean_threats_batch",
            "payload": {"threats": threats[:10]},
        }

        return {
            "request_type": "clean_threats",
            "reply": "\n".join(lines),
            "confirm_required": True,
            "confirm_token": token,
            "actions": [{"label": "Confirmar limpieza", "type": "confirm", "token": token}],
            "engines_executed": collected.get("capabilities_executed", []),
            "threat_count": len(threats),
            "task_completed": False,
        }

    def _wait_for_report(self, scan_id: str, timeout: int) -> Optional[Dict]:
        from services.deep_scan_engine import deep_scan_engine

        deadline = time.time() + timeout
        while time.time() < deadline:
            st = deep_scan_engine.get_status(scan_id)
            if not st:
                break
            state = st.get("status")
            if state == "completed":
                return deep_scan_engine.get_report(scan_id)
            if state == "error":
                logger.error(f"Workflow {scan_id} error: {st.get('error')}")
                break
            time.sleep(1.5)
        return None

    def _execute_inline(
        self,
        action_id: str,
        message: str,
        user_id: Optional[int],
    ) -> Dict[str, Any]:
        if action_id == "gmail":
            return self._action_gmail(user_id, message)
        if action_id == "report":
            return self._action_report(user_id, message)
        return {
            "request_type": "action",
            "reply": "Acción no implementada.",
            "task_completed": False,
        }

    def _action_gmail(self, user_id: Optional[int], message: str) -> Dict[str, Any]:
        started = datetime.now()
        if not user_id:
            return {
                "request_type": "action",
                "reply": (
                    "═══ ANÁLISIS DE CORREO ═══\n\n"
                    "Fuente real no disponible: requiere sesión autenticada para Gmail OAuth.\n"
                    "Configure GOOGLE_CLIENT_ID/SECRET y conecte Gmail en Configuración.\n\n"
                    "NOTA: Validación SPF/DKIM/DMARC completa — requiere desarrollo adicional.\n"
                    "NOTA: VirusTotal — requiere configuración de clave API."
                ),
                "task_completed": False,
                "engines_executed": ["gmail_oauth_service (requiere sesión)"],
                "soc_report": True,
            }

        from services.gmail_analyzer_service import sync_new_messages, get_stats
        from services.gmail_oauth_service import get_connection_status

        conn = get_connection_status(user_id)
        if not conn.get("connected"):
            return {
                "request_type": "action",
                "reply": (
                    "═══ ANÁLISIS DE CORREO ═══\n\n"
                    "Gmail OAuth no configurado o no conectado.\n"
                    "Configure GOOGLE_CLIENT_ID/SECRET y conecte Gmail en Configuración.\n\n"
                    "Motores disponibles tras conexión: Gmail API, análisis de enlaces/adjuntos, "
                    "reputación, ingeniería social.\n"
                    "NOTA: SPF/DKIM/DMARC completo y VirusTotal requieren desarrollo/config adicional."
                ),
                "task_completed": False,
                "engines_executed": ["gmail_oauth_service"],
            }

        sync = sync_new_messages(user_id)
        stats = get_stats(user_id)
        collected = kernel_orchestrator.collect_capabilities(
            ["gmail.analyzer", "security.threats"], user_id=user_id, force_refresh=True
        )
        elapsed = (datetime.now() - started).total_seconds()

        lines = [
            "╔══════════════════════════════════════════════════════════════╗",
            "║           INFORME SOC — ANÁLISIS DE CORREO                     ║",
            "╚══════════════════════════════════════════════════════════════╝",
            "",
            "═══ RESUMEN EJECUTIVO ═══",
            f"Sincronización Gmail completada en {elapsed:.1f}s.",
            f"Mensajes analizados en esta ejecución: {sync.get('analyzed', 0)}",
            f"Total histórico: {stats.get('total_analyzed', 0)} | "
            f"Seguros: {stats.get('safe', 0)} | Sospechosos: {stats.get('suspicious', 0)} | "
            f"Maliciosos: {stats.get('malicious', 0)}",
            "",
            "═══ MOTORES EJECUTADOS ═══",
            "  • gmail_analyzer_service.sync_new_messages",
            "  • gmail_oauth_service",
            "  • gmail.analyzer (capability registry)",
            "",
            "═══ CAPACIDADES PENDIENTES ═══",
            "  ! Validación SPF/DKIM/DMARC completa — requiere desarrollo adicional",
            "  ! VirusTotal — requiere configuración de clave API",
            "",
            "═══ RECOMENDACIONES ═══",
            "  → Revise correos sospechosos/maliciosos en pestaña Seguridad del correo",
            "  → No haga clic en enlaces de remitentes no verificados",
        ]
        if sync.get("message"):
            lines.append(f"\nDetalle sync: {sync['message']}")

        return {
            "request_type": "action",
            "action_id": "gmail",
            "reply": "\n".join(lines),
            "task_completed": sync.get("status") == "success",
            "engines_executed": [
                "gmail_analyzer_service.sync_new_messages",
                "gmail_oauth_service",
                "gmail.analyzer",
            ],
            "soc_report": True,
            "actions": [{"label": "Historial correo", "type": "navigate", "url": "/ai"}],
        }

    def _action_report(self, user_id: Optional[int], message: str) -> Dict[str, Any]:
        from services.novus_security_integration import novus_security
        from services.security_report_service import auto_generate_for_findings, list_reports

        novus_security.detect_threats_realtime(force=True)
        cache = novus_security._threat_cache or {}
        findings = []
        idx = 1
        for sp in cache.get("suspicious_processes") or []:
            findings.append({
                "id": f"PROC-{sp.get('pid', idx)}",
                "tipo": "Proceso sospechoso",
                "nombre": sp.get("name"),
                "descripcion": sp.get("description") or sp.get("command_line", ""),
                "ip": "local",
            })
            idx += 1
        for port in cache.get("open_ports") or []:
            findings.append({
                "id": f"PORT-{port.get('port', idx)}",
                "tipo": "Puerto abierto",
                "nombre": f"Puerto {port.get('port')}",
                "descripcion": port.get("description", ""),
                "ip": port.get("target_ip", "local"),
            })
            idx += 1

        created = auto_generate_for_findings(findings)
        recent = list_reports(limit=5)
        lines = [
            "═══ INFORME TAREA: GENERACIÓN DE REPORTES ═══",
            "Motores: novus_security_integration.detect_threats_realtime(force=True), security_report_service",
            f"Hallazgos en vivo detectados: {len(findings)}",
            f"Reportes nuevos generados: {len(created)}",
            f"Reportes en historial: {len(recent)}",
        ]
        for r in created[:3]:
            lines.append(f"  • {r.get('id', '?')}: {r.get('titulo', r.get('nombre', 'Reporte'))}")
        if not created and not findings:
            lines.append("Sin hallazgos nuevos — no se inventaron reportes.")
        return {
            "request_type": "action",
            "action_id": "report",
            "reply": "\n".join(lines),
            "task_completed": True,
            "engines_executed": [
                "novus_security_integration.detect_threats_realtime",
                "security_report_service.auto_generate_for_findings",
            ],
            "soc_report": True,
        }


kernel_operator = KernelOperator()
