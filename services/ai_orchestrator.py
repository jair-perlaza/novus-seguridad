"""
NOVUS AI Kernel — Agente de Orquestación SOC.

Arquitectura intent-first:
1. Clasificar intención
2. Resolver capacidades (motores reales)
3. Ejecutar TODAS las capacidades relacionadas
4. Fusionar → respuesta única completa
"""
import re
from datetime import datetime

from services.ai_capability_registry import capability_registry
from utils.logger import logger

# Intenciones SOC con capacidades obligatorias
SOC_INTENTS = {
    "vulnerabilities": {
        "label": "Consulta de vulnerabilidades",
        "priority": 100,
        "patterns": [
            (r"vulnerabil", 12),
            (r"\bvulns?\b", 12),
            (r"\bcves?\b", 12),
            (r"pentest", 10),
            (r"hallazgo", 8),
            (r"exploit", 8),
            (r"parche", 6),
            (r"cu[aá]ntas?\s+vulnerabil", 15),
            (r"cu[aá]ntos?\s+hallazgos?", 12),
            (r"tiene.*vulnerabil", 14),
            (r"mi equipo.*vulnerabil|vulnerabil.*mi equipo", 15),
        ],
        "capabilities": [
            "security.vulnerabilities",
            "security.threats",
            "security.system_health",
            "advanced_detector.ports",
            "advanced_detector.processes",
            "reports.manager",
        ],
        "forbidden_unless_network": True,
    },
    "network_status": {
        "label": "Estado de la red",
        "priority": 90,
        "patterns": [
            (r"\b(red|network|wifi|wi-?fi|wlan)\b", 10),
            (r"c[oó]mo est[aá].*red|estado.*red|red.*est[aá]", 12),
            (r"tr[aá]fico.*red|red.*tr[aá]fico", 12),
            (r"\b(gateway|router|arp|segmento|subnet)\b", 8),
            (r"dispositivos?\s+conectados?", 10),
            (r"qui[eé]n est[aá] conectado", 10),
            (r"cu[aá]ntos?\s+dispositivos?", 10),
        ],
        "capabilities": [
            "network.scanner",
            "network.events",
            "dashboard.metrics",
            "traffic.stats",
            "endpoints.live",
            "firewall.ports",
            "connections.active",
            "security.threats",
        ],
    },
    "traffic": {
        "label": "Tráfico de red",
        "priority": 85,
        "patterns": [
            (r"tr[aá]fico", 10),
            (r"ancho de banda", 8),
            (r"bytes|mb/s|consumo de red", 8),
        ],
        "capabilities": [
            "traffic.stats",
            "network.scanner",
            "dashboard.metrics",
            "connections.active",
            "process.scanner",
            "security.threats",
        ],
    },
    "processes": {
        "label": "Análisis de procesos",
        "priority": 88,
        "patterns": [
            (r"proceso|procesos|process", 10),
            (r"pid|tarea", 6),
            (r"qui[eé]n consume|m[aá]s cpu|m[aá]s memoria", 10),
            (r"procesos?\s+sospechosos?", 12),
        ],
        "capabilities": [
            "process.scanner",
            "advanced_detector.processes",
            "advanced_detector.malware",
            "security.threats",
            "system.metrics",
            "endpoints.live",
        ],
    },
    "malware": {
        "label": "Detección malware/ransomware",
        "priority": 92,
        "patterns": [
            (r"malware|ransomware|rootkit|virus|cryptolocker|botnet", 12),
            (r"busca.*malware|buscar.*virus|detecta.*malware", 14),
        ],
        "capabilities": [
            "advanced_detector.malware",
            "advanced_detector.processes",
            "security.threats",
            "security.vulnerabilities",
            "process.scanner",
        ],
    },
    "firewall": {
        "label": "Firewall y puertos",
        "priority": 87,
        "patterns": [
            (r"firewall|cortafuegos", 12),
            (r"puertos?\s+abiertos?", 10),
            (r"puertos?\s+expuestos?", 12),
            (r"revisa.*firewall|analiza.*firewall", 14),
            (r"analiza.*puertos?", 12),
        ],
        "capabilities": [
            "firewall.ports",
            "advanced_detector.ports",
            "connections.active",
            "security.threats",
            "network.scanner",
        ],
    },
    "connections": {
        "label": "Conexiones activas",
        "priority": 86,
        "patterns": [
            (r"conexi[oó]n|conexiones|socket", 10),
            (r"conectado a|saliente|entrante|established", 8),
            (r"analiza.*conexiones?", 12),
        ],
        "capabilities": [
            "connections.active",
            "traffic.stats",
            "network.scanner",
            "security.threats",
            "firewall.ports",
        ],
    },
    "gmail": {
        "label": "Seguridad del correo",
        "priority": 91,
        "patterns": [
            (r"correo|correos|email|gmail|buz[oó]n", 10),
            (r"phishing|spam", 8),
            (r"analiza.*correo|revisa.*correo|mis correos", 14),
        ],
        "capabilities": [
            "gmail.analyzer",
            "security.threats",
        ],
    },
    "incidents": {
        "label": "Incidentes de seguridad",
        "priority": 89,
        "patterns": [
            (r"incidente|incidentes", 12),
            (r"alertas?\s+cr[ií]ticas?", 10),
            (r"hay algo raro|algo raro|anomal[ií]a", 8),
        ],
        "capabilities": [
            "incidents.manager",
            "security.threats",
            "security.vulnerabilities",
            "process.scanner",
        ],
    },
    "reports": {
        "label": "Reportes e informes",
        "priority": 84,
        "patterns": [
            (r"reporte|reportes|informe|informes", 10),
            (r"exportar.*pdf|descargar.*pdf|generar.*informe", 12),
        ],
        "capabilities": [
            "reports.manager",
            "security.vulnerabilities",
            "incidents.manager",
        ],
    },
    "system_health": {
        "label": "Salud del sistema",
        "priority": 83,
        "patterns": [
            (r"\b(cpu|ram|memoria|disco|disk)\b", 10),
            (r"rev[ií]same el computador|mi computador|mi pc", 10),
            (r"salud del sistema|system health", 10),
        ],
        "capabilities": [
            "system.metrics",
            "security.system_health",
            "process.scanner",
            "dashboard.metrics",
        ],
    },
    "general_status": {
        "label": "Estado general / SOC",
        "priority": 70,
        "patterns": [
            (r"c[oó]mo estamos|qu[eé] tal|estado general", 10),
            (r"panorama|resumen|diagn[oó]stico", 8),
        ],
        "capabilities": [
            "dashboard.metrics",
            "system.metrics",
            "network.scanner",
            "security.threats",
            "security.vulnerabilities",
            "incidents.manager",
            "traffic.stats",
        ],
    },
    "full_computer_analysis": {
        "label": "Análisis completo del equipo",
        "priority": 95,
        "patterns": [
            (r"analiza completamente|an[aá]lisis completo|escanea todo|analiza todo", 15),
            (r"revisa todo|eval[uú]a todo|auditor[ií]a completa", 14),
            (r"analiza.*computador|escanea.*sistema|analiza.*equipo", 12),
        ],
        "capabilities": [
            "system.metrics",
            "security.system_health",
            "process.scanner",
            "advanced_detector.processes",
            "advanced_detector.malware",
            "advanced_detector.ports",
            "firewall.ports",
            "network.scanner",
            "traffic.stats",
            "connections.active",
            "security.vulnerabilities",
            "security.threats",
            "gmail.analyzer",
            "incidents.manager",
            "reports.manager",
            "dashboard.metrics",
        ],
    },
    "deep_scan": {
        "label": "Deep Scan — escaneo integral del equipo",
        "priority": 99,
        "patterns": [
            (r"deep\s*scan", 20),
            (r"escanea\s+mi\s+(port[aá]til|laptop|computador|equipo|pc)", 18),
            (r"analiza\s+mi\s+(computador|equipo|port[aá]til|laptop|pc)", 18),
            (r"haz\s+un\s+an[aá]lisis\s+completo", 17),
            (r"busca\s+anomal[ií]as", 16),
            (r"analiza\s+todos\s+los\s+archivos", 16),
            (r"revisa\s+todo", 15),
            (r"escaneo\s+integral|an[aá]lisis\s+integral", 15),
            (r"busca\s+(malware|virus|amenazas|rootkit)", 14),
        ],
        "capabilities": ["deep_scan.engine"],
        "force_fresh": True,
    },
    "wifi_intrusion": {
        "label": "Intrusión WiFi / dispositivos no autorizados",
        "priority": 93,
        "patterns": [
            (r"wifi|wi-?fi", 10),
            (r"conectado.*wifi|wifi.*conectado", 12),
            (r"alguien.*(wifi|red)|intruso.*(wifi|red)", 14),
            (r"revisa si alguien|qui[eé]n est[aá] en mi wifi", 15),
        ],
        "capabilities": [
            "network.scanner",
            "network.events",
            "connections.active",
            "traffic.stats",
            "firewall.ports",
            "security.threats",
        ],
    },
    "performance_slow": {
        "label": "Diagnóstico de rendimiento / equipo lento",
        "priority": 88,
        "patterns": [
            (r"lento|lentitud|va lento|est[aá] lento", 12),
            (r"computador.*lento|pc.*lento|equipo.*lento", 14),
            (r"consume.*recursos|alta cpu|alta memoria", 10),
        ],
        "capabilities": [
            "process.scanner",
            "system.metrics",
            "advanced_detector.processes",
            "security.system_health",
            "endpoints.live",
        ],
    },
    "banking_access": {
        "label": "Conectividad bancaria / DNS / certificados",
        "priority": 91,
        "patterns": [
            (r"banco|banking|banca en l[ií]nea", 10),
            (r"no puedo entrar.*banco|banco.*no.*entra|acceso.*banco", 14),
            (r"certificado|ssl|tls", 8),
        ],
        "capabilities": [
            "connections.active",
            "network.scanner",
            "traffic.stats",
            "firewall.ports",
            "security.threats",
        ],
    },
    "enterprise_security": {
        "label": "Postura de seguridad empresarial",
        "priority": 96,
        "patterns": [
            (r"seguridad.*(empresa|organizaci[oó]n)", 14),
            (r"empresa.*seguridad|postura.*seguridad", 14),
            (r"informe ejecutivo|auditor[ií]a.*empresa", 12),
        ],
        "capabilities": [
            "deep_scan.engine",
            "security.vulnerabilities",
            "security.threats",
            "network.scanner",
            "security.sector_shield",
            "incidents.manager",
            "reports.manager",
            "gmail.analyzer",
        ],
    },
    "threat_cleanup": {
        "label": "Limpieza de amenazas",
        "priority": 94,
        "patterns": [
            (r"limpia.*amenazas|elimina.*amenazas|limpiar.*amenazas", 15),
            (r"cuarentena|remover.*amenazas", 12),
        ],
        "capabilities": [
            "security.threats",
            "security.vulnerabilities",
            "advanced_detector.malware",
            "remediation.engine",
        ],
    },
    "email_analysis": {
        "label": "Análisis de correo específico",
        "priority": 92,
        "patterns": [
            (r"analiza\s+(?:este\s+)?correo|analiza\s+el\s+correo", 14),
            (r"revisa\s+(?:este\s+)?correo|examina\s+correo", 12),
            (r"phishing|spear.?phishing", 10),
        ],
        "capabilities": [
            "gmail.analyzer",
            "security.threats",
        ],
    },
    "daily_summary": {
        "label": "Resumen de actividad del día",
        "priority": 88,
        "patterns": [
            (r"qu[eé]\s+pas[oó]\s+hoy", 14),
            (r"resumen\s+de\s+hoy|eventos\s+de\s+hoy", 12),
            (r"actividad\s+de\s+hoy|qu[eé]\s+ocurri[oó]\s+hoy", 12),
            (r"informe\s+del\s+d[ií]a", 10),
        ],
        "capabilities": [
            "siem.logs",
            "incidents.manager",
            "network.events",
            "security.threats",
            "reports.manager",
        ],
    },
    "greeting": {
        "label": "Saludo",
        "priority": 50,
        "patterns": [
            (r"^hola$", 10),
            (r"^buenos\s+d[ií]as", 10),
            (r"^buenas\s+tardes", 10),
            (r"^saludos$", 8),
        ],
        "capabilities": [],
    },
}

NETWORK_KEYWORDS = re.compile(
    r"\b(red|network|wifi|wi-?fi|gateway|router|arp|dispositivos?\s+conectados?|"
    r"nodo|nodos|segmento|subnet|tr[aá]fico.*red|red.*tr[aá]fico)\b", re.I
)

ACTION_SIGNALS = [
    (r"\b(escanear|escanea|scan).*(red|network|arp)\b", "scan_network"),
    (r"\b(escanear|escanea|scan|buscar|analizar|analiza).*(vulnerabil|vuln)\b", "scan_vulnerabilities"),
    (r"\b(analizar|analiza|revisar|revisa|sync|sincronizar).*(correo|correos|gmail)\b", "sync_gmail"),
    (r"\b(generar|sincronizar).*(reporte|informe)\b", "sync_reports"),
    (r"\b(actualizar|refrescar|recargar)\b", "refresh_all"),
    (r"\b(remediar|mitigar|parchear)\b", "remediate"),
]

MODULE_ROUTES = {
    "dashboard": "/dashboard",
    "network": "/network",
    "xdr": "/amenazas",
    "vulnerabilidades": "/vulnerabilidades",
    "incidentes": "/incidentes",
    "reportes": "/reportes",
    "configuracion": "/configuracion",
    "endpoints": "/endpoints",
    "siem": "/siem",
}


class KernelOrchestrator:
    """Agente de orquestación — Director del SOC."""

    def normalize(self, text):
        t = str(text or "").lower().strip()
        t = t.replace("¿", "").replace("?", "").replace("¡", "").replace("!", "")
        return re.sub(r"\s+", " ", t)

    def classify_intent(self, message):
        """Clasifica intención primaria y secundarias por puntuación acumulada."""
        m = self.normalize(message)
        scores = {}

        for intent_id, cfg in SOC_INTENTS.items():
            total = 0
            for pattern, weight in cfg["patterns"]:
                if re.search(pattern, m, re.I):
                    total += weight
            if total > 0:
                scores[intent_id] = total * (cfg["priority"] / 100.0)

        if not scores:
            scores["general_status"] = 5.0

        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        primary_id, primary_score = ranked[0]
        secondary = [i for i, s in ranked[1:] if s >= primary_score * 0.45]

        # Anti-conflicto: vulnerabilidades NO activa red salvo keywords de red explícitas
        VULN_KW = re.search(r"\b(vulnerabil|\bvulns?\b|\bcves?\b|hallazgo|pentest)\b", m, re.I)
        if VULN_KW and scores.get("vulnerabilities", 0) > 0:
            primary_id = "vulnerabilities"
            primary_score = scores["vulnerabilities"]
            secondary = [i for i, s in ranked if i != "vulnerabilities" and s >= primary_score * 0.45]

        if primary_id == "vulnerabilities" or "vulnerabilities" in secondary:
            if not NETWORK_KEYWORDS.search(m):
                scores.pop("network_status", None)
                scores.pop("traffic", None)
                secondary = [s for s in secondary if s not in ("network_status", "traffic")]

        active_intents = [primary_id] + [s for s in secondary if s != primary_id]

        capabilities = []
        for iid in active_intents:
            caps = SOC_INTENTS.get(iid, {}).get("capabilities", [])
            for c in caps:
                if c not in capabilities:
                    capabilities.append(c)

        actions = []
        for pattern, action in ACTION_SIGNALS:
            if re.search(pattern, m, re.I):
                actions.append(action)

        modules = list({
            capability_registry.CAPABILITY_CATALOG[c]["module"]
            for c in capabilities
            if c in capability_registry.CAPABILITY_CATALOG
        })

        # Filtrar red en consultas de vulnerabilidades sin contexto de red
        if primary_id == "vulnerabilities" and not NETWORK_KEYWORDS.search(m):
            capabilities = [
                c for c in capabilities
                if capability_registry.CAPABILITY_CATALOG.get(c, {}).get("module") != "network"
            ]
            modules = [mod for mod in modules if mod != "network"]

        return {
            "message": message,
            "normalized": m,
            "primary_intent": primary_id,
            "primary_label": SOC_INTENTS.get(primary_id, {}).get("label", primary_id),
            "secondary_intents": secondary,
            "intent_scores": scores,
            "active_intents": active_intents,
            "capabilities": capabilities,
            "active_modules": modules,
            "actions": list(dict.fromkeys(actions)),
        }

    # Alias compat
    def analyze_intent(self, message):
        return self.classify_intent(message)

    def collect_module_data(self, modules, user_id=None, force_refresh=False):
        """Legacy — redirige a collect_capabilities."""
        caps = []
        for cap_id, meta in capability_registry.CAPABILITY_CATALOG.items():
            if meta["module"] in modules:
                caps.append(cap_id)
        return self.collect_capabilities(caps or ["dashboard.metrics"], user_id, force_refresh)

    def collect_capabilities(self, capability_ids, user_id=None, force_refresh=False, parallel_groups=None, cache_ttl_sec=0):
        return capability_registry.execute(
            capability_ids,
            user_id=user_id,
            force_refresh=force_refresh,
            parallel_groups=parallel_groups,
            cache_ttl_sec=cache_ttl_sec,
        )

    def execute_action(self, action, session_id, user_id=None, ai_kernel=None):
        result = {"action": action, "executed": False, "message": "", "data": {}}

        if action == "scan_network":
            try:
                from services.network_scan_coordinator import schedule_network_discovery
                from services.network_scanner import network_scanner

                scheduled = schedule_network_discovery(consumer="ai_orchestrator", force=False)
                nodes = network_scanner.get_cached_nodes() or []
                msg = (
                    f"Snapshot de red: {len(nodes)} dispositivo(s)."
                    if nodes
                    else ("Descubrimiento programado en background." if scheduled else "Descubrimiento ya en curso.")
                )
                result.update(executed=True, message=msg, data={"count": len(nodes), "discovery_scheduled": scheduled})
            except Exception as exc:
                result["message"] = str(exc)

        elif action == "scan_vulnerabilities":
            try:
                from services.novus_security_integration import novus_security
                vulns = novus_security.scan_vulnerabilities()
                result.update(executed=True, message=f"Escaneo de vulnerabilidades ejecutado: {len(vulns)} hallazgo(s).", data={"count": len(vulns)})
            except Exception as exc:
                result["message"] = str(exc)

        elif action in ("refresh_system", "refresh_all"):
            result.update(executed=True, message="Motores actualizados.")

        elif action == "sync_gmail":
            if user_id:
                try:
                    from services.gmail_analyzer_service import sync_new_messages
                    sync = sync_new_messages(user_id)
                    if sync.get("status") == "success":
                        result.update(executed=True, message=f"Gmail sincronizado: {sync.get('analyzed', 0)} correo(s).", data=sync)
                    else:
                        result["message"] = sync.get("message", "OAuth no configurado")
                except Exception as exc:
                    result["message"] = str(exc)
            else:
                result["message"] = "Sesión requerida"

        elif action == "sync_reports":
            try:
                from services.novus_security_integration import novus_security
                from services.security_report_service import auto_generate_for_findings
                created = auto_generate_for_findings(novus_security.scan_vulnerabilities())
                result.update(executed=True, message=f"{len(created)} informe(s) generado(s).", data={"created": len(created)})
            except Exception as exc:
                result["message"] = str(exc)

        return result

    def _risk_level(self, data):
        score = 0
        vulns = data.get("vulnerabilities") or []
        sec = data.get("security") or {}
        sys_d = data.get("system") or {}
        if (sec.get("threat_count") or 0) > 0:
            score += 3
        if len(vulns) > 3:
            score += 2
        elif vulns:
            score += 1
        if sec.get("suspicious_processes"):
            score += 2
        if (sys_d.get("cpu") or 0) > 85:
            score += 1
        if (sys_d.get("ram") or 0) > 90:
            score += 1
        if score >= 5:
            return "ALTO", score
        if score >= 3:
            return "MEDIO", score
        if score >= 1:
            return "BAJO", score
        return "NOMINAL", score

    def _direct_answer(self, intent, data):
        """Respuesta directa a la pregunta del usuario — primero."""
        pid = intent.get("primary_intent")
        vulns = data.get("vulnerabilities") or []
        sec = data.get("security") or {}
        net = data.get("network") or {}
        nodes = net.get("nodes") or []

        if pid == "vulnerabilities":
            count = len(vulns)
            if count == 0:
                return "RESPUESTA DIRECTA: No se detectaron vulnerabilidades en el escaneo actual de su equipo."
            return f"RESPUESTA DIRECTA: Su equipo tiene {count} vulnerabilidad(es) detectada(s) por el motor de seguridad NOVUS."

        if pid == "network_status":
            return (
                f"RESPUESTA DIRECTA: Red con {len(nodes)} dispositivo(s) detectado(s). "
                f"Gateway: {(net.get('meta') or {}).get('gateway', 'Sin datos')}. "
                f"Rango: {(net.get('meta') or {}).get('network_range', 'Sin datos')}."
            )

        if pid == "traffic":
            tr = data.get("traffic") or {}
            return (
                f"RESPUESTA DIRECTA: Tráfico recibido {tr.get('bytes_recv_mb', 'N/D')} MB, "
                f"enviado {tr.get('bytes_sent_mb', 'N/D')} MB, "
                f"{tr.get('active_connections', 'N/D')} conexiones activas."
            )

        if pid == "processes":
            sus = sec.get("suspicious_processes") or []
            procs = data.get("processes") or []
            return (
                f"RESPUESTA DIRECTA: {len(procs)} procesos monitorizados. "
                f"{len(sus)} proceso(s) sospechoso(s) detectado(s)."
            )

        if pid == "malware":
            sus = sec.get("suspicious_processes") or []
            return f"RESPUESTA DIRECTA: {len(sus)} indicador(es) de malware/procesos sospechosos en telemetría local."

        if pid == "firewall":
            ports = (data.get("firewall") or {}).get("open_ports") or sec.get("open_ports") or []
            return f"RESPUESTA DIRECTA: {len(ports)} puerto(s) abierto(s) detectado(s) localmente."

        if pid == "gmail":
            gm = data.get("gmail") or {}
            stats = gm.get("stats") or {}
            return f"RESPUESTA DIRECTA: {stats.get('total_analyzed', 0)} correo(s) analizados. Maliciosos: {stats.get('malicious', 0)}."

        if pid == "incidents":
            incs = data.get("incidents") or []
            return f"RESPUESTA DIRECTA: {len(incs)} incidente(s) registrado(s) en NOVUS."

        if pid == "deep_scan":
            return "RESPUESTA DIRECTA: Deep Scan integral ejecutándose en tiempo real — sin caché."

        if pid == "full_computer_analysis":
            return (
                f"RESPUESTA DIRECTA: Análisis completo ejecutado — "
                f"{len(vulns)} vulnerabilidades, {len(nodes)} dispositivos en red, "
                f"{len(sec.get('suspicious_processes') or [])} procesos sospechosos."
            )

        if pid == "general_status":
            return (
                f"RESPUESTA DIRECTA: Estado general — CPU {(data.get('system') or {}).get('cpu', 'N/D')}%, "
                f"RAM {(data.get('system') or {}).get('ram', 'N/D')}%, "
                f"{len(vulns)} vulnerabilidades, {sec.get('threat_count', 0) or 0} amenazas."
            )

        return None

    def synthesize_response(self, intent, data, actions_executed=None):
        actions_executed = actions_executed or []
        caps = data.get("capabilities_executed") or intent.get("capabilities", [])
        modules = data.get("modules_queried") or intent.get("active_modules", [])
        risk_label, risk_score = self._risk_level(data)

        lines = []
        lines.append("=== RESUMEN EJECUTIVO ===")
        direct = self._direct_answer(intent, data)
        if direct:
            lines.append(direct)
        lines.append(f"Intención clasificada: {intent.get('primary_label')} ({intent.get('primary_intent')})")
        if intent.get("secondary_intents"):
            lines.append(f"Intenciones secundarias: {', '.join(intent['secondary_intents'])}")
        lines.append(f"Motores consultados ({len(caps)}): {', '.join(caps[:6])}" + (f" +{len(caps)-6} más" if len(caps) > 6 else ""))
        lines.append(f"Nivel de riesgo: {risk_label}")

        done = [a for a in actions_executed if a.get("executed")]
        if done:
            lines.append("Acciones ejecutadas:")
            for a in done:
                lines.append(f"  [OK] {a.get('action')}: {a.get('message')}")

        lines.append("")
        lines.append("=== DETALLES TECNICOS ===")

        if "vulnerabilities" in modules or data.get("vulnerabilities") is not None:
            vulns = data.get("vulnerabilities") or []
            lines.append("\n> VULNERABILIDADES (motor security/vulnerabilities)")
            lines.append(f"  Total detectadas: {len(vulns)}")
            for v in vulns[:6]:
                lines.append(f"  - [{v.get('id', '?')}] {v.get('nombre', v.get('tipo', 'N/D'))}")

        if "network" in modules:
            net = data.get("network") or {}
            meta = net.get("meta") or {}
            nodes = net.get("nodes") or []
            lines.append("\n> RED (network scanner)")
            lines.append(f"  IP: {meta.get('local_ip', 'N/D')} | Gateway: {meta.get('gateway', 'N/D')}")
            lines.append(f"  Dispositivos: {len(nodes)}")
            for n in nodes[:4]:
                lines.append(f"  - {n.get('ip')} {n.get('name', '')}")

        if "traffic" in modules:
            tr = data.get("traffic") or {}
            lines.append("\n> TRAFICO")
            lines.append(f"  Recv: {tr.get('bytes_recv_mb', 'N/D')} MB | Sent: {tr.get('bytes_sent_mb', 'N/D')} MB")

        if "system" in modules or "dashboard" in modules:
            sys_d = data.get("system") or {}
            lines.append("\n> SISTEMA (CPU/RAM/Disco)")
            lines.append(f"  CPU: {sys_d.get('cpu', 'N/D')}% | RAM: {sys_d.get('ram', 'N/D')}% | Disco: {sys_d.get('disk', 'N/D')}%")

        if "processes" in modules or "endpoints" in modules:
            top = data.get("processes") or data.get("top_cpu") or []
            sus = (data.get("security") or {}).get("suspicious_processes") or []
            lines.append("\n> PROCESOS (process scanner + advanced_detector)")
            for p in (top[:4] if isinstance(top, list) else []):
                if isinstance(p, dict):
                    lines.append(f"  - PID {p.get('pid')} {p.get('name')} CPU {p.get('cpu_percent', 0):.1f}%")
            lines.append(f"  Sospechosos: {len(sus)}")

        if "connections" in modules:
            conn = data.get("connections") or {}
            lines.append("\n> CONEXIONES")
            lines.append(f"  Establecidas: {conn.get('established', 0)} / Total: {conn.get('total', 0)}")

        if "firewall" in modules or "security" in modules:
            ports = (data.get("firewall") or {}).get("open_ports") or (data.get("security") or {}).get("open_ports") or []
            lines.append("\n> FIREWALL / PUERTOS")
            lines.append(f"  Puertos abiertos: {len(ports)}")
            for p in ports[:5]:
                lines.append(f"  - Puerto {p.get('port')} {p.get('description', '')}")

        if "security" in modules:
            sec = data.get("security") or {}
            lines.append("\n> SEGURIDAD / XDR / THREATS")
            lines.append(f"  Amenazas: {sec.get('threat_count', 'N/D')}")

        if "gmail" in modules:
            gm = data.get("gmail") or {}
            stats = gm.get("stats") or {}
            lines.append("\n> CORREO (gmail analyzer)")
            lines.append(f"  Analizados: {stats.get('total_analyzed', 0)} | OAuth: {(gm.get('connection') or {}).get('oauth_configured', False)}")

        if "incidents" in modules:
            incs = data.get("incidents") or []
            lines.append(f"\n> INCIDENTES: {len(incs)} registrados")

        if "reports" in modules:
            reps = data.get("reports") or []
            lines.append(f"\n> REPORTES: {len(reps)} informes")

        lines.append("")
        lines.append("=== HALLAZGOS ===")
        findings = []
        vulns = data.get("vulnerabilities") or []
        if vulns:
            findings.append(f"{len(vulns)} vulnerabilidades")
        sus = (data.get("security") or {}).get("suspicious_processes") or []
        if sus:
            findings.append(f"{len(sus)} procesos sospechosos")
        lines.append("  " + ("; ".join(findings) if findings else "Sin hallazgos criticos"))

        gaps = data.get("gaps") or []
        if gaps:
            lines.append("\nDatos no disponibles:")
            for g in gaps:
                lines.append(f"  ! {g}")

        lines.append("")
        lines.append("=== RECOMENDACIONES ===")
        if vulns:
            lines.append("  -> Priorizar remediacion en /vulnerabilidades")
        if not findings:
            lines.append("  -> Mantener monitorizacion continua")

        lines.append("")
        lines.append("=== PROXIMOS PASOS ===")
        if intent.get("primary_intent") == "vulnerabilities":
            lines.append("  * Abrir /vulnerabilidades")
            lines.append("  * Generar informe en /reportes")
        elif "network" in modules:
            lines.append("  * Abrir /network")

        ui_actions = []
        pid = intent.get("primary_intent")
        if pid == "vulnerabilities":
            ui_actions.append({"label": "Vulnerabilidades", "type": "navigate", "url": "/vulnerabilidades"})
        if "network" in modules:
            ui_actions.append({"label": "Network", "type": "navigate", "url": "/network"})
        ui_actions.append({"label": "Reportes", "type": "navigate", "url": "/reportes"})

        return {
            "reply": "\n".join(lines),
            "actions": ui_actions,
            "confirm_required": False,
            "risk_level": risk_label,
            "modules_used": modules,
            "capabilities_used": caps,
            "primary_intent": intent.get("primary_intent"),
            "data_snapshot": {"risk_score": risk_score, "modules": modules, "capabilities": caps},
        }

    def resolve_navigation(self, message):
        m = self.normalize(message)
        for key, url in MODULE_ROUTES.items():
            if key in m:
                return url, key
        return None, None


kernel_orchestrator = KernelOrchestrator()

# Export for ai_kernel
MODULES = tuple(set(
    meta["module"] for meta in capability_registry.CAPABILITY_CATALOG.values()
))
