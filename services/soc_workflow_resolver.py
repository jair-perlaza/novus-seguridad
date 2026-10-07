"""
Resolver de workflows SOC/XDR — el Kernel NO responde con resumen hasta completar análisis.
"""
import re
from typing import Optional

# Perfiles → fases del motor (deep_scan_engine)
WORKFLOW_PROFILES = {
    "full": {
        "label": "Escaneo integral SOC/XDR",
        "modules": [
            "Process Scanner", "Memory Scanner", "Startup Scanner", "Windows Services",
            "Drivers", "DLL Loader", "Registry Scanner", "Firewall Analyzer",
            "Open Ports", "Active Connections", "Installed Programs", "Scheduled Tasks",
            "Browser Extensions", "USB Devices", "Security Logs", "Event Viewer",
            "Defender Status", "Certificate Store", "File Reputation",
            "Advanced Detector", "Security Engine",
        ],
    },
    "processes": {
        "label": "Análisis de procesos y aplicaciones",
        "modules": [
            "Process Scanner", "Memory Scanner", "DLL Loader", "Advanced Detector",
            "Security Engine", "Defender Status",
        ],
    },
    "memory": {
        "label": "Análisis de memoria",
        "modules": ["Memory Scanner", "Process Scanner", "Advanced Detector"],
    },
    "malware": {
        "label": "Caza de malware",
        "modules": [
            "Process Scanner", "File Reputation", "DLL Loader", "Advanced Detector",
            "Security Engine", "Defender Status",
        ],
    },
    "rootkit": {
        "label": "Detección rootkit / procesos ocultos",
        "modules": [
            "Process Scanner", "Memory Scanner", "Drivers", "Windows Services",
            "DLL Loader", "Advanced Detector", "Security Engine",
        ],
    },
    "services": {
        "label": "Análisis de servicios y drivers",
        "modules": ["Windows Services", "Drivers", "Startup Scanner", "Process Scanner"],
    },
    "registry": {
        "label": "Análisis de registro y persistencia",
        "modules": ["Registry Scanner", "Startup Scanner", "Scheduled Tasks"],
    },
    "connections": {
        "label": "Análisis de conexiones y red local",
        "modules": ["Active Connections", "Open Ports", "Firewall Analyzer"],
    },
    "installed": {
        "label": "Programas instalados",
        "modules": ["Installed Programs", "Browser Extensions", "Startup Scanner"],
    },
    "scheduled": {
        "label": "Tareas programadas",
        "modules": ["Scheduled Tasks", "Startup Scanner", "Registry Scanner"],
    },
    "background": {
        "label": "Aplicaciones en segundo plano",
        "modules": ["Process Scanner", "Memory Scanner", "Startup Scanner", "Advanced Detector"],
    },
    "network": {
        "label": "Análisis de red (ARP + conexiones + firewall)",
        "modules": ["Network Scanner ARP", "Active Connections", "Open Ports", "Firewall Analyzer"],
    },
}

# (patrón, perfil, peso) — mayor peso gana
SOC_PATTERNS = [
    (r"analiza\s+mi\s+red|revisa\s+mi\s+red|escanea\s+(?:mi\s+)?red\b", "network", 22),
    (r"revisa\s+mi\s+firewall|analiza\s+(?:mi\s+)?firewall", "connections", 21),
    (r"deep\s*scan|escaneo\s+integral", "full", 25),
    (r"escanea\s+mi\s+(port[aá]til|laptop|computador|equipo|pc)", "full", 24),
    (r"analiza\s+mi\s+(equipo|computador|port[aá]til|pc)", "full", 23),
    (r"haz\s+un\s+an[aá]lisis\s+completo|an[aá]lisis\s+integral", "full", 22),
    (r"revisa\s+todo|analiza\s+todos\s+los\s+archivos", "full", 21),
    (r"busca\s+anomal[ií]as", "full", 20),
    (r"busca\s+procesos?\s+ocultos?|procesos?\s+ocultos?", "rootkit", 22),
    (r"busca\s+rootkits?|detecta\s+rootkits?", "rootkit", 22),
    (r"busca\s+malware|buscar\s+virus|detecta\s+malware", "malware", 21),
    (r"analiza\s+memoria|escaneo\s+de\s+memoria", "memory", 20),
    (r"busca\s+aplicaciones?\s+sospechosas?|aplicaciones?\s+sospechosas?", "processes", 20),
    (r"busca\s+software\s+ejecut[aá]ndose\s+sin\s+autorizaci[oó]n", "processes", 20),
    (r"aplicaciones?\s+en\s+segundo\s+plano|segundo\s+plano", "background", 19),
    (r"revisa\s+procesos?|analiza\s+procesos?|busca\s+procesos?", "processes", 18),
    (r"analiza\s+servicios?|revisa\s+servicios?", "services", 18),
    (r"analiza\s+tareas?\s+programadas?|tareas?\s+programadas?", "scheduled", 18),
    (r"analiza\s+el\s+registro|registro\s+windows", "registry", 18),
    (r"analiza\s+conexiones?|conexiones?\s+sospechosas?", "connections", 18),
    (r"analiza\s+programas?\s+instalados?|programas?\s+instalados?", "installed", 17),
    (r"sin\s+firma|sin\s+autorizaci[oó]n|desconocid", "processes", 16),
    (r"\b(escanea|analiza|revisa|busca|detecta|verifica)\b.*\b(equipo|port[aá]til|pc|sistema|host)\b", "full", 15),
]

# Consultas que NUNCA deben usar el chatbot de resumen (verbos de análisis)
SOC_ACTION_VERBS = re.compile(
    r"\b(escanea|escanear|analiza|analizar|revisa|revisar|busca|buscar|detecta|detectar|verifica|verificar)\b",
    re.I,
)

# Intents del orquestador que deben redirigirse a workflow si hay verbo de acción
REDIRECT_INTENTS = {
    "processes", "malware", "system_health", "firewall", "connections",
    "full_computer_analysis", "deep_scan",
}


def normalize(text: str) -> str:
    t = str(text or "").lower().strip()
    t = t.replace("¿", "").replace("?", "").replace("¡", "").replace("!", "")
    return re.sub(r"\s+", " ", t)


def resolve_soc_workflow(message: str, orchestrator_intent: Optional[str] = None) -> Optional[dict]:
    """
    Si la consulta requiere análisis SOC, retorna perfil y módulos.
    None → puede usar orquestador conversacional (estado general, red, etc.).
    """
    m = normalize(message)
    if not m or len(m) < 4:
        return None

    best_profile = None
    best_score = 0
    for pattern, profile, weight in SOC_PATTERNS:
        if re.search(pattern, m, re.I):
            if weight > best_score:
                best_score = weight
                best_profile = profile

    if not best_profile and orchestrator_intent in REDIRECT_INTENTS and SOC_ACTION_VERBS.search(m):
        intent_map = {
            "processes": "processes",
            "malware": "malware",
            "system_health": "full",
            "firewall": "connections",
            "connections": "connections",
            "full_computer_analysis": "full",
            "deep_scan": "full",
        }
        best_profile = intent_map.get(orchestrator_intent, "full")
        best_score = 14

    if not best_profile:
        return None

    meta = WORKFLOW_PROFILES.get(best_profile, WORKFLOW_PROFILES["full"])
    return {
        "profile": best_profile,
        "label": meta["label"],
        "modules": meta["modules"],
        "score": best_score,
        "query": message,
    }


def is_soc_workflow_message(message: str) -> bool:
    return resolve_soc_workflow(message) is not None
