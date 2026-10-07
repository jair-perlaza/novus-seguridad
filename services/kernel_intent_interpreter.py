"""
Intérprete de intención del Kernel IA — Fase 1.

Interpreta escenarios operativos (no solo palabras clave aisladas).
Combina señales semánticas, contexto de sesión e historial reciente.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# Perfiles de investigación — motores reales existentes en capability_registry
INVESTIGATION_PROFILES: Dict[str, dict] = {
    "performance_investigation": {
        "label": "Investigación de rendimiento del equipo",
        "intent_id": "performance_slow",
        "signals": [
            (r"\b(lento|lenta|lentitud|va\s+mal|congela|bloquea|traba|tarda\s+mucho)\b", 18),
            (r"\b(computador|equipo|port[aá]til|pc|laptop)\b", 4),
        ],
        "capabilities": [
            "system.metrics",
            "security.system_health",
            "process.scanner",
            "advanced_detector.processes",
            "connections.active",
            "network.events",
            "security.threats",
            "incidents.manager",
        ],
        "internal_steps": [
            "Evaluar CPU, RAM y disco",
            "Analizar procesos y consumo",
            "Revisar servicios y memoria",
            "Analizar conexiones activas",
            "Revisar eventos recientes",
            "Correlacionar hallazgos",
            "Generar conclusiones",
        ],
    },
    "full_device_scan": {
        "label": "Escaneo completo del equipo",
        "intent_id": "deep_scan",
        "signals": [
            (r"\b(escanea|escanear|analiza|analizar)\s+(mi\s+)?(port[aá]til|laptop|equipo|pc|computador)\b", 20),
            (r"\b(an[aá]lisis|escaneo)\s+(completo|integral|total)\b", 18),
        ],
        "workflow_profile": "full",
        "capabilities": [],
        "internal_steps": [
            "Analizar procesos",
            "Analizar servicios",
            "Analizar memoria",
            "Analizar conexiones",
            "Analizar firewall",
            "Analizar puertos",
            "Analizar dispositivos",
            "Analizar eventos",
            "Correlacionar",
            "Generar conclusiones",
        ],
    },
    "network_only": {
        "label": "Análisis exclusivo de red",
        "intent_id": "network_status",
        "exclusive_capabilities": True,
        "signals": [
            (r"\b(revisa|revisar|escanea|escanear|analiza|analizar)\s+(mi\s+)?red\b", 18),
            (r"\b(estado|seguridad)\s+de\s+(la\s+)?red\b", 14),
        ],
        "capabilities": [
            "network.radar",
            "network.scanner",
            "connections.active",
            "traffic.stats",
            "firewall.ports",
            "network.events",
        ],
        "orchestrator_actions": ["scan_network"],
        "internal_steps": [
            "Escaneo ARP / inventario",
            "Conexiones activas",
            "Tráfico y puertos",
            "Firewall",
            "Correlación de red",
            "Conclusiones",
        ],
    },
    "anomaly_suspicion": {
        "label": "Investigación de actividad sospechosa",
        "intent_id": "malware",
        "signals": [
            (r"\b(algo\s+raro|sospech|extra[nñ]o|anomal[ií]|inusual|no\s+me\s+cuadra)\b", 18),
            (r"\b(hay\s+algo|pasa\s+algo|est[aá]\s+mal)\b", 12),
        ],
        "capabilities": [
            "security.threats",
            "advanced_detector.malware",
            "advanced_detector.processes",
            "process.scanner",
            "security.vulnerabilities",
            "connections.active",
            "network.events",
        ],
        "internal_steps": [
            "Evaluar amenazas XDR",
            "Analizar procesos sospechosos",
            "Buscar malware",
            "Revisar conexiones",
            "Correlacionar indicadores",
            "Priorizar hallazgos",
            "Conclusiones",
        ],
    },
    "contextual_problem": {
        "label": "Análisis contextual del problema en curso",
        "intent_id": None,  # hereda de sesión
        "signals": [
            (r"\b(analiza|analizar|revisa|revisar|investiga|investigar)\s+(este|ese|el)\s+(problema|tema|caso|asunto)\b", 22),
            (r"\b(sobre\s+eso|mismo\s+tema|contin[uú]a|sigue\s+con)\b", 16),
        ],
        "use_session_intent": True,
        "internal_steps": [
            "Recuperar contexto de sesión",
            "Re-ejecutar motores relevantes",
            "Correlacionar con hallazgos previos",
            "Conclusiones",
        ],
    },
}


def interpret_intent(
    message: str,
    base_intent: dict,
    session_ctx: Optional[dict] = None,
    history: Optional[List[dict]] = None,
) -> dict:
    """
    Enriquece la intención base con interpretación de escenario.
    Retorna dict con primary_intent, capabilities, internal_plan, confidence, reasoning.
    """
    m = str(message or "").lower().strip()
    m = re.sub(r"\[contexto:[^\]]+\]\s*", "", m, flags=re.I)
    session_ctx = session_ctx or {}
    best_profile = None
    best_score = 0.0

    for pid, profile in INVESTIGATION_PROFILES.items():
        score = 0.0
        for pattern, weight in profile.get("signals", []):
            if re.search(pattern, m, re.I):
                score += weight
        if score > best_score:
            best_score = score
            best_profile = pid

    result = dict(base_intent)
    result["interpretation_method"] = "regex_base"
    result["reasoning"] = []

    if best_profile and best_score >= 12:
        prof = INVESTIGATION_PROFILES[best_profile]
        result["interpretation_method"] = "scenario_profile"
        result["scenario_id"] = best_profile
        result["reasoning"].append(
            f"Escenario detectado: {prof['label']} (confianza {min(100, int(best_score * 3))}%)"
        )

        if prof.get("use_session_intent") and session_ctx.get("last_intent"):
            result["primary_intent"] = session_ctx["last_intent"]
            result["primary_label"] = session_ctx.get("last_intent_label") or session_ctx["last_intent"]
            result["reasoning"].append(f"Referencia contextual → intención previa: {result['primary_label']}")
        elif prof.get("intent_id"):
            result["primary_intent"] = prof["intent_id"]
            result["primary_label"] = prof["label"]

        if prof.get("capabilities"):
            caps = list(prof["capabilities"])
            if not prof.get("exclusive_capabilities"):
                for c in base_intent.get("capabilities") or []:
                    if c not in caps:
                        caps.append(c)
            result["capabilities"] = caps

        if prof.get("orchestrator_actions"):
            actions = list(prof.get("orchestrator_actions") or [])
            for a in base_intent.get("actions") or []:
                if a not in actions:
                    actions.append(a)
            result["actions"] = actions

        if prof.get("workflow_profile"):
            result["workflow_profile"] = prof["workflow_profile"]

        result["internal_plan"] = prof.get("internal_steps") or []
        result["confidence"] = min(100, int(best_score * 3))
    else:
        result["internal_plan"] = _default_plan_for_intent(base_intent.get("primary_intent", "general_status"))
        intent_scores = base_intent.get("intent_scores") or {}
        result["confidence"] = int(max(intent_scores.values(), default=0) * 5)
        result["reasoning"].append(f"Intención base: {base_intent.get('primary_label', 'N/D')}")

    # Refuerzo por historial — follow-up corto
    if history and len(m) < 40:
        follow = re.search(r"^(y\s+|tambi[eé]n|qu[eé]\s+tal|y\s+la\s+|y\s+el\s+)", m)
        if follow and session_ctx.get("last_intent"):
            result["reasoning"].append("Follow-up detectado — manteniendo hilo de investigación")
            if not result.get("capabilities"):
                result["capabilities"] = list(base_intent.get("capabilities") or [])

    return result


def _default_plan_for_intent(intent_id: str) -> List[str]:
    plans = {
        "vulnerabilities": [
            "Ejecutar motor de vulnerabilidades",
            "Correlacionar XDR",
            "Priorizar por impacto",
            "Generar conclusiones",
        ],
        "network_status": [
            "Escaneo de red",
            "Conexiones y firewall",
            "Correlacionar",
            "Conclusiones",
        ],
        "malware": [
            "Threat engine",
            "Procesos sospechosos",
            "Antimalware",
            "Conclusiones",
        ],
        "general_status": [
            "Métricas de sistema",
            "Amenazas y vulnerabilidades",
            "Correlacionar",
            "Conclusiones",
        ],
    }
    return plans.get(intent_id, [
        "Clasificar intención",
        "Ejecutar motores relevantes",
        "Correlacionar evidencias",
        "Generar conclusiones",
    ])
