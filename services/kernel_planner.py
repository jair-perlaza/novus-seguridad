"""
Planificador interno del Kernel IA — convierte intención + contexto en plan de ejecución.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from services.ai_orchestrator import kernel_orchestrator, SOC_INTENTS

GREETING = re.compile(
    r"^(hola|hey|buenos\s+d[ií]as|buenas\s+tardes|buenas\s+noches|saludos|qu[eé]\s+tal)[\s!.?]*$",
    re.I,
)

DAILY_SUMMARY = re.compile(
    r"qu[eé]\s+pas[oó]\s+hoy|resumen\s+de\s+hoy|eventos\s+de\s+hoy|actividad\s+de\s+hoy|"
    r"qu[eé]\s+ocurri[oó]\s+hoy|informe\s+del\s+d[ií]a",
    re.I,
)


@dataclass
class ExecutionPlan:
    """Plan interno generado antes de ejecutar motores."""
    goal: str
    intent_id: str
    intent_label: str
    request_type: str  # greeting | query | action | clean_threats
    capabilities: List[str] = field(default_factory=list)
    orchestrator_actions: List[str] = field(default_factory=list)
    workflow_profile: Optional[str] = None
    workflow_sync: bool = False
    workflow_modules: List[str] = field(default_factory=list)
    inline_action: Optional[str] = None
    phases: List[str] = field(default_factory=list)
    auto_actions_allowed: List[str] = field(default_factory=list)
    requires_confirmation: bool = False
    confirmation_reason: str = ""
    skip_engines: bool = False
    rationale: List[str] = field(default_factory=list)
    missing_capabilities: List[str] = field(default_factory=list)
    # Rendimiento (kernel_performance_planner)
    performance_level: int = 2
    performance_label: str = "Análisis rápido"
    target_seconds_min: float = 5.0
    target_seconds_max: float = 15.0
    eta_message: str = ""
    force_refresh_policy: bool = False
    cache_ttl_sec: int = 30
    sync_fast_path: bool = False
    parallel_groups: List[List[str]] = field(default_factory=list)
    quick_capabilities: List[str] = field(default_factory=list)
    # Fase 1 — plan interno (no visible al usuario salvo debug)
    internal_plan: List[str] = field(default_factory=list)
    intent_confidence: int = 0
    intent_reasoning: List[str] = field(default_factory=list)
    scenario_id: Optional[str] = None


# Capacidades por dominio operativo (reutiliza motores existentes)
DOMAIN_ENGINES = {
    "network": [
        "network.ndr", "network.radar", "network.scanner", "network.events",
        "connections.active", "traffic.stats", "firewall.ports",
    ],
    "threats": [
        "security.threats", "advanced_detector.malware",
        "advanced_detector.processes", "security.vulnerabilities",
    ],
    "vulnerabilities": [
        "security.vulnerabilities", "vulnerability.scanner",
        "advanced_detector.ports", "security.threats", "reports.manager",
    ],
    "processes": [
        "process.scanner", "advanced_detector.processes",
        "endpoints.live", "system.metrics",
    ],
    "email": ["gmail.analyzer", "security.threats"],
    "enterprise": [
        "security.sector_shield", "security.vulnerabilities", "security.threats",
        "network.scanner", "incidents.manager", "reports.manager", "playbooks.manager",
    ],
    "daily": [
        "siem.logs", "incidents.manager", "network.events",
        "security.threats", "reports.manager",
    ],
    "vault": ["security.vault"],
    "playbooks": ["playbooks.manager"],
    "topology": ["topology.view", "network.scanner"],
}

# Motores solicitados pero sin implementación independiente
MISSING_STANDALONE = {
    "radar": "network.radar (alias ARP — Radar dedicado requiere desarrollo)",
    "topology_ui": "topology.view (datos de red; UI completa en /topology)",
    "virustotal": "Integración VirusTotal — requiere API key",
    "spf_dkim": "Validación SPF/DKIM/DMARC completa — desarrollo adicional",
}


def build_plan(
    message: str,
    context: Optional[dict] = None,
    user_prefs: Optional[dict] = None,
    session_id: Optional[str] = None,
    history: Optional[List[dict]] = None,
) -> ExecutionPlan:
    """Crea plan interno a partir del mensaje, contexto de sesión e historial."""
    from services.kernel_operator import ACTION_PROFILES, classify_request, resolve_action, _build_action
    from services.kernel_intent_interpreter import interpret_intent
    from services.kernel_session_context import kernel_session_context

    context = context or {}
    user_prefs = user_prefs or {}
    rationale: List[str] = []

    session_ctx = kernel_session_context.get(session_id or "")
    if history:
        session_ctx = kernel_session_context.enrich_from_history(session_id or "", history)
    resolved_message = kernel_session_context.resolve_message(message, session_id or "")

    if GREETING.match(message.strip()):
        plan = ExecutionPlan(
            goal="Saludo del operador",
            intent_id="greeting",
            intent_label="Saludo",
            request_type="greeting",
            skip_engines=True,
            rationale=["Mensaje de saludo — respuesta natural sin escaneo obligatorio"],
        )
        from services.kernel_performance_planner import apply_performance_to_plan, classify_performance_level
        apply_performance_to_plan(plan, classify_performance_level(plan, message))
        return plan

    classification = classify_request(message)
    req_type = classification["request_type"]

    if req_type == "clean_threats":
        plan = ExecutionPlan(
            goal="Limpieza de amenazas con confirmación",
            intent_id="threat_cleanup",
            intent_label="Limpieza de amenazas",
            request_type="clean_threats",
            capabilities=["security.threats", "security.vulnerabilities", "advanced_detector.malware"],
            requires_confirmation=True,
            confirmation_reason="Remediación puede terminar procesos o modificar configuración",
            rationale=["Detección previa obligatoria antes de cualquier acción destructiva"],
        )
        _attach_performance(plan, message)
        return plan

    intent = kernel_orchestrator.analyze_intent(resolved_message)
    intent = interpret_intent(resolved_message, intent, session_ctx, history)
    pid = intent.get("primary_intent", "general_status")
    label = intent.get("primary_label", pid)

    kernel_session_context.update_before_plan(session_id or "", message, pid, label)
    for hint in kernel_session_context.planning_hints(session_id or ""):
        rationale.append(hint)
    for r in intent.get("reasoning") or []:
        rationale.append(r)

    if DAILY_SUMMARY.search(message.lower()):
        pid = "daily_summary"
        label = "Resumen de actividad del día"
        rationale.append("Consulta temporal — revisar eventos SIEM/incidentes/red del día")

    plan = ExecutionPlan(
        goal=f"Atender: {label}",
        intent_id=pid,
        intent_label=label,
        request_type=req_type if req_type != "query" else "query",
        capabilities=list(intent.get("capabilities") or []),
        orchestrator_actions=list(intent.get("actions") or []),
        rationale=[f"Intención interpretada: {label} [{pid}]"],
        internal_plan=list(intent.get("internal_plan") or []),
        intent_confidence=intent.get("confidence") or 0,
        intent_reasoning=list(intent.get("reasoning") or []),
        scenario_id=intent.get("scenario_id"),
    )

    if intent.get("workflow_profile") and not plan.workflow_profile:
        plan.workflow_profile = intent["workflow_profile"]

    # Acción con workflow Deep Scan
    if req_type == "action" and classification.get("action"):
        action = classification["action"]
        if action.get("type") == "inline":
            plan.inline_action = action.get("action_id")
            plan.request_type = "action"
            plan.rationale.append(f"Acción inline: {action.get('label')}")
            _attach_performance(plan, message)
            return plan

        profile = action.get("profile") or "full"
        meta = ACTION_PROFILES.get(profile, ACTION_PROFILES["full"])
        plan.workflow_profile = profile
        plan.workflow_sync = meta.get("sync", False)
        plan.workflow_modules = meta.get("modules", [])
        plan.request_type = "action"
        plan.phases = _phases_for_profile(profile)
        plan.rationale.append(f"Workflow Deep Scan perfil «{profile}» — {len(plan.workflow_modules)} motores")
        # No ejecutar deep_scan.engine vía registry en paralelo
        plan.capabilities = [c for c in plan.capabilities if c != "deep_scan.engine"]
        _attach_performance(plan, message)
        return plan

    # Consultas analíticas — enriquecer capacidades según dominio
    if pid == "daily_summary":
        plan.capabilities = DOMAIN_ENGINES["daily"]
    elif pid in ("network_status", "wifi_intrusion"):
        if plan.scenario_id == "network_only":
            plan.capabilities = list(dict.fromkeys(plan.capabilities or DOMAIN_ENGINES["network"]))
        else:
            plan.capabilities = list(dict.fromkeys(
                DOMAIN_ENGINES["network"] + (plan.capabilities or [])
            ))
        from services.kernel_performance_planner import SCAN_VERBS
        if SCAN_VERBS.search(message):
            plan.orchestrator_actions.append("scan_network")
        plan.missing_capabilities.append(MISSING_STANDALONE["radar"])
    elif pid == "vulnerabilities":
        plan.capabilities = list(dict.fromkeys(DOMAIN_ENGINES["vulnerabilities"] + plan.capabilities))
    elif pid == "malware":
        plan.capabilities = list(dict.fromkeys(DOMAIN_ENGINES["threats"] + plan.capabilities))
    elif pid == "processes" or pid == "performance_slow":
        plan.capabilities = list(dict.fromkeys(
            [
                "system.metrics",
                "security.system_health",
                "process.scanner",
                "advanced_detector.processes",
                "connections.active",
                "network.events",
                "security.threats",
                "incidents.manager",
            ] + plan.capabilities
        ))
        if not plan.internal_plan:
            plan.internal_plan = [
                "Evaluar CPU, RAM y disco",
                "Analizar procesos",
                "Analizar servicios y memoria",
                "Analizar conexiones",
                "Revisar eventos",
                "Correlacionar",
                "Conclusiones",
            ]
    elif pid in ("gmail", "email_analysis"):
        plan.capabilities = DOMAIN_ENGINES["email"]
        plan.missing_capabilities.extend([MISSING_STANDALONE["spf_dkim"], MISSING_STANDALONE["virustotal"]])
    elif pid == "enterprise_security":
        plan.capabilities = list(dict.fromkeys(DOMAIN_ENGINES["enterprise"] + plan.capabilities))
    elif pid in ("deep_scan", "full_computer_analysis"):
        action = resolve_action(message) or _build_action("full", message, 20)
        plan.workflow_profile = action.get("profile") or "full"
        meta = ACTION_PROFILES.get(plan.workflow_profile, ACTION_PROFILES["full"])
        plan.workflow_sync = meta.get("sync", False)
        plan.workflow_modules = meta.get("modules", [])
        plan.phases = _phases_for_profile(plan.workflow_profile)
        plan.request_type = "action"
        plan.capabilities = [c for c in plan.capabilities if c != "deep_scan.engine"]

    # Preferencias del usuario — priorizar escaneos frecuentes en sugerencias (no auto-ejecutar)
    freq = user_prefs.get("frequent_scans") or []
    if freq and plan.workflow_profile:
        rationale.append(f"Perfil habitual del operador: {freq[0][0]}")

    # Filtrar capacidades no ejecutables inline
    plan.capabilities = [c for c in plan.capabilities if c != "deep_scan.engine"]

    if not plan.capabilities and not plan.workflow_profile and not plan.inline_action:
        plan.capabilities = ["security.threats", "security.vulnerabilities", "system.metrics"]

    plan.rationale.extend(plan.missing_capabilities)
    sector_key = context.get("sector_key")
    if sector_key:
        from services.sector_profile_service import apply_sector_to_plan
        apply_sector_to_plan(plan, sector_key)
    _attach_performance(plan, message)
    return plan


def _attach_performance(plan: ExecutionPlan, message: str) -> None:
    from services.kernel_performance_planner import apply_performance_to_plan, classify_performance_level
    perf = classify_performance_level(plan, message)
    apply_performance_to_plan(plan, perf)
    plan.rationale.append(
        f"Rendimiento N{perf.level} ({perf.label}) — refresh={'sí' if perf.force_refresh else 'caché'}"
    )


def _phases_for_profile(profile: str) -> List[str]:
    """Fases SOC mostradas al operador durante Deep Scan."""
    common = {
        "full": [
            "Fase 1 — Sistema operativo",
            "Fase 2 — Procesos",
            "Fase 3 — Servicios",
            "Fase 4 — Conexiones de red",
            "Fase 5 — Puertos",
            "Fase 6 — Firewall",
            "Fase 7 — Archivos críticos",
            "Fase 8 — Registros y eventos",
            "Fase 9 — Correlación de evidencias",
        ],
        "network": [
            "Fase 1 — Escaneo ARP / Radar",
            "Fase 2 — Conexiones activas",
            "Fase 3 — Puertos expuestos",
            "Fase 4 — Firewall",
            "Fase 5 — Correlación de red",
        ],
        "processes": [
            "Fase 1 — Inventario de procesos",
            "Fase 2 — Memoria",
            "Fase 3 — DLL / cargas sospechosas",
            "Fase 4 — Defender / XDR",
        ],
        "malware": [
            "Fase 1 — Procesos sospechosos",
            "Fase 2 — Archivos y reputación",
            "Fase 3 — Threat Engine / XDR",
            "Fase 4 — Vulnerabilidades asociadas",
        ],
        "connections": [
            "Fase 1 — Conexiones activas",
            "Fase 2 — DNS / Gateway",
            "Fase 3 — Puertos y firewall",
        ],
    }
    return common.get(profile, common["full"])
