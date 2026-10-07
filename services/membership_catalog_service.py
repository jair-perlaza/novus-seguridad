"""
Catálogo de membresías NOVUS — únicamente capacidades verificadas en código.
Fuente canónica para UI de planes, registro y consultas Kernel IA.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# Capacidades verificadas → módulos/rutas/servicios reales
CAPABILITY_INDEX: Dict[str, Dict[str, Any]] = {
    "dashboard": {"module": "dashboard", "route": "/dashboard", "service": "platform_metrics_service"},
    "kernel_ia": {"module": "kernel_ia", "route": "/api/ai", "service": "ai_kernel"},
    "auto_scan": {"module": "network", "service": "network_monitor_engine, novus_security_integration"},
    "manual_scan": {"module": "centro_defensa", "route": "/centro-defensa-manual", "service": "manual_defense_service"},
    "centro_defensa": {"route": "/centro-defensa-manual", "service": "defense_center_service"},
    "reports_pdf": {"module": "reportes", "route": "/reportes", "service": "security_report_service"},
    "historial": {"route": "/historial-dispositivos", "service": "device_connection_monitor"},
    "xdr": {"module": "xdr", "route": "/xdr", "service": "novus_security_integration"},
    "ndr": {"module": "network", "route": "/network", "service": "network_ndr_service"},
    "malware": {"service": "advanced_detector_service, novus_security_integration"},
    "ransomware": {"service": "platform_metrics_service.get_active_ransomware_findings"},
    "brute_force": {"service": "auth_protection_service"},
    "web_shield_basic": {"module": "web_shield", "route": "/web-shield", "service": "web_shield_engine"},
    "web_shield_advanced": {"module": "web_shield", "service": "web_shield_analyzer, web_shield_host_audit"},
    "mail_shield": {"module": "mail_shield", "route": "/mail-shield", "service": "mail_shield_engine"},
    "phishing": {"api": "POST /api/system/security/phishing/inspect", "service": "mail_shield, web_shield"},
    "bec": {"api": "POST /api/system/security/bec/validate"},
    "link_protection": {"service": "web_shield_analyzer.analyze_and_policy_url"},
    "attachment_protection": {"service": "mail_shield_service quarantine"},
    "domain_reputation": {"service": "web_shield_analyzer"},
    "deep_scan": {"service": "deep_scan_engine, endpoint_scan_engine"},
    "host_scan_processes": {"service": "manual_defense_catalog host_scan_processes"},
    "host_scan_memory": {"service": "manual_defense_catalog host_scan_memory"},
    "host_scan_services": {"service": "manual_defense_catalog host_scan_services"},
    "host_scan_registry": {"service": "manual_defense_catalog host_scan_registry"},
    "playbooks": {"module": "playbooks", "route": "/automatizacion", "service": "playbook_service"},
    "cryptovault": {"api": "/api/system/defense-registry", "service": "crypto_vault, defense_evidence_registry"},
    "forensic_integrity": {"route": "/verificador-evidencias", "service": "forensic_evidence_integrity_service"},
    "security_audit": {"api": "/api/audit/integral/summary", "service": "integral_security_audit_service"},
    "executive_reports": {"service": "soc_report_builder, reports_center_service"},
    "sector_fintech": {"service": "sector_shield_service, adaptive_sector_protection_engine"},
    "sector_logistics": {"service": "sector_shield_service (logistica)"},
    "sector_mobile": {"service": "adaptive_sector_protection_engine (movil/UI Shield)"},
    "sector_cloud_uce": {"service": "universal_compatibility_engine", "note": "Cloud Shield CSPM planificado"},
    "network_history": {"route": "/historial-seguridad-red", "service": "network_security_history_service"},
    "threat_intel": {"route": "/inteligencia", "service": "threat_intelligence_service"},
    "forensic_pcap": {"api": "/api/forensic-pcap", "service": "forensic_pcap_capture_service"},
    "chain_of_custody": {"service": "forensic_evidence_integrity_service"},
    "immutable_storage": {"path": "data/forensic_ledger/records.jsonl"},
    "digital_signatures": {"service": "forensic_evidence_keys Ed25519"},
    "crypto_hashes": {"service": "forensic_evidence_integrity_service SHA-256"},
    "kernel_contextual": {"service": "kernel_coordinator, module_kernel_context"},
    "executive_dashboard": {"api": "/api/threat-intel/dashboard, /api/dashboard/priority"},
    "continuous_monitoring": {"api": "/api/monitoring/status", "service": "continuous_monitoring_orchestrator"},
    "m365_oauth": {"service": "microsoft365_oauth_service", "requires": "AZURE_CLIENT_ID/SECRET"},
    "google_oauth": {"service": "gmail_oauth_service", "requires": "GOOGLE_CLIENT_ID/SECRET"},
    "enterprise_api": {"service": "REST APIs /api/*"},
    "sector_policies": {"api": "/api/system/sector-shield/policies"},
    "ndr_investigate": {"api": "POST /api/network/ndr/device/<ip>/investigate"},
    "forensic_vault": {"service": "forensic_evidence_integrity_service, data/forensic_keys"},
    "endpoint_management": {"api": "/api/endpoint-scan", "service": "endpoint_scan_engine"},
    "incident_automation": {"service": "playbook_orchestrator, remediation_engine"},
    "enterprise_data": {"api": "/api/enterprise/architecture/status", "service": "enterprise_data_service"},
    "siem_internal": {"route": "/siem", "service": "database.Log, ai_kernel"},
    "alerts": {"route": "/incidentes", "service": "alerts_canonical_service"},
    "evidence_center": {"route": "/centro-evidencias", "service": "evidence_center_service"},
    "tenant_scope": {"api": "/api/tenant/scope", "service": "tenant_scope_service"},
}

PLANS: List[Dict[str, Any]] = [
    {
        "id": "essential",
        "legacy_id": "STARTER",
        "name": "Essential",
        "price_min_usd": 25,
        "price_max_usd": 60,
        "price_label": "USD 25–60 / equipo / mes",
        "client_type": "Microempresas, profesionales independientes y negocios pequeños",
        "endpoints_label": "1–10 equipos protegidos (nodo NOVUS + dispositivos ARP en LAN)",
        "icon": "fa-shield-alt",
        "color": "#06b6d4",
        "capabilities": [
            "dashboard", "kernel_ia", "auto_scan", "manual_scan", "centro_defensa",
            "reports_pdf", "historial", "xdr", "ndr", "malware", "ransomware",
            "brute_force", "web_shield_basic", "alerts", "evidence_center",
        ],
        "kernel_summary": (
            "Plan de entrada con telemetría real del host NOVUS: dashboard, escaneos automáticos "
            "y manuales básicos, XDR/NDR, Web Shield básico, alertas y reportes PDF."
        ),
        "ideal_for": "PyMEs que necesitan visibilidad de seguridad en un solo nodo sin complejidad SOC.",
    },
    {
        "id": "professional",
        "legacy_id": "PRO",
        "name": "Professional",
        "price_min_usd": 80,
        "price_max_usd": 180,
        "price_label": "USD 80–180 / equipo / mes",
        "client_type": "Empresas medianas con operación digital y correo/navegación expuestos",
        "endpoints_label": "Hasta 50 equipos monitoreados vía inventario de red del nodo NOVUS",
        "icon": "fa-user-shield",
        "color": "#6366f1",
        "includes_plan": "essential",
        "capabilities": [
            "web_shield_advanced", "mail_shield", "phishing", "bec", "link_protection",
            "attachment_protection", "domain_reputation", "deep_scan",
            "host_scan_processes", "host_scan_memory", "host_scan_services",
            "host_scan_registry", "playbooks", "cryptovault", "forensic_integrity",
            "security_audit", "executive_reports",
        ],
        "kernel_summary": (
            "Añade escudos web y correo (OAuth requerido), escaneos profundos del host, "
            "playbooks, CryptoVault, integridad forense y auditoría integral."
        ),
        "ideal_for": "Equipos que requieren protección de correo/navegación y respuesta estructurada.",
    },
    {
        "id": "business",
        "legacy_id": "CORP",
        "name": "Business",
        "price_min_usd": 250,
        "price_max_usd": 600,
        "price_label": "USD 250–600 / equipo / mes",
        "client_type": "Organizaciones con múltiples redes, sectores regulados y necesidad forense",
        "endpoints_label": "Hasta 200 equipos / múltiples perfiles de red (historial por scope)",
        "icon": "fa-building",
        "color": "#8b5cf6",
        "includes_plan": "professional",
        "capabilities": [
            "sector_fintech", "sector_logistics", "sector_mobile", "sector_cloud_uce",
            "network_history", "threat_intel", "forensic_pcap", "chain_of_custody",
            "immutable_storage", "digital_signatures", "crypto_hashes", "kernel_contextual",
            "executive_dashboard", "continuous_monitoring", "ndr_investigate",
        ],
        "kernel_summary": (
            "Incluye protección sectorial (Fintech, Logística, Móvil vía ASPE), historial de redes, "
            "inteligencia de amenazas, captura PCAP forense, cadena de custodia Ed25519/SHA-256 "
            "y automatización avanzada."
        ),
        "ideal_for": "Empresas con cumplimiento, historial multi-red y evidencia forense verificable.",
    },
    {
        "id": "enterprise",
        "legacy_id": "ELITE",
        "name": "Enterprise",
        "price_min_usd": 700,
        "price_max_usd": 2000,
        "price_label": "USD 700–2.000+ / equipo / mes",
        "client_type": "Grandes organizaciones, MSSP y operaciones SOC maduras",
        "endpoints_label": "200+ equipos / operación multi-tenant con APIs empresariales",
        "icon": "fa-landmark",
        "color": "#f59e0b",
        "includes_plan": "business",
        "capabilities": [
            "m365_oauth", "google_oauth", "enterprise_api", "sector_policies",
            "forensic_vault", "endpoint_management", "incident_automation",
            "enterprise_data", "siem_internal", "tenant_scope",
        ],
        "kernel_summary": (
            "Capacidades empresariales verificadas: OAuth M365/Google, APIs REST completas, "
            "políticas sectoriales, bóveda forense, gestión de endpoints, automatización de "
            "incidentes, arquitectura enterprise y SIEM interno NOVUS."
        ),
        "ideal_for": "Organizaciones que integran NOVUS vía API, OAuth corporativo y operación SOC.",
    },
]

ADDON_SERVICES: List[Dict[str, Any]] = [
    {
        "id": "mail_shield",
        "name": "NOVUS Mail Shield",
        "status": "active",
        "description": "Motor de correo con sync OAuth Gmail y Microsoft 365, cuarentena y eventos.",
        "benefit": "Protección contra phishing, BEC y adjuntos maliciosos en buzones conectados.",
        "requirements": "OAuth Google o Azure configurado; buzón del usuario.",
        "plans": ["professional", "business", "enterprise"],
        "service": "mail_shield_engine",
    },
    {
        "id": "web_shield",
        "name": "NOVUS Web Shield",
        "status": "active",
        "description": "Auditoría de navegación, descargas, análisis URL y host audit en el nodo.",
        "benefit": "Detección de enlaces maliciosos y archivos descargados sospechosos.",
        "requirements": "Nodo NOVUS en el host del usuario.",
        "plans": ["essential", "professional", "business", "enterprise"],
        "service": "web_shield_engine",
    },
    {
        "id": "mobile_shield",
        "name": "NOVUS Mobile Shield",
        "status": "planned",
        "description": "Arquitectura reservada — agente móvil futuro (shield_platform_registry).",
        "benefit": "Protección dedicada de apps móviles (no operativo aún).",
        "requirements": "Implementación futura.",
        "plans": [],
        "service": "shield_platform_registry (planned)",
        "note": "Sector móvil parcial vía ASPE/UI Shield en plan Business.",
    },
    {
        "id": "cloud_shield",
        "name": "NOVUS Cloud Shield",
        "status": "planned",
        "description": "CSPM cloud planificado; detección local vía UCE disponible.",
        "benefit": "Visibilidad cloud completa pendiente de implementación.",
        "requirements": "UCE operativo; Cloud Shield CSPM no operativo.",
        "plans": ["business"],
        "service": "universal_compatibility_engine (parcial)",
    },
    {
        "id": "fintech_shield",
        "name": "NOVUS Fintech Shield",
        "status": "active",
        "description": "Protección sectorial Fintech vía ASPE y Sector Shield.",
        "benefit": "Reglas y baseline adaptados al sector financiero.",
        "requirements": "Sector Fintech en perfil de usuario.",
        "plans": ["business", "enterprise"],
        "service": "adaptive_sector_protection_engine",
    },
    {
        "id": "logistics_shield",
        "name": "NOVUS Logistics Shield",
        "status": "active",
        "description": "Protección sectorial Logística vía ASPE.",
        "benefit": "Monitoreo adaptado a cadena de suministro e IoT local.",
        "requirements": "Sector Logística en perfil.",
        "plans": ["business", "enterprise"],
        "service": "sector_shield_service",
    },
    {
        "id": "threat_intelligence",
        "name": "NOVUS Threat Intelligence",
        "status": "active",
        "description": "Centro de inteligencia con casos, timeline y dashboard operativo.",
        "benefit": "Correlación y recomendaciones basadas en telemetría real.",
        "requirements": "Datos de motores con eventos verificables.",
        "plans": ["business", "enterprise"],
        "service": "threat_intelligence_service",
    },
    {
        "id": "forensic_vault",
        "name": "NOVUS Forensic Vault",
        "status": "active",
        "description": "Ledger append-only, firmas Ed25519, hashes SHA-256 y verificador.",
        "benefit": "Cadena de custodia e integridad demostrable de evidencias.",
        "requirements": "Eventos de motores registrados en defense registry.",
        "plans": ["professional", "business", "enterprise"],
        "service": "forensic_evidence_integrity_service",
    },
    {
        "id": "consultoria",
        "name": "Consultoría en Ciberseguridad",
        "status": "commercial",
        "description": "Servicio comercial de acompañamiento (no módulo software).",
        "benefit": "Asesoría humana complementaria a la plataforma.",
        "requirements": "Contrato comercial externo a NOVUS.",
        "plans": ["enterprise"],
    },
    {
        "id": "incident_response",
        "name": "Respuesta a Incidentes",
        "status": "commercial",
        "description": "Servicio comercial de respuesta (playbooks y remediación automatizada sí existen en software).",
        "benefit": "Equipo humano para incidentes críticos.",
        "requirements": "Contrato comercial; automatización vía playbooks incluida en Professional+.",
        "plans": ["enterprise"],
    },
    {
        "id": "security_audits",
        "name": "Auditorías de Seguridad",
        "status": "active",
        "description": "Auditoría integral automatizada en plataforma (`integral_security_audit_service`).",
        "benefit": "Informe de fuentes de datos y hallazgos verificables.",
        "requirements": "Plan Professional o superior.",
        "plans": ["professional", "business", "enterprise"],
        "service": "integral_security_audit_service",
    },
    {
        "id": "training",
        "name": "Capacitación Empresarial",
        "status": "commercial",
        "description": "Servicio comercial de formación (no módulo software).",
        "benefit": "Capacitación de administradores y analistas.",
        "requirements": "Contrato comercial externo.",
        "plans": ["enterprise"],
    },
]

# Capacidades solicitadas en Enterprise pero NO implementadas (solo auditoría / UI footnote)
ENTERPRISE_NOT_IMPLEMENTED: List[Dict[str, str]] = [
    {"name": "Administración multisede", "reason": "Tenant scope existe; gestión multisede centralizada no implementada."},
    {"name": "Alta disponibilidad", "reason": "Despliegue actual: Flask dev server monolítico."},
    {"name": "Integración Active Directory", "reason": "Auth SQLite local; sin LDAP/AD."},
    {"name": "Integración SIEM externa", "reason": "SIEM interno `/siem` existe; conectores Splunk/QRadar no implementados."},
    {"name": "Threat Hunting dedicado", "reason": "Investigación NDR/manual existe; módulo hunting no dedicado."},
    {"name": "Soporte prioritario 24/7", "reason": "Servicio comercial, no módulo software."},
    {"name": "Capacitación incluida", "reason": "Servicio comercial externo."},
]


def _cap_label(cap_id: str) -> str:
    labels = {
        "dashboard": "Dashboard operativo",
        "kernel_ia": "Kernel IA (consultas y asistente)",
        "auto_scan": "Escaneo automático (red y amenazas)",
        "manual_scan": "Escaneo manual (Centro de Defensa)",
        "centro_defensa": "Centro de Defensa Manual",
        "reports_pdf": "Reportes PDF",
        "historial": "Historial de dispositivos",
        "xdr": "XDR — detección en el host",
        "ndr": "NDR — radar de red",
        "malware": "Protección contra malware",
        "ransomware": "Protección contra ransomware",
        "brute_force": "Protección contra fuerza bruta",
        "web_shield_basic": "Web Shield básico",
        "web_shield_advanced": "Web Shield avanzado (URL, host audit)",
        "mail_shield": "Mail Shield (OAuth)",
        "phishing": "Protección contra phishing",
        "bec": "Protección BEC",
        "link_protection": "Protección de enlaces",
        "attachment_protection": "Protección de adjuntos",
        "domain_reputation": "Reputación de dominios",
        "deep_scan": "Escaneo profundo del equipo",
        "host_scan_processes": "Escaneo de procesos",
        "host_scan_memory": "Escaneo de memoria",
        "host_scan_services": "Escaneo de servicios",
        "host_scan_registry": "Escaneo del registro (Windows)",
        "playbooks": "Playbooks y automatización",
        "cryptovault": "CryptoVault / Defense Registry",
        "forensic_integrity": "Integridad de evidencias",
        "security_audit": "Auditoría de seguridad integral",
        "executive_reports": "Reportes ejecutivos SOC",
        "sector_fintech": "Protección sector Fintech (ASPE)",
        "sector_logistics": "Protección sector Logística",
        "sector_mobile": "Protección Apps Móviles (ASPE/UI Shield)",
        "sector_cloud_uce": "Detección infra cloud (UCE; CSPM planificado)",
        "network_history": "Historial de redes",
        "threat_intel": "Inteligencia de amenazas",
        "forensic_pcap": "Captura forense PCAP",
        "chain_of_custody": "Cadena de custodia",
        "immutable_storage": "Almacenamiento inmutable (ledger)",
        "digital_signatures": "Firmas digitales Ed25519",
        "crypto_hashes": "Hashes criptográficos SHA-256",
        "kernel_contextual": "IA contextual (Kernel Coordinator)",
        "executive_dashboard": "Dashboard ejecutivo",
        "continuous_monitoring": "Monitoreo continuo",
        "ndr_investigate": "Investigación profunda NDR",
        "m365_oauth": "Integración Microsoft 365 (OAuth Mail)",
        "google_oauth": "Integración Google Workspace (OAuth)",
        "enterprise_api": "API empresarial REST",
        "sector_policies": "Gestión de políticas sectoriales",
        "forensic_vault": "Forensic Vault",
        "endpoint_management": "Gestión de endpoints (scan/cuarentena)",
        "incident_automation": "Automatización de respuesta a incidentes",
        "enterprise_data": "Arquitectura de datos enterprise",
        "siem_internal": "SIEM interno NOVUS",
        "alerts": "Centro de alertas",
        "evidence_center": "Centro de evidencias",
        "tenant_scope": "Alcance multi-tenant",
    }
    return labels.get(cap_id, cap_id.replace("_", " ").title())


def _resolve_plan_capabilities(plan: Dict[str, Any]) -> List[str]:
    caps: List[str] = list(plan.get("capabilities") or [])
    inc = plan.get("includes_plan")
    if inc:
        parent = get_plan(inc)
        if parent:
            caps = _resolve_plan_capabilities(parent) + caps
    return caps


def get_plan(plan_id: str) -> Optional[Dict[str, Any]]:
    key = (plan_id or "").lower().strip()
    for p in PLANS:
        if p["id"] == key or p.get("legacy_id", "").lower() == key:
            return p
    return None


def build_plan_payload(plan_id: str) -> Optional[Dict[str, Any]]:
    plan = get_plan(plan_id)
    if not plan:
        return None
    cap_ids = _resolve_plan_capabilities(plan)
    features = []
    for cid in cap_ids:
        meta = CAPABILITY_INDEX.get(cid, {})
        features.append({
            "id": cid,
            "label": _cap_label(cid),
            "verified": True,
            "module": meta.get("module"),
            "route": meta.get("route"),
            "service": meta.get("service"),
            "note": meta.get("note"),
        })
    return {
        **plan,
        "features": features,
        "feature_count": len(features),
    }


def get_catalog_payload() -> Dict[str, Any]:
    return {
        "status": "success",
        "plans": [build_plan_payload(p["id"]) for p in PLANS],
        "addons": ADDON_SERVICES,
        "enterprise_not_implemented": ENTERPRISE_NOT_IMPLEMENTED,
        "disclaimer": (
            "Precios orientativos comerciales. Capacidades listadas corresponden a módulos "
            "verificados en el código NOVUS. Servicios marcados como planned o commercial "
            "no están operativos como software."
        ),
    }


def compare_plans() -> List[Dict[str, Any]]:
    rows = []
    all_caps: List[str] = []
    for p in PLANS:
        all_caps.extend(_resolve_plan_capabilities(p))
    unique = list(dict.fromkeys(all_caps))
    for cap in unique:
        row = {"capability": _cap_label(cap), "capability_id": cap}
        for p in PLANS:
            row[p["id"]] = cap in _resolve_plan_capabilities(p)
        rows.append(row)
    return rows


def explain_plan_for_kernel(plan_id: str, question: str = "") -> Dict[str, Any]:
    """Explicación verificable para Kernel IA / UI pública (sin inventar capacidades)."""
    plan = build_plan_payload(plan_id)
    if not plan:
        return {"status": "error", "message": f"Plan desconocido: {plan_id}"}

    others = [p for p in PLANS if p["id"] != plan_id]
    diff_lines = []
    my_caps = set(_resolve_plan_capabilities(get_plan(plan_id) or {}))
    for op in others:
        op_caps = set(_resolve_plan_capabilities(op))
        only_mine = my_caps - op_caps
        only_other = op_caps - my_caps
        if only_other - my_caps:
            diff_lines.append(
                f"Frente a {op['name']}: usted incluye {_cap_label(list(only_mine)[0]) if only_mine else 'base'}; "
                f"{op['name']} añade {len(only_other - my_caps)} capacidades adicionales verificadas."
            )

    q = (question or "").lower()
    focus = ""
    if "diferencia" in q or "compar" in q:
        focus = " ".join(diff_lines[:3]) if diff_lines else "Compare la tabla de planes en la UI."
    elif "empresa" in q or "beneficia" in q:
        focus = plan.get("ideal_for", "")
    else:
        focus = plan.get("kernel_summary", "")

    return {
        "status": "success",
        "plan_id": plan_id,
        "plan_name": plan["name"],
        "price_label": plan["price_label"],
        "client_type": plan["client_type"],
        "includes": [f["label"] for f in plan.get("features", [])],
        "feature_count": plan.get("feature_count", 0),
        "ideal_for": plan.get("ideal_for"),
        "summary": plan.get("kernel_summary"),
        "comparison_hint": diff_lines,
        "answer": focus or plan.get("kernel_summary"),
        "verified_only": True,
    }


def build_kernel_consult_prompt(plan_id: Optional[str] = None) -> str:
    pid = plan_id or "essential"
    exp = explain_plan_for_kernel(pid)
    lines = [
        f"Plan NOVUS: {exp.get('plan_name')} ({exp.get('price_label')}).",
        f"Tipo de cliente: {exp.get('client_type')}.",
        f"Ideal para: {exp.get('ideal_for')}.",
        f"Resumen: {exp.get('summary')}.",
        "Capacidades verificadas incluidas:",
    ]
    for label in exp.get("includes", [])[:25]:
        lines.append(f"- {label}")
    if len(exp.get("includes", [])) > 25:
        lines.append(f"... y {len(exp['includes']) - 25} más.")
    lines.append(
        "Responde en español. Usa únicamente esta información verificada. "
        "No prometas Active Directory, alta disponibilidad, Mobile/Cloud Shield completos "
        "ni soporte 24/7 si no están en la lista."
    )
    if exp.get("comparison_hint"):
        lines.append("Diferencias: " + "; ".join(exp["comparison_hint"][:2]))
    return "\n".join(lines)
