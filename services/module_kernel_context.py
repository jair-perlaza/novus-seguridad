"""
Contexto automático por módulo para el botón «Consultar Kernel IA».
Recopila telemetría real; nunca inventa datos.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from services.telemetry_resolver import explain, is_absent, resolve

MODULE_LABELS = {
    "dashboard": "Dashboard",
    "inteligencia": "Centro de Inteligencia",
    "vulnerabilidades": "Vulnerabilidades",
    "network": "Network",
    "topology": "Topology",
    "endpoints": "Endpoints",
    "reportes": "Reportes",
    "xdr": "XDR / Amenazas",
    "incidentes": "Incidentes",
    "playbooks": "Playbooks / Automatización",
    "configuracion": "Configuración",
    "adaptive_defense": "Adaptive Defense",
    "uce": "Universal Compatibility Engine",
    "aspe": "Adaptive Sector Protection Engine",
    "cryptovault": "CryptoVault",
    "casos_estudio": "Casos de Estudio (NDCI)",
    "auth_protection": "Protección de Acceso",
    "threat_coverage": "Cobertura de Amenazas",
    "manual_defense_center": "Centro de Defensa",
    "historial_seguridad_red": "Historial de Seguridad de Red",
    "verificador_evidencias": "Verificador de Evidencias",
    "membresias": "Membresías y Planes NOVUS",
    "compliance_center": "Compliance Center",
}

CONSULT_INSTRUCTIONS = {
    "dashboard": (
        "Analiza el estado general de seguridad, el principal riesgo, prioridades y recomendaciones "
        "concretas basadas únicamente en el contexto verificado."
    ),
    "inteligencia": (
        "Resume incidentes, tendencias, amenazas, eventos recientes y acciones tomadas. "
        "Indica nivel de confianza y qué requiere atención."
    ),
    "vulnerabilidades": (
        "Analiza cada hallazgo: riesgo, evidencia, causa, impacto, remediación automática y manual, "
        "consecuencias si no se corrige, motores NOVUS activos, Adaptive Defense, confianza y recomendaciones."
    ),
    "network": (
        "Analiza dispositivos, tráfico, anomalías, riesgos, comportamiento, consumo y posibles ataques "
        "según la telemetría NDR disponible."
    ),
    "historial_seguridad_red": (
        "Usa exclusivamente el historial persistente de la red conectada: identificación, sesiones de análisis, "
        "eventos verificados y conclusiones agregadas. No inventes ataques anteriores ni estadísticas sin datos."
    ),
    "verificador_evidencias": (
        "Explica resultados del verificador forense real (hash SHA-256, firma Ed25519, cadena). "
        "Si hay «Integridad comprometida», describe consecuencias y acciones sin inventar incidentes."
    ),
    "topology": (
        "Analiza el dispositivo o la topología de red. Explica: qué dispositivo es, qué función cumple, "
        "riesgos, evidencias, motores de protección activos, Adaptive Defense, vulnerabilidades vinculadas, "
        "nivel de confianza, qué ocurrirá si no se actúa y recomendaciones concretas. "
        "Usa únicamente telemetría verificada del contexto."
    ),
    "endpoints": (
        "Analiza el inventario de endpoints: salud, hallazgos, procesos y exposición."
    ),
    "reportes": (
        "Analiza el informe indicado usando únicamente report_executive_brief del contexto. "
        "No cites nombres de variables internas ni estructuras JSON. "
        "Explica en lenguaje ejecutivo: qué encontró, qué significa, riesgos, prioridad y acciones."
    ),
    "xdr": (
        "Analiza amenazas en tiempo real, procesos sospechosos, severidad y respuesta recomendada."
    ),
    "incidentes": (
        "Analiza incidentes abiertos y cerrados: prioridad, evidencia, timeline y remediación."
    ),
    "playbooks": (
        "Analiza reglas de automatización activas, ejecuciones recientes y efectividad."
    ),
    "configuracion": (
        "Resume configuración de seguridad activa, sector, escudo y recomendaciones de endurecimiento."
    ),
    "casos_estudio": (
        "Analiza casos de estudio NDCI almacenados: riesgos, remediaciones, lecciones aprendidas y comparaciones."
    ),
    "auth_protection": (
        "Analiza intentos de acceso no autorizado: evidencias, origen bloqueado, nivel de confianza, "
        "riesgo, acciones ejecutadas y confirma que el bloqueo afecta solo al origen del ataque."
    ),
    "threat_coverage": (
        "Analiza cobertura real por categoría y sector: qué está implementado, validado en vivo, "
        "limitaciones y riesgos residuales. No asumir protección sin evidencia."
    ),
    "manual_defense_center": (
        "Explica el mecanismo de defensa manual indicado en el contexto: qué hace, amenazas, técnicas, "
        "limitaciones, información necesaria, evidencias y acciones. No inventes IPs, archivos ni hallazgos."
    ),
    "membresias": (
        "Explica los planes de membresía NOVUS usando únicamente el catálogo verificado en contexto: "
        "qué incluye cada plan, precio orientativo, tipo de cliente ideal y diferencias reales. "
        "No prometas Active Directory, alta disponibilidad, Mobile/Cloud Shield completos ni soporte 24/7."
    ),
    "compliance_center": (
        "Explica controles del Compliance Center usando únicamente estados VERIFICADO/NO_VERIFICADO/"
        "PENDIENTE/NO_APLICA y evidencias del contexto. No afirmes certificaciones ni cumplimiento legal completo."
    ),
}


def _safe_json(data: Any, limit: int = 6000) -> str:
    try:
        raw = json.dumps(data, ensure_ascii=False, default=str, indent=0)
        return raw[:limit] + ("…" if len(raw) > limit else "")
    except Exception:
        return str(data)[:limit]


def _ctx_dashboard(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {"module": "dashboard"}
    try:
        from services.dashboard_priority_service import get_current_priority
        ctx["priority"] = get_current_priority(email)
    except Exception as exc:
        ctx["priority_error"] = str(exc)
    try:
        from services.intel_operational_service import collect_operational_data, build_executive_summary
        data = collect_operational_data(email)
        ctx["executive_summary"] = build_executive_summary(data)
    except Exception as exc:
        ctx["summary_error"] = str(exc)
    try:
        from services.sector_shield_service import get_active_shield_status
        ctx["shield"] = get_active_shield_status(email)
    except Exception as exc:
        ctx["shield_error"] = str(exc)
    try:
        from services.system_monitor import system_monitor
        ctx["system"] = system_monitor.get_system_status()
    except Exception as exc:
        ctx["system_error"] = str(exc)
    return ctx


def _ctx_vulnerabilidades(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {"module": "vulnerabilidades", "finding_id": extra.get("finding_id")}
    try:
        from services.novus_security_integration import novus_security
        from services.vulnerability_analyst_service import enrich_findings
        findings = enrich_findings(novus_security.scan_vulnerabilities())
        if extra.get("finding_id"):
            ctx["selected"] = next((f for f in findings if f.get("id") == extra["finding_id"]), None)
        ctx["findings"] = findings[:12]
        ctx["total"] = len(findings)
    except Exception as exc:
        ctx["error"] = str(exc)
    try:
        from services.adaptive_defense_engine import adaptive_defense
        ctx["adaptive_defense"] = adaptive_defense.get_adaptive_defense_panel(email)
    except Exception:
        pass
    try:
        from services.adaptive_sector_protection_engine import aspe
        ctx["aspe"] = aspe.get_sector_protection_panel(email)
    except Exception:
        pass
    return ctx


def _ctx_network(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {"module": "network", "focus_ip": extra.get("ip")}
    try:
        from services.network_ndr_service import build_ndr_payload
        ctx["ndr"] = build_ndr_payload()
    except Exception as exc:
        ctx["ndr_error"] = str(exc)
    try:
        from services.network_scanner import network_scanner
        ctx["nodes"] = network_scanner.get_cached_nodes() or []
    except Exception as exc:
        ctx["nodes_error"] = str(exc)
    try:
        from services.device_connection_monitor import get_recent_connection_summary
        ctx["connection_events"] = get_recent_connection_summary(limit=15)
    except Exception as exc:
        ctx["connection_events_error"] = str(exc)
    return ctx


def _ctx_verificador_evidencias(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    """Kernel IA: solo lectura/análisis — nunca modifica el ledger forense."""
    ctx: Dict[str, Any] = {
        "module": "verificador_evidencias",
        "kernel_policy": "read_only_no_evidence_mutation",
        "modified_evidence": False,
    }
    try:
        from services.forensic_evidence_integrity_service import get_system_summary, run_full_verifier

        ctx["forensic_summary"] = get_system_summary()
        ctx["evidence_basis"] = "verifiable_system_summary"
        if extra.get("run_verify"):
            ctx["verification"] = run_full_verifier(register_incidents=False)
            ctx["evidence_basis"] = "verifiable_cryptographic_verification"
        else:
            ctx["verification_note"] = "Ejecute verificación desde el módulo para resultados completos."
        fid = extra.get("forensic_id")
        if fid:
            from services.forensic_custody_phase1 import kernel_analyze_evidence

            analysis = kernel_analyze_evidence(str(fid))
            ctx["ai_analysis"] = analysis
            ctx["ai_disclaimer"] = analysis.get("ai_disclaimer")
            # Separar claramente evidencia vs hipótesis IA
            ctx["conclusions"] = {
                "from_verifiable_evidence": analysis.get("verification"),
                "from_ai_analysis": {
                    "hypotheses": analysis.get("hypotheses_ai"),
                    "patterns": analysis.get("patterns"),
                    "chronology": analysis.get("chronology_explanation_ai"),
                    "disclaimer": analysis.get("ai_disclaimer"),
                },
            }
    except Exception as exc:
        ctx["error"] = str(exc)[:200]
    return ctx


def _ctx_historial_seguridad_red(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {"module": "historial_seguridad_red"}
    try:
        from services.network_security_history_service import (
            build_kernel_network_insights,
            get_network_history_summary,
        )

        summary = get_network_history_summary()
        ctx["network_history"] = {
            "identification": summary.get("identification"),
            "state": summary.get("state"),
            "disclaimer": summary.get("disclaimer"),
            "first_analysis_at": summary.get("first_analysis_at"),
            "last_analysis_at": summary.get("last_analysis_at"),
            "event_count": summary.get("event_count"),
            "recent_events": (summary.get("recent_events") or [])[:15],
            "analysis_sessions": (summary.get("analysis_sessions") or [])[:10],
        }
        ctx["kernel_history_insights"] = build_kernel_network_insights()
    except Exception as exc:
        ctx["network_history_error"] = str(exc)[:200]
    return ctx


def _ctx_topology(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {"module": "topology"}
    focus_ip = extra.get("ip") or extra.get("node_ip")
    ctx["focus_node"] = focus_ip
    try:
        from services.topology_service import build_topology_payload
        topo = build_topology_payload(force_refresh=False)
        ctx["topology_summary"] = topo.get("summary")
        ctx["digital_twin"] = topo.get("digital_twin")
        ctx["topology_nodes"] = (topo.get("nodes") or [])[:20]
        ctx["topology_connections"] = (topo.get("connections") or [])[:15]
        ctx["topology_alerts"] = (topo.get("alerts") or [])[:8]
    except Exception as exc:
        ctx["topology_error"] = str(exc)
    if focus_ip:
        try:
            from services.topology_service import get_topology_device
            detail = get_topology_device(focus_ip)
            if detail.get("status") == "success":
                ctx["device_panel"] = detail.get("panel")
                ctx["device_detail"] = detail.get("device")
                ctx["device_alerts"] = detail.get("alerts")
                ctx["device_vulnerabilities"] = detail.get("vulnerabilities_related")
                ctx["device_history"] = detail.get("history")
                ctx["device_recommendations"] = detail.get("recommendations")
            else:
                ctx["device_not_found"] = detail.get("message")
        except Exception as exc:
            ctx["device_error"] = str(exc)
    try:
        from services.network_event_log import network_event_log
        ctx["network_events"] = network_event_log.get_recent(10)
    except Exception:
        pass
    return ctx


def _ctx_inteligencia(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {"module": "inteligencia"}
    try:
        from services.intel_operational_service import (
            collect_operational_data,
            build_executive_summary,
            build_operational_brief,
            build_global_timeline,
            analyze_patterns,
        )
        data = collect_operational_data(email)
        ctx["summary"] = build_executive_summary(data)
        ctx["brief"] = build_operational_brief(data)
        ctx["timeline"] = build_global_timeline(data, limit=15)
        ctx["patterns"] = analyze_patterns(data)
        ctx["sources"] = data.get("sources") or []
    except Exception as exc:
        ctx["error"] = str(exc)
    return ctx


def _ctx_xdr(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {"module": "xdr"}
    try:
        from services.novus_security_integration import novus_security
        from services.kernel_threat_explainer import explain_threat

        ctx["threats"] = novus_security.detect_threats_realtime()
        threats = ctx["threats"] if isinstance(ctx["threats"], list) else []
        ctx["threat_explanations"] = [
            explain_threat(t) for t in threats[:10] if isinstance(t, dict)
        ]
        if extra.get("finding_id"):
            sel = next(
                (t for t in threats if str(t.get("id")) == str(extra["finding_id"])),
                None,
            )
            if sel:
                ctx["selected_threat_explanation"] = explain_threat(sel)
    except Exception as exc:
        ctx["error"] = str(exc)
    return ctx


def _ctx_incidentes(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {"module": "incidentes", "incident_id": extra.get("incident_id")}
    try:
        from services.threat_intelligence_service import threat_intelligence
        ctx["cases"] = threat_intelligence.list_cases(limit=20)
        ctx["stats"] = threat_intelligence.stats()
        if extra.get("incident_id"):
            for c in ctx["cases"]:
                if c.get("id") == extra["incident_id"] or str(c.get("finding_id")) == extra["incident_id"]:
                    ctx["selected"] = c
                    break
    except Exception as exc:
        ctx["error"] = str(exc)
    return ctx


def _ctx_endpoints(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {"module": "endpoints"}
    try:
        from services.platform_metrics_service import build_endpoint_inventory
        ctx["inventory"] = build_endpoint_inventory()[:20]
        ctx["total"] = len(ctx["inventory"])
    except Exception as exc:
        ctx["error"] = str(exc)
    try:
        from services.endpoint_scan_engine import endpoint_scan_engine
        from services.endpoint_realtime_monitor import list_monitor_events

        ctx["endpoint_shield"] = endpoint_scan_engine.engine_status()
        ctx["monitor_events"] = list_monitor_events(limit=10)
    except Exception as exc:
        ctx["endpoint_shield_error"] = str(exc)
    return ctx


def _ctx_reportes(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {
        "module": "reportes",
        "report_id": extra.get("report_id"),
        "read_only": bool(extra.get("read_only") or extra.get("report_id")),
    }
    try:
        from services.security_report_service import list_reports, get_report
        from services.report_presentation_service import build_kernel_context_brief

        if extra.get("report_id"):
            report = get_report(extra["report_id"])
            if report:
                ctx["selected_report"] = {
                    "id": report.get("id"),
                    "tipo": report.get("tipo"),
                    "titulo": report.get("titulo") or report.get("title"),
                }
                ctx["report_executive_brief"] = build_kernel_context_brief(report)
        else:
            ctx["reports"] = list_reports(limit=10)
    except Exception as exc:
        ctx["error"] = str(exc)
    return ctx


def _ctx_playbooks(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {"module": "playbooks"}
    try:
        from services.playbook_service import list_playbooks, list_executions
        ctx["playbooks"] = list_playbooks(active_only=False)[:15]
        ctx["executions"] = list_executions(limit=10)
    except Exception as exc:
        ctx["error"] = str(exc)
    return ctx


def _ctx_configuracion(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {"module": "configuracion"}
    try:
        from services.sector_profile_service import get_kernel_context_for_user, get_sector_profile
        from services.sector_shield_service import resolve_sector_for_user
        sk = resolve_sector_for_user(email)
        ctx["sector"] = get_sector_profile(sk)
        ctx["kernel_context"] = get_kernel_context_for_user(email)
    except Exception as exc:
        ctx["error"] = str(exc)
    return ctx


def _ctx_sector_engines(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {}
    try:
        from services.universal_compatibility_engine import uce
        ctx["uce"] = uce.get_infrastructure_panel(email)
    except Exception as exc:
        ctx["uce_error"] = str(exc)
    try:
        from services.adaptive_sector_protection_engine import aspe
        ctx["aspe"] = aspe.get_sector_protection_panel(email)
    except Exception as exc:
        ctx["aspe_error"] = str(exc)
    try:
        from services.adaptive_defense_engine import adaptive_defense
        ctx["adaptive_defense"] = adaptive_defense.get_adaptive_defense_panel(email)
    except Exception as exc:
        ctx["ade_error"] = str(exc)
    return ctx


def _enrich_defense_engines(ctx: Dict[str, Any], email: Optional[str]) -> Dict[str, Any]:
    """UCE, ASPE y Adaptive Defense en todo contexto de consulta."""
    engines = _ctx_sector_engines(email, {})
    for key, val in engines.items():
        if val is not None:
            ctx[key] = val
    return ctx


def _ctx_casos_estudio(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {"module": "casos_estudio"}
    try:
        from services.ndci_service import ndci_service
        ctx["cases"] = ndci_service.list_cases(15)
        case_id = extra.get("case_id")
        if case_id:
            ctx["selected_case"] = ndci_service.get_case(case_id)
    except Exception as exc:
        ctx["error"] = str(exc)
    return ctx


def _ctx_auth_protection(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    try:
        from services.auth_protection_service import auth_protection
        return auth_protection.get_kernel_context(extra.get("incident_id"))
    except Exception as exc:
        return {"module": "auth_protection", "error": str(exc)}


def _ctx_threat_coverage(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    try:
        from services.threat_coverage_service import threat_coverage
        from services.sector_shield_service import resolve_sector_for_user
        sector = extra.get("sector") or resolve_sector_for_user(email)
        ctx = threat_coverage.get_kernel_context()
        ctx["sector_detail"] = threat_coverage.get_sector_coverage(sector)
        return ctx
    except Exception as exc:
        return {"module": "threat_coverage", "error": str(exc)}


def _ctx_compliance_center(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    from services.compliance_center_service import build_profile, evaluate_controls, list_audits
    sector = (extra or {}).get("sector_id") or "otros"
    profile = build_profile(sector_id=sector)
    # evaluación ligera: reutilizar evaluate (es la fuente de verdad)
    evaluation = evaluate_controls(profile=profile, user=None)
    control_id = (extra or {}).get("control_id")
    selected = None
    if control_id:
        selected = next((c for c in evaluation.get("controls", []) if c["id"] == control_id), None)
    return {
        "module": "compliance_center",
        "profile": profile,
        "score": evaluation.get("score"),
        "counts": evaluation.get("counts"),
        "limitations": evaluation.get("limitations"),
        "selected_control": selected,
        "recent_audits": list_audits(limit=5),
        "certification_claim": False,
    }


def _ctx_membresias(email: Optional[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    from services.membership_catalog_service import (
        build_plan_payload,
        explain_plan_for_kernel,
        get_catalog_payload,
    )

    plan_id = (extra or {}).get("plan_id") or (extra or {}).get("plan") or "essential"
    catalog = get_catalog_payload()
    plan = build_plan_payload(plan_id)
    explanation = explain_plan_for_kernel(plan_id, extra.get("question") if extra else "")
    return {
        "module": "membresias",
        "catalog_summary": {
            "plan_count": len(catalog.get("plans") or []),
            "addon_count": len(catalog.get("addons") or []),
        },
        "selected_plan": plan,
        "plan_explanation": explanation,
        "enterprise_gaps": catalog.get("enterprise_not_implemented"),
    }


def _ctx_manual_defense(user_email: Optional[str], extra: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    extra = extra or {}
    try:
        from services.manual_defense_catalog import get_kernel_doc, get_mechanism, audit_capabilities, check_availability
        from services.manual_defense_service import list_history

        mid = extra.get("mechanism_id")
        mech = get_mechanism(mid) if mid else None
        ctx: Dict[str, Any] = {
            "module": "manual_defense_center",
            "audit_summary": audit_capabilities(getattr(user_email, "id", None) if False else None),
            "recent_history": list_history(5),
        }
        if mid:
            ctx["mechanism"] = mech
            ctx["mechanism_doc"] = extra.get("mechanism_doc") or get_kernel_doc(mid)
            if mech:
                ctx["availability"] = check_availability(mech, None)
        try:
            from services.forensic_pcap_capture_service import capture_capability, list_captures

            ctx["forensic_pcap"] = {
                "capability": capture_capability(),
                "recent_captures": list_captures(8),
                "kernel_usage_note": (
                    "El Kernel IA puede citar metadatos de capturas selladas; "
                    "no debe inferir contenido de aplicaciones sin decodificación verificable."
                ),
            }
        except Exception as exc:
            ctx["forensic_pcap_error"] = str(exc)[:160]
        return ctx
    except Exception as exc:
        return {"module": "manual_defense_center", "error": str(exc)}


_BUILDERS = {
    "dashboard": _ctx_dashboard,
    "inteligencia": _ctx_inteligencia,
    "vulnerabilidades": _ctx_vulnerabilidades,
    "network": _ctx_network,
    "historial_seguridad_red": _ctx_historial_seguridad_red,
    "verificador_evidencias": _ctx_verificador_evidencias,
    "topology": _ctx_topology,
    "endpoints": _ctx_endpoints,
    "reportes": _ctx_reportes,
    "xdr": _ctx_xdr,
    "incidentes": _ctx_incidentes,
    "playbooks": _ctx_playbooks,
    "configuracion": _ctx_configuracion,
    "casos_estudio": _ctx_casos_estudio,
    "auth_protection": _ctx_auth_protection,
    "threat_coverage": _ctx_threat_coverage,
    "manual_defense_center": _ctx_manual_defense,
    "centro_defensa_manual": _ctx_manual_defense,
    "centro_defensa": _ctx_manual_defense,
    "membresias": _ctx_membresias,
    "compliance_center": _ctx_compliance_center,
    "adaptive_defense": lambda e, x: {"module": "adaptive_defense", **_ctx_sector_engines(e, x)},
    "uce": lambda e, x: {"module": "uce", **_ctx_sector_engines(e, x)},
    "aspe": lambda e, x: {"module": "aspe", **_ctx_sector_engines(e, x)},
    "cryptovault": _ctx_configuracion,
}


def normalize_module(module: Optional[str]) -> str:
    key = (module or "dashboard").strip().lower()
    aliases = {
        "amenazas": "xdr",
        "automatizacion": "playbooks",
        "": "dashboard",
        "centro_defensa_manual": "manual_defense_center",
        "centro_defensa": "manual_defense_center",
        "historial-seguridad-red": "historial_seguridad_red",
    }
    return aliases.get(key, key)


def build_module_context(
    module: Optional[str],
    user_email: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    extra = extra or {}
    key = normalize_module(module)
    builder = _BUILDERS.get(key, _ctx_dashboard)
    context = builder(user_email, extra)
    context = _enrich_defense_engines(context, user_email)
    try:
        from services.adaptive_profile_engine import enrichment_for_engine

        # Señal compacta interna para Kernel IA (sin dump de baseline)
        context["adaptive_profile"] = enrichment_for_engine(user_email, key)
    except Exception:
        pass
    context["module_key"] = key
    context["module_label"] = MODULE_LABELS.get(key, key.title())
    return context


def build_consult_prompt(
    module: Optional[str],
    user_email: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    from services.ai_kernel_brain.kernel_prompt import get_kernel_brain

    key = normalize_module(module)
    context = build_module_context(key, user_email, extra)
    label = MODULE_LABELS.get(key, key.title())
    instruction = CONSULT_INSTRUCTIONS.get(key, CONSULT_INSTRUCTIONS["dashboard"])
    focus = ""
    if extra and extra.get("finding_id"):
        focus = f"\nEnfócate en el hallazgo: {extra['finding_id']}."
    if extra and (extra.get("ip") or extra.get("node_ip")):
        focus += f"\nNodo/IP de interés: {extra.get('ip') or extra.get('node_ip')}."
    if extra and extra.get("case_id"):
        focus += f"\nCaso de estudio NDCI: {extra['case_id']}."
    if extra and extra.get("incident_id"):
        focus += f"\nIncidente: {extra['incident_id']}."
    if extra and extra.get("report_id"):
        focus += f"\nInforme: {extra['report_id']}."
    prompt = (
        f"{get_kernel_brain().get_prompt_header()}\n\n"
        f"[CONSULTA AUTOMÁTICA — Módulo: {label}]\n"
        f"{instruction}{focus}\n\n"
        f"Responde en español como analista SOC/XDR. Estructura obligatoria:\n"
        f"1) Qué ocurrió (solo hechos del contexto)\n"
        f"2) Por qué ocurrió (causa técnica según evidencia)\n"
        f"3) Evidencia disponible (motores, logs, telemetría)\n"
        f"4) Nivel de riesgo y confianza\n"
        f"5) Mecanismos de defensa activos (ADE, ASPE, UCE, escudo sectorial)\n"
        f"6) Recomendaciones concretas\n"
        f"7) Consecuencias de no actuar\n"
        f"Si falta evidencia, indícalo explícitamente — no inventes.\n\n"
        f"--- CONTEXTO VERIFICADO (telemetría real NOVUS) ---\n"
        f"{_safe_json(context)}\n"
        f"--- FIN CONTEXTO ---"
    )
    return {
        "module": key,
        "module_label": label,
        "context": context,
        "prompt": prompt,
        "system_prompt": get_kernel_brain().get_system_prompt(),
        "greeting": get_kernel_brain().get_time_based_greeting(),
        "has_real_data": _context_has_data(context),
    }


def _context_has_data(context: Dict[str, Any]) -> bool:
    skip = {"module", "module_key", "module_label", "error", "priority_error", "summary_error"}
    for k, v in context.items():
        if k in skip or k.endswith("_error"):
            continue
        if v is None:
            continue
        if isinstance(v, (list, dict)) and len(v) == 0:
            continue
        if is_absent(v):
            continue
        return True
    return False
