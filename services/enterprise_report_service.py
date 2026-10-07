"""
Enterprise Report Service — informes técnicos y ejecutivos con datos reales de motores NOVUS.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger

NO_DATA = "Sin datos disponibles"
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "reports")
REPORT_VERSION = "2.0"
CLASSIFICATION = "CONFIDENCIAL — USO INTERNO"

SECTION_KEYS = {
    "general": "Estado general",
    "red": "Red",
    "vulnerabilidades": "Vulnerabilidades",
    "incidentes": "Incidentes",
    "topology": "Topology",
    "endpoints": "Endpoints",
    "sistema": "Sistema",
    "kernel": "Kernel IA",
    "completo": "Reporte completo",
}

ALL_SECTIONS = list(SECTION_KEYS.keys())


def _now() -> datetime:
    return datetime.now()


def _resolve_sections(selected: Optional[List[str]]) -> List[str]:
    if not selected or "completo" in selected:
        return ["general", "red", "vulnerabilidades", "incidentes", "topology", "endpoints", "sistema"]
    return [s for s in selected if s in SECTION_KEYS and s != "completo"]


def _client_context(user_email: Optional[str] = None) -> dict:
    empresa = NO_DATA
    sector = NO_DATA
    try:
        if user_email:
            from database import SessionLocal, Usuario
            from services.sector_profile_service import get_kernel_context_for_user
            db = SessionLocal()
            try:
                user = db.query(Usuario).filter(Usuario.email == user_email).first()
                if user:
                    empresa = user.nit_pyme or user.email.split("@")[0]
                    sector = user.sector or NO_DATA
            finally:
                db.close()
            ctx = get_kernel_context_for_user(user_email)
            if ctx.get("sector_label"):
                sector = ctx["sector_label"]
    except Exception as exc:
        logger.debug("client context: %s", exc)
    return {"empresa": empresa, "sector": sector, "generado_por": user_email or "operador NOVUS"}


def _collect_general() -> dict:
    try:
        from services.novus_security_integration import novus_security
        vuln_result = novus_security.scan_vulnerabilities(force=True)
        if isinstance(vuln_result, dict):
            activas = vuln_result.get("activas") or []
            resueltas = vuln_result.get("resueltas_historial") or []
        else:
            activas = vuln_result or []
            resueltas = []
        threats = novus_security.detect_threats_realtime(force=True)
        proc_count = len(threats.get("suspicious_processes") or [])
    except Exception as exc:
        logger.error("collect general: %s", exc)
        activas, resueltas, proc_count = [], [], 0

    risk_order = {"Crítico": 4, "Alto": 3, "Medio": 2, "Bajo": 1}
    max_risk = "Bajo"
    for v in activas:
        sev = str(v.get("impacto_nivel") or v.get("severidad") or "Medio")
        for label, score in risk_order.items():
            if label.lower() in sev.lower() or sev.lower() in label.lower():
                if score > risk_order.get(max_risk, 0):
                    max_risk = label
                break

    if proc_count > 0 and max_risk in ("Bajo", "Medio"):
        max_risk = "Alto"
    if len(activas) >= 5:
        max_risk = "Alto" if max_risk != "Crítico" else max_risk

    conf_values = [v.get("confianza_porcentaje") for v in activas if isinstance(v.get("confianza_porcentaje"), (int, float))]
    confianza = round(sum(conf_values) / len(conf_values)) if conf_values else NO_DATA

    return {
        "estado_general": "Atención requerida" if activas or proc_count else "Estable",
        "nivel_riesgo": max_risk,
        "nivel_confianza": f"{confianza}%" if confianza != NO_DATA else NO_DATA,
        "vulnerabilidades_activas": len(activas),
        "vulnerabilidades_resueltas": len(resueltas),
        "amenazas_activas": proc_count,
        "incidentes_activos": proc_count,
        "motores": ["novus_security_integration", "vulnerability_analyst_service"],
    }


def _collect_network() -> dict:
    try:
        from services.topology_service import build_topology_payload
        topo = build_topology_payload(force_refresh=False)
        return {
            "dispositivos": topo.get("summary", {}).get("device_count", 0),
            "desconocidos": topo.get("summary", {}).get("unknown_count", 0),
            "criticos": topo.get("summary", {}).get("critical_count", 0),
            "gateway": topo.get("summary", {}).get("gateway", NO_DATA),
            "alertas_ndr": topo.get("summary", {}).get("alert_count", 0),
            "nodos": topo.get("nodes") or [],
            "motores": topo.get("motors") or [],
        }
    except Exception as exc:
        logger.error("collect network: %s", exc)
        return {"dispositivos": 0, "nodos": [], "motores": []}


def _collect_vulnerabilities() -> dict:
    try:
        from services.novus_security_integration import novus_security
        from services.vulnerability_analyst_service import enrich_findings
        result = novus_security.scan_vulnerabilities(force=True)
        if isinstance(result, dict):
            activas = enrich_findings(result.get("activas") or [])
            resueltas = result.get("resueltas_historial") or []
        else:
            activas = enrich_findings(result or [])
            resueltas = []
        return {"activas": activas, "resueltas": resueltas, "total_activas": len(activas)}
    except Exception as exc:
        logger.error("collect vulnerabilities: %s", exc)
        return {"activas": [], "resueltas": [], "total_activas": 0}


def _collect_incidents() -> dict:
    try:
        from services.novus_security_integration import novus_security
        threats = novus_security.detect_threats_realtime(force=True)
        procs = threats.get("suspicious_processes") or []
        return {"incidentes": procs, "total": len(procs), "motores": ["advanced_detector.scan_running_processes"]}
    except Exception as exc:
        return {"incidentes": [], "total": 0}


def _collect_endpoints() -> dict:
    try:
        import psutil
        from utils.host_data import get_local_ip
        return {
            "hostname": socket.gethostname(),
            "ip": get_local_ip() or NO_DATA,
            "cpu_percent": psutil.cpu_percent(interval=0.3),
            "ram_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage("/").percent if os.name != "nt" else psutil.disk_usage("C:\\").percent,
            "procesos_activos": len(psutil.pids()),
            "motores": ["psutil", "system_monitor"],
        }
    except Exception as exc:
        logger.debug("collect endpoints: %s", exc)
        return {"hostname": socket.gethostname(), "motores": ["psutil"]}


def _collect_system() -> dict:
    try:
        import psutil
        boot = datetime.fromtimestamp(psutil.boot_time())
        uptime_h = round((datetime.now() - boot).total_seconds() / 3600, 1)
        net = psutil.net_io_counters()
        return {
            "uptime_horas": uptime_h,
            "bytes_enviados": net.bytes_sent if net else NO_DATA,
            "bytes_recibidos": net.bytes_recv if net else NO_DATA,
            "motores": ["psutil.net_io_counters"],
        }
    except Exception:
        return {}


def _build_charts(general: dict, vulns: dict, network: dict, endpoints: dict, system: dict = None) -> dict:
    system = system or {}
    activas = vulns.get("activas") or []
    risk_dist: Dict[str, int] = {"Crítico": 0, "Alto": 0, "Medio": 0, "Bajo": 0, "Informativo": 0}
    for v in activas:
        sev = str(v.get("impacto_nivel") or "Medio")
        matched = False
        for k in risk_dist:
            if k.lower() in sev.lower():
                risk_dist[k] += 1
                matched = True
                break
        if not matched:
            risk_dist["Medio"] += 1

    resueltas = vulns.get("resueltas") or []
    return {
        "distribucion_riesgos": risk_dist,
        "estado_infraestructura": {
            "dispositivos_monitoreados": network.get("dispositivos", 0),
            "endpoints_activos": 1,
            "vulnerabilidades_activas": general.get("vulnerabilidades_activas", 0),
            "amenazas": general.get("amenazas_activas", 0),
        },
        "evolucion_vulnerabilidades": {
            "activas": len(activas),
            "resueltas": len(resueltas),
            "corregidas_historial": len(resueltas),
        },
        "uso_recursos": {
            "cpu": endpoints.get("cpu_percent", NO_DATA),
            "ram": endpoints.get("ram_percent", NO_DATA),
            "disco": endpoints.get("disk_percent", NO_DATA),
        },
        "dispositivos_por_riesgo": {
            "criticos": network.get("criticos", 0),
            "desconocidos": network.get("desconocidos", 0),
        },
        "trafico_host": {
            "bytes_enviados_mb": round(system.get("bytes_enviados", 0) / 1_048_576, 1) if isinstance(system.get("bytes_enviados"), int) else NO_DATA,
            "bytes_recibidos_mb": round(system.get("bytes_recibidos", 0) / 1_048_576, 1) if isinstance(system.get("bytes_recibidos"), int) else NO_DATA,
        },
    }


def _build_history_evolution(vulns: dict, previous_reports: List[dict]) -> dict:
    resueltas = vulns.get("resueltas") or []
    return {
        "informes_anteriores": len(previous_reports),
        "vulnerabilidades_corregidas": len(resueltas),
        "mejoras": [
            f"{len(resueltas)} hallazgo(s) verificado(s) como RESUELTA en historial NOVUS"
        ] if resueltas else ["Sin remediaciones verificadas en el historial reciente."],
        "riesgo_tendencia": "Reducción" if resueltas and not vulns.get("activas") else "Estable" if not vulns.get("activas") else "Requiere atención",
    }


def _finding_to_technical(finding: dict) -> dict:
    from services.security_report_service import _build_technical_sections
    tech = _build_technical_sections(finding)
    hist = finding.get("historial") or {}
    rems = hist.get("remediations") or hist.get("remediaciones") or []
    auto_actions = [r.get("method") for r in rems if r.get("method")]
    return {
        "id": finding.get("id"),
        "descripcion": finding.get("descripcion_sencilla") or tech.get("descripcion_tecnica"),
        "evidencia": tech.get("evidencias") or [json.dumps(finding.get("evidencia") or {}, ensure_ascii=False)],
        "motor": finding.get("motor") or tech.get("motor") or NO_DATA,
        "confianza": finding.get("confianza_etiqueta") or tech.get("nivel_confianza") or NO_DATA,
        "confianza_porcentaje": finding.get("confianza_porcentaje", NO_DATA),
        "riesgo": finding.get("impacto_nivel") or tech.get("riesgo_sistema") or NO_DATA,
        "fecha": finding.get("fecha") or NO_DATA,
        "hora": finding.get("hora") or NO_DATA,
        "estado": finding.get("estado") or tech.get("estado") or "Activo",
        "impacto": finding.get("impacto_potencial") or tech.get("consecuencias") or NO_DATA,
        "recomendaciones": tech.get("recomendaciones") or [],
        "acciones_automaticas": auto_actions or tech.get("acciones_automaticas") or [],
        "acciones_manuales_pendientes": finding.get("acciones_cliente") or [],
    }


def _build_executive_summary(general: dict, vulns: dict, network: dict, sections: List[str]) -> dict:
    activas = vulns.get("activas") or []
    top = activas[0] if activas else None
    main_problem = NO_DATA
    if top:
        main_problem = f"{top.get('nombre') or top.get('id')} — {top.get('impacto_nivel') or 'Riesgo detectado'}"

    rec = "Mantener monitoreo continuo y revisar informes periódicos."
    if activas:
        rec = f"Priorizar remediación de {activas[0].get('nombre') or activas[0].get('id')} ({activas[0].get('impacto_nivel')})."
    elif general.get("amenazas_activas", 0) > 0:
        rec = "Investigar procesos sospechosos detectados por el motor XDR."

    return {
        "estado_general": general.get("estado_general", NO_DATA),
        "problema_mas_importante": main_problem,
        "vulnerabilidades": general.get("vulnerabilidades_activas", 0),
        "incidentes": general.get("incidentes_activos", 0),
        "amenazas": general.get("amenazas_activas", 0),
        "dispositivos_monitoreados": network.get("dispositivos", 0),
        "recomendacion_principal": rec,
        "nivel_seguridad": general.get("nivel_riesgo", NO_DATA),
        "texto_ejecutivo": (
            f"El estado general de seguridad es {general.get('estado_general', NO_DATA)} "
            f"con nivel de riesgo {general.get('nivel_riesgo', NO_DATA)}. "
            f"Se detectaron {general.get('vulnerabilidades_activas', 0)} vulnerabilidad(es) activa(s), "
            f"{general.get('amenazas_activas', 0)} amenaza(s) y {network.get('dispositivos', 0)} dispositivo(s) en la red. "
            f"Recomendación: {rec}"
        ),
    }


def build_enterprise_report(
    sections: Optional[List[str]] = None,
    user_email: Optional[str] = None,
) -> dict:
    """Genera informe empresarial completo desde motores reales."""
    from services.security_report_service import list_reports, save_report

    now = _now()
    report_id = f"RPT-{now.strftime('%Y%m%d%H%M%S')}"
    selected = _resolve_sections(sections)
    client = _client_context(user_email)

    general = _collect_general() if "general" in selected or not selected else {}
    network = _collect_network() if any(s in selected for s in ("red", "topology", "general")) else {}
    vulns = _collect_vulnerabilities() if "vulnerabilidades" in selected or "general" in selected else {"activas": [], "resueltas": []}
    incidents = _collect_incidents() if "incidentes" in selected or "general" in selected else {"incidentes": [], "total": 0}
    endpoints = _collect_endpoints() if any(s in selected for s in ("endpoints", "sistema", "general")) else {}
    system = _collect_system() if "sistema" in selected or "general" in selected else {}

    previous = list_reports(limit=50)
    charts = _build_charts(general, vulns, network, endpoints, system)
    history = _build_history_evolution(vulns, previous)
    executive = _build_executive_summary(general, vulns, network, selected)

    technical_details = [_finding_to_technical(f) for f in (vulns.get("activas") or [])]

    report = {
        "id": report_id,
        "report_type": "enterprise",
        "version": REPORT_VERSION,
        "classification": CLASSIFICATION,
        "metadata": {
            **client,
            "fecha": now.strftime("%Y-%m-%d"),
            "hora": now.strftime("%H:%M:%S"),
            "hostname": socket.gethostname(),
            "secciones_incluidas": [SECTION_KEYS.get(s, s) for s in selected],
        },
        "cover": {
            "titulo": "Informe de Seguridad NOVUS",
            "subtitulo": "Plataforma Empresarial de Ciberseguridad",
            "empresa": client["empresa"],
            "sector": client["sector"],
            "fecha": now.strftime("%Y-%m-%d"),
            "hora": now.strftime("%H:%M:%S"),
            "resumen_ejecutivo_breve": executive.get("texto_ejecutivo", ""),
            "nivel_seguridad": executive.get("nivel_seguridad", NO_DATA),
        },
        "executive_summary": executive,
        "general_status": general,
        "sections": {
            "red": network if "red" in selected or "topology" in selected else None,
            "topology": network if "topology" in selected else None,
            "vulnerabilidades": vulns if "vulnerabilidades" in selected else None,
            "incidentes": incidents if "incidentes" in selected else None,
            "endpoints": endpoints if "endpoints" in selected else None,
            "sistema": system if "sistema" in selected else None,
        },
        "charts": charts,
        "history_evolution": history,
        "technical_details": technical_details,
        "findings_count": len(technical_details),
        "tipo": "Informe Empresarial",
        "fecha": now.strftime("%Y-%m-%d %H:%M:%S"),
        "severidad": general.get("nivel_riesgo", "Medio"),
        "estado": general.get("estado_general", "Generado"),
        "equipo_afectado": socket.gethostname(),
        "resumen_ejecutivo": executive.get("texto_ejecutivo", ""),
        "conclusiones": executive.get("recomendacion_principal", ""),
        "technical": {"hallazgos": technical_details},
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
    }

    content_for_hash = json.dumps({k: v for k, v in report.items() if k != "signature"}, sort_keys=True, ensure_ascii=False)
    integrity = hashlib.sha256(content_for_hash.encode("utf-8")).hexdigest()
    report["signature"] = {
        "generado_por": "NOVUS Security Platform",
        "fecha": now.strftime("%Y-%m-%d"),
        "hora": now.strftime("%H:%M:%S"),
        "version": REPORT_VERSION,
        "integridad_sha256": integrity,
        "operador": client.get("generado_por"),
    }

    save_report(report)
    logger.info(f"Enterprise report generated: {report_id} sections={selected}")
    return report


def answer_kernel_query(question: str, user_email: Optional[str] = None) -> Optional[str]:
    q = (question or "").lower()
    triggers = (
        "genera un reporte", "genera reporte", "generar reporte", "generar informe",
        "reporte de hoy", "reporte ejecutivo", "reporte de vulnerabilidades",
        "reporte de la red", "reporte completo", "informe de hoy", "informe ejecutivo",
    )
    if not any(k in q for k in triggers):
        return None

    sections = ["general"]
    if "ejecutivo" in q:
        sections = ["general", "vulnerabilidades"]
    elif "vulnerabilidad" in q:
        sections = ["vulnerabilidades"]
    elif "red" in q or "network" in q or "topolog" in q:
        sections = ["red", "topology"]
    elif "completo" in q:
        sections = ["completo"]

    report = build_enterprise_report(sections=sections, user_email=user_email)
    return (
        f"Informe generado: {report['id']}\n"
        f"Tipo: {report['tipo']} | Riesgo: {report['severidad']}\n"
        f"Hallazgos técnicos: {report['findings_count']}\n"
        f"Descargue PDF/HTML/JSON/CSV desde Reportes → {report['id']}\n"
        f"Integridad SHA-256: {report['signature']['integridad_sha256'][:16]}..."
    )
