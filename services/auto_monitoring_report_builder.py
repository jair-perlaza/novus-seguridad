"""
Informe ejecutivo de monitoreo automático post-login — solo datos de análisis real.
Entrega al CEO: continuous_monitoring_orchestrator._persist_report → deliver_report_to_ceo.
"""
from __future__ import annotations

import platform
import socket
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.host_data import format_ip_or_unavailable, get_local_ip


def _na(val: Any, label: str = "No disponible") -> Any:
    if val is None:
        return label
    if isinstance(val, str) and not val.strip():
        return label
    return val


def build_executive_auto_report(
    *,
    user_email: str,
    session_audit_id: str,
    phase1: Dict[str, Any],
    phase2: Optional[Dict[str, Any]] = None,
    deep_scan_report: Optional[Dict[str, Any]] = None,
    motors_activated: Optional[List[str]] = None,
    auto_actions: Optional[List[Dict[str, Any]]] = None,
    analysis_type: str = "Monitoreo automático post-login",
) -> Dict[str, Any]:
    now = datetime.now()
    report_id = f"AUTO-{session_audit_id}"
    hostname = socket.gethostname()
    sys_block = phase1.get("system") or {}
    os_name = sys_block.get("os") or platform.system()
    ip = phase1.get("network", {}).get("local_ip") or format_ip_or_unavailable(get_local_ip())

    p1_started = phase1.get("started_at")
    p1_finished = phase1.get("finished_at")
    duration_sec = phase1.get("duration_sec")
    if phase2 and phase2.get("duration_sec"):
        duration_sec = (duration_sec or 0) + phase2.get("duration_sec")

    stats = {}
    if deep_scan_report:
        stats = deep_scan_report.get("stats") or deep_scan_report.get("scan_stats") or {}
    elif phase2:
        stats = phase2.get("stats") or {}

    findings = []
    for block in (phase1.get("findings") or [], (deep_scan_report or {}).get("findings") or []):
        for f in block:
            if isinstance(f, dict):
                findings.append(f)

    vulns = phase1.get("vulnerabilities") or []
    if deep_scan_report and deep_scan_report.get("vulnerabilities"):
        vulns = list(vulns) + list(deep_scan_report.get("vulnerabilities") or [])

    malware = [f for f in findings if _is_malware_class(f)]
    viruses = [f for f in findings if "virus" in str(f.get("category", "")).lower() or "eicar" in str(f.get("title", "")).lower()]
    iocs = phase1.get("indicators_of_compromise") or []

    risks = _classify_risks(findings, vulns, phase1.get("risks") or [])
    kernel_block = _kernel_narrative(
        phase1, deep_scan_report, motors_activated or [], auto_actions or [], risks,
    )

    executive = {
        "resumen_ejecutivo": phase1.get("executive_summary")
        or _default_summary(findings, vulns, hostname, ip),
        "fecha": now.strftime("%Y-%m-%d"),
        "hora": now.strftime("%H:%M:%S"),
        "usuario": user_email,
        "equipo_analizado": hostname,
        "sistema_operativo": os_name,
        "direccion_ip": ip,
        "tiempo_analisis_seg": duration_sec,
        "tipo_analisis": analysis_type,
        "carpetas_analizadas": stats.get("folders_analyzed", phase1.get("counts", {}).get("folders", "No analizado")),
        "archivos_analizados": stats.get("files_analyzed", phase1.get("counts", {}).get("files", "No analizado")),
        "procesos_analizados": stats.get(
            "processes_analyzed",
            phase1.get("counts", {}).get("processes", len(phase1.get("processes") or [])),
        ),
        "servicios_analizados": stats.get("services_analyzed", "No analizado"),
        "memoria_analizada": phase1.get("memory") or stats.get("memory_note", "No analizado"),
        "registro_analizado": stats.get("registry_analyzed", "No analizado"),
        "programas_instalados": stats.get("programs_analyzed", "No analizado"),
        "tareas_programadas": stats.get("tasks_analyzed", "No analizado"),
        "dispositivos_detectados": phase1.get("network", {}).get("devices_detected", "No disponible"),
        "estado_red": phase1.get("network", {}).get("status", "No disponible"),
        "vulnerabilidades": vulns if vulns else [],
        "virus_encontrados": viruses if viruses else [],
        "malware_encontrado": malware if malware else [],
        "indicadores_compromiso": iocs,
        "riesgos_clasificados": risks,
        "evidencias": phase1.get("evidence") or {},
        "acciones_automaticas": auto_actions or [],
        "kernel_ia": kernel_block,
        "conclusion": _conclusion(findings, vulns, phase2),
        "phase1_completed": bool(phase1.get("finished_at")),
        "phase2_completed": bool(phase2 and phase2.get("status") == "completed"),
        "deep_scan_id": (phase2 or {}).get("scan_id"),
    }

    severity = "Informativo"
    if any(r.get("level") in ("critical", "critico", "high", "alto") for r in risks):
        severity = "Alto"
    elif risks or vulns or malware:
        severity = "Medio"

    report = {
        "id": report_id,
        "finding_id": f"auto-monitor-{session_audit_id}",
        "tipo": analysis_type,
        "fecha": executive["fecha"],
        "severidad": severity,
        "estado": "Completado" if executive["phase2_completed"] else ("Parcial" if executive["phase1_completed"] else "En curso"),
        "equipo_afectado": hostname,
        "tiempo_resolucion": None,
        "resumen_ejecutivo": executive["resumen_ejecutivo"],
        "technical": {"executive_auto_monitoring": executive, "phase1_raw": phase1, "phase2_status": phase2},
        "conclusiones": executive["conclusion"],
        "remediation_log": auto_actions or [],
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "source": "continuous_monitoring_orchestrator",
        "verified": True,
    }
    return report


def _is_malware_class(f: dict) -> bool:
    blob = " ".join(
        str(f.get(k, "")) for k in ("category", "type", "technique", "title", "description", "motor")
    ).lower()
    return any(t in blob for t in ("malware", "minero", "trojan", "ransom", "backdoor", "powershell_malicioso"))


def _classify_risks(findings: List[dict], vulns: List, extra: List) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in extra:
        if isinstance(r, dict):
            out.append({
                "level": r.get("severity", "info"),
                "detail": r.get("detail") or r.get("type"),
                "source": r.get("source", "phase1"),
            })
    for f in findings[:30]:
        risk = f.get("risk") or f.get("severity") or "info"
        out.append({
            "level": risk,
            "detail": f.get("title") or f.get("description") or f.get("reason"),
            "source": f.get("motor") or "finding",
        })
    for v in vulns[:15]:
        if isinstance(v, dict):
            out.append({
                "level": v.get("severidad") or v.get("severity") or "medium",
                "detail": v.get("nombre") or v.get("title") or v.get("id"),
                "source": v.get("fuente") or "vulnerability_scan",
            })
    return out


def _default_summary(findings, vulns, hostname, ip) -> str:
    n_f, n_v = len(findings), len(vulns)
    if n_f == 0 and n_v == 0:
        return (
            f"Análisis automático en {hostname} ({ip}): no se registraron hallazgos críticos "
            "en la fase inicial. El escaneo profundo puede ampliar el inventario."
        )
    return (
        f"Análisis automático en {hostname} ({ip}): {n_f} hallazgo(s) y {n_v} vulnerabilidad(es) "
        "documentadas con evidencia de motores NOVUS."
    )


def _conclusion(findings, vulns, phase2) -> str:
    if phase2 and phase2.get("status") == "completed":
        return (
            "Análisis en dos fases finalizado. Los resultados provienen exclusivamente de motores "
            "locales NOVUS; elementos no escaneados figuran como «No analizado»."
        )
    if phase2 and phase2.get("status") == "running":
        return "Fase 1 completada; escaneo profundo en curso en segundo plano."
    return "Fase 1 completada; escaneo profundo pendiente o no iniciado."


def _kernel_narrative(phase1, deep_report, motors, actions, risks) -> Dict[str, Any]:
    analyzed = []
    if phase1.get("system"):
        analyzed.append("Estado del sistema (CPU/RAM/disco)")
    if phase1.get("processes") is not None:
        analyzed.append("Procesos activos")
    if phase1.get("network"):
        analyzed.append("Red local y dispositivos (caché/escaneo)")
    if deep_report:
        analyzed.append("Escaneo profundo deep_scan_engine")

    found = []
    not_found = ["Amenazas no verificadas permanecen sin registro"]
    if not (phase1.get("findings") or []):
        not_found.append("Sin procesos maliciosos confirmados en fase rápida")
    else:
        found.append(f"{len(phase1.get('findings') or [])} indicador(es) en fase rápida")

    recommendations = []
    if risks:
        recommendations.append("Revisar riesgos clasificados en el informe y validar en Centro de Defensa.")
    else:
        recommendations.append("Mantener monitoreo continuo activo; repetir escaneo ante cambios en la red.")
    if any(r.get("level") in ("high", "alto", "critical", "critico") for r in risks):
        recommendations.insert(0, "Priorizar contención del hallazgo de mayor severidad con evidencia adjunta.")

    return {
        "que_analizo": analyzed or ["No analizado"],
        "que_encontro": found or ["Sin hallazgos confirmados en telemetría disponible"],
        "que_no_encontro": not_found,
        "mecanismos_activados": motors or ["No disponible"],
        "acciones_ejecutadas": actions or [],
        "riesgos_permanecen": [r.get("detail") for r in risks[:10]] or ["Ninguno documentado en esta ejecución"],
        "recomendaciones": recommendations,
        "disclaimer": "Narrativa generada solo desde resultados de motores; no se inventan IOCs.",
    }
