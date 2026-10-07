"""Informes verificables del Centro de Defensa — persistencia vía security_report_service."""
from __future__ import annotations

import socket
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.host_data import get_local_ip
from utils.logger import logger


def _stats_from_result(result: Dict[str, Any], raw: Optional[dict] = None) -> Dict[str, int]:
    raw = raw or result.get("raw_summary") or {}
    stats = raw.get("stats") if isinstance(raw.get("stats"), dict) else {}
    if not stats and isinstance(result.get("evidence"), list):
        for ev in result["evidence"]:
            if isinstance(ev, dict) and ev.get("scan_id"):
                try:
                    from services.deep_scan_engine import deep_scan_engine
                    st = deep_scan_engine.get_status(ev["scan_id"])
                    if st and st.get("stats"):
                        stats = st["stats"]
                except Exception:
                    pass
    return {
        "files_analyzed": int(stats.get("files_analyzed") or stats.get("files_scanned") or 0),
        "processes_analyzed": int(stats.get("processes_analyzed") or stats.get("processes_scanned") or 0),
        "services_analyzed": int(stats.get("services_analyzed") or 0),
    }


def build_manual_defense_report(
    *,
    mechanism_id: str,
    mechanism_title: str,
    category: str,
    result: Dict[str, Any],
    user_email: Optional[str] = None,
    history_id: Optional[str] = None,
    aggregate: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Construye y guarda informe JSON/PDF-indexable. Devuelve report dict."""
    from services.manual_defense_report_builder import build_defense_report_payload
    from services.security_report_service import save_report

    now = datetime.now()
    report_id = f"MDR-{now.strftime('%Y%m%d%H%M%S')}-{mechanism_id[:24]}"
    findings = [f for f in (result.get("findings") or []) if isinstance(f, dict)]
    stats = _stats_from_result(result, result.get("raw_summary"))
    if aggregate:
        stats["mechanisms_run"] = len(aggregate.get("steps") or [])

    defense_report = build_defense_report_payload(
        mechanism_id=mechanism_id,
        mechanism_title=mechanism_title,
        category=category,
        result=result,
        user_email=user_email,
        aggregate=aggregate,
    )

    hostname = socket.gethostname()
    severity = "Alta" if any(
        str(f.get("risk", "")).lower() in ("high", "critical", "alto", "crítico")
        for f in findings
    ) else ("Media" if findings else "Informativa")

    exec_status = result.get("status") or "completed"
    kernel = defense_report.get("kernel_analysis") or {}
    technical = {
        "tipo_vulnerabilidad": f"Análisis manual — {mechanism_title}",
        "fecha_deteccion": result.get("timestamp") or now.strftime("%Y-%m-%d %H:%M:%S"),
        "severidad": severity,
        "que_ocurrio": (
            f"Ejecución del mecanismo {mechanism_id} ({category}). "
            f"Estado: {exec_status}. Elementos analizados: {result.get('analyzed')}."
        ),
        "origen": "Centro de Defensa NOVUS — telemetría local verificable",
        "motores_utilizados": ["manual_defense_center", mechanism_id],
        "evidencias": result.get("evidence") or [],
        "hallazgos": findings[:100],
        "riesgo_sistema": severity,
        "acciones_automaticas": result.get("auto_actions") or [],
        "recomendaciones": result.get("recommendations") or kernel.get("recommendations") or [],
        "limitaciones": result.get("limitations") or defense_report.get("limitations") or [],
        "estadisticas": stats,
        "duracion_segundos": result.get("duration_sec"),
        "operador": user_email,
        "history_id": history_id,
        "nivel_confianza": "Alta" if result.get("evidence") else "Media",
        "observaciones": "Informe generado al finalizar ejecución manual; sin datos simulados.",
        "defense_report": defense_report,
    }
    if aggregate:
        technical["defensa_completa"] = aggregate

    report = {
        "id": report_id,
        "finding_id": history_id or mechanism_id,
        "tipo": "Centro de Defensa",
        "fecha": technical["fecha_deteccion"],
        "severidad": severity,
        "estado": "Completado" if exec_status in ("completed", "ok", "no_data") else exec_status.title(),
        "equipo_afectado": hostname,
        "tiempo_resolucion": f"{result.get('duration_sec', 0)}s",
        "resumen_ejecutivo": defense_report.get("executive_summary")
        or (
            f"{mechanism_title} en {hostname} ({get_local_ip() or 'IP local'}). "
            f"Hallazgos: {len(findings)}."
        ),
        "technical": technical,
        "conclusiones": defense_report.get("conclusion") or "; ".join(result.get("recommendations") or [])[:500]
        or "Sin recomendaciones adicionales.",
        "remediation_log": [],
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
    }
    save_report(report)
    logger.info("Manual defense report saved: %s", report_id)
    return report


def report_exists(report_id: str) -> bool:
    from services.security_report_service import get_report
    return get_report(report_id) is not None
