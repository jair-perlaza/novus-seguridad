"""
Centro de Reportes NOVUS — catálogo e historiales basados en evidencia verificable.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from utils.logger import logger

NO_EVIDENCE = "Sin evidencia verificable."


def _classify_report(report: dict) -> str:
    tipo = (report.get("tipo") or report.get("report_type") or "").lower()
    rid = (report.get("id") or "").upper()
    if rid.startswith("AUTO-") or "monitoreo" in tipo or "automático" in tipo:
        return "automaticos"
    if "enterprise" in tipo or "empresarial" in tipo:
        return "ejecutivos"
    if "defensa" in tipo or "manual" in tipo:
        return "mecanismos"
    if "incident" in tipo or rid.startswith("INC-"):
        return "incidentes"
    if "vuln" in tipo:
        return "vulnerabilidades"
    return "manuales"


def get_network_history_report() -> Dict[str, Any]:
    """Historial de red — solo datos observados por motores."""
    try:
        from services.network_security_history_service import get_network_history_summary

        summary = get_network_history_summary(schedule_discovery=False)
        ctx = summary.get("network_context") or {}
        events = summary.get("recent_events") or []
        rows: List[Dict[str, Any]] = []
        for e in events:
            ev = e.get("evidence") if isinstance(e.get("evidence"), dict) else {}
            rows.append({
                "fecha_hora": e.get("timestamp") or NO_EVIDENCE,
                "tipo": e.get("event_type") or NO_EVIDENCE,
                "titulo": e.get("title") or NO_EVIDENCE,
                "gateway": ctx.get("gateway") or NO_EVIDENCE,
                "subred": ctx.get("subnet") or NO_EVIDENCE,
                "dispositivos_visibles": ctx.get("visible_devices_count"),
                "motor": e.get("motor") or NO_EVIDENCE,
                "severidad": e.get("severity") or NO_EVIDENCE,
                "evidencia_verificada": ev.get("verified") is True,
                "detalle": ev if ev.get("verified") else NO_EVIDENCE,
            })
        return {
            "disclaimer": summary.get("disclaimer") or NO_EVIDENCE,
            "monitoring_started_at": summary.get("monitoring_started_at"),
            "first_analysis_at": summary.get("first_analysis_at"),
            "last_analysis_at": summary.get("last_analysis_at"),
            "scope_id": summary.get("scope_id"),
            "identification": summary.get("identification") or {},
            "state": summary.get("state") or {},
            "kernel_insights": summary.get("kernel_insights") or {},
            "contexto": {
                "gateway": ctx.get("gateway") or NO_EVIDENCE,
                "subred": ctx.get("subnet") or NO_EVIDENCE,
                "dns": ctx.get("dns_servers") or NO_EVIDENCE,
                "ssid": (summary.get("identification") or {}).get("ssid") or NO_EVIDENCE,
                "public_ip": (summary.get("identification") or {}).get("public_ip") or NO_EVIDENCE,
                "dispositivos_detectados": ctx.get("visible_devices_count")
                if ctx.get("visible_devices_count") is not None
                else NO_EVIDENCE,
                "local_ip": ctx.get("local_ip") or NO_EVIDENCE,
            },
            "eventos": rows,
            "total_eventos": summary.get("event_count") or 0,
        }
    except Exception as exc:
        logger.error("reports_center network history: %s", exc, exc_info=True)
        return {"error_internal": str(exc)[:200], "eventos": [], "contexto": {}, "disclaimer": NO_EVIDENCE}


def get_reports_center_payload(*, reports_limit: int = 150, tenant_id: Optional[str] = None) -> Dict[str, Any]:
    from services.security_report_service import list_reports

    all_reports = list_reports(limit=reports_limit, tenant_id=tenant_id)
    buckets: Dict[str, List[dict]] = {
        "automaticos": [],
        "manuales": [],
        "ejecutivos": [],
        "incidentes": [],
        "vulnerabilidades": [],
        "mecanismos": [],
    }
    for r in all_reports:
        key = _classify_report(r)
        buckets.setdefault(key, []).append(r)

    threat_rows: List[dict] = []
    try:
        from services.http_shell_service import get_threat_cache_snapshot

        rt = get_threat_cache_snapshot()
        for sp in (rt.get("suspicious_processes") or [])[:30]:
            if isinstance(sp, dict):
                threat_rows.append({**sp, "verified": True})
            else:
                threat_rows.append({"detail": str(sp), "verified": True})
    except Exception as exc:
        logger.debug("threat history: %s", exc)

    vuln_rows: List[dict] = []
    try:
        from services.http_shell_service import get_cached_vulnerabilities_snapshot

        for v in (get_cached_vulnerabilities_snapshot() or [])[:50]:
            if isinstance(v, dict):
                vuln_rows.append(v)
    except Exception as exc:
        logger.debug("vuln history: %s", exc)

    device_events: List[dict] = []
    try:
        from services.device_connection_monitor import list_events

        device_events = list_events(limit=40) or []
    except Exception as exc:
        logger.debug("device events: %s", exc)

    defense_events: List[dict] = []
    try:
        from services.defense_evidence_registry import list_recent_events

        defense_events = list_recent_events(limit=40) or []
    except Exception as exc:
        logger.debug("defense events: %s", exc)

    return {
        "centro": {
            "automaticos": {"count": len(buckets["automaticos"]), "items": buckets["automaticos"][:40]},
            "manuales": {"count": len(buckets["manuales"]), "items": buckets["manuales"][:40]},
            "ejecutivos": {"count": len(buckets["ejecutivos"]), "items": buckets["ejecutivos"][:40]},
            "historial_red": get_network_history_report(),
            "historial_amenazas": {
                "count": len(threat_rows),
                "items": threat_rows,
                "note": NO_EVIDENCE if not threat_rows else None,
            },
            "historial_vulnerabilidades": {
                "count": len(vuln_rows),
                "items": vuln_rows,
            },
            "historial_incidentes": buckets["incidentes"],
            "historial_dispositivos": {
                "count": len(device_events),
                "items": device_events,
                "enlace": "/historial-dispositivos",
            },
            "historial_conexiones": {
                "count": len(device_events),
                "items": [e for e in device_events if (e.get("event_type") or "") in ("connect", "disconnect")][:30],
            },
            "historial_mecanismos": {
                "count": len(defense_events),
                "items": defense_events,
            },
            "reportes_ejecutivos": buckets["ejecutivos"],
        },
        "total_informes": len(all_reports),
        "sin_evidencia_label": NO_EVIDENCE,
    }
