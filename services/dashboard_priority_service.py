"""
Prioridad Actual del Dashboard — consume telemetría real existente (sin datos inventados).
"""
from __future__ import annotations

import json
import socket
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

GENERIC_INCIDENT_DESC_PREFIX = "Condición crítica detectada por motor de seguridad"
PRIORITY_INCIDENT_MAX_AGE_HOURS = 24
INCIDENT_PROVENANCE_KEYS = (
    "detection_id",
    "evidence_id",
    "finding_id",
    "incident_id",
    "event_id",
    "anomaly_id",
)

from services.soc_report_builder import _severity_score, _vuln_exploit_hint, _vuln_remediation
from utils.logger import logger


def _risk_label(score: int) -> str:
    if score >= 85:
        return "Crítico"
    if score >= 70:
        return "Alto"
    if score >= 50:
        return "Medio"
    return "Bajo"


def _probability_label(score: int) -> str:
    if score >= 85:
        return "Alta"
    if score >= 65:
        return "Media"
    return "Baja"


def _parse_analysis_timestamp(raw: Optional[str]) -> Optional[datetime]:
    if not raw:
        return None
    text = str(raw).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _resolve_last_analysis(user_email: Optional[str], cache: dict) -> str:
    """Último análisis verificable — nunca config estática obsoleta (sector_shield_state)."""
    candidates: List[str] = []
    if cache.get("last_scan"):
        candidates.append(str(cache["last_scan"]))
    audit_ts = (cache.get("vulnerabilities_audit") or {}).get("timestamp")
    if audit_ts:
        candidates.append(str(audit_ts))
    if not candidates:
        return "Sin datos disponibles"
    parsed = [
        (ts, value)
        for value in candidates
        if (ts := _parse_analysis_timestamp(value)) is not None
    ]
    if parsed:
        parsed.sort(key=lambda item: item[0], reverse=True)
        return parsed[0][1]
    return candidates[0]


def _is_stale_incident(fecha: Optional[str]) -> bool:
    ts = _parse_analysis_timestamp(fecha)
    if not ts:
        return True
    return datetime.now() - ts > timedelta(hours=PRIORITY_INCIDENT_MAX_AGE_HOURS)


def _evidence_payload_has_provenance(payload: dict) -> bool:
    return isinstance(payload, dict) and any(payload.get(key) for key in INCIDENT_PROVENANCE_KEYS)


def _alert_has_verifiable_evidence(alert, desc: str, presented: Dict[str, Any]) -> bool:
    payload: Optional[dict] = None
    if alert.evidencia_json:
        try:
            raw = json.loads(alert.evidencia_json)
            payload = raw if isinstance(raw, dict) else None
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = None
    if payload and _evidence_payload_has_provenance(payload):
        presented_ev = _present_evidence(payload)
        if presented_ev.get("evidence_items"):
            presented.update(presented_ev)
            return True
    if desc.startswith(GENERIC_INCIDENT_DESC_PREFIX):
        return False
    items = presented.get("evidence_items") or []
    if not items:
        return False
    if len(items) == 1 and items[0].get("label") == "Resumen":
        summary = str(items[0].get("value") or "")
        if summary.startswith(GENERIC_INCIDENT_DESC_PREFIX):
            return False
    return True


def _present_evidence(raw: Any, details: Optional[dict] = None) -> Dict[str, Any]:
    from services.alerts_canonical_service import humanize_evidence_for_client

    if isinstance(raw, dict) and details is None:
        details = raw
        raw = raw.get("evidence")
    return humanize_evidence_for_client(raw, details)


def _threat_has_verified_evidence(threat: dict) -> bool:
    details = threat.get("details") or {}
    if not isinstance(details, dict) or not details:
        return False
    if details.get("verified") is not True:
        return False
    if details.get("status") in ("SECURE", "STABLE", "OPERATIONAL", "OBSERVATION"):
        return False
    evidence_text = details.get("evidence") or details.get("message")
    if isinstance(evidence_text, str) and evidence_text.strip():
        return True
    presented = _present_evidence(details)
    return bool(presented.get("evidence_items"))


def _is_not_verifiable_mitm_alert(alert, presented: Dict[str, Any], desc: str) -> bool:
    """Historical/false MITM from TLS trust-store noise must not surface as LIVE priority."""
    title = (getattr(alert, "titulo", None) or "").lower()
    blob = " ".join(
        [
            title,
            (desc or "").lower(),
            str(presented.get("evidence_summary") or "").lower(),
            json.dumps(presented.get("evidence_items") or [], ensure_ascii=False).lower(),
        ]
    )
    if "mitm" not in blob and "man-in-the-middle" not in blob and "ssl stripping" not in blob:
        return False
    # Known over-trigger pattern (cert_verify / local trust presented as stripping)
    if "not_verifiable" in blob or "trust store" in blob or "cert_verify_failed" in blob:
        return True
    if "conexión no cifrada" in blob or "ssl stripping" in blob:
        # Without pin mismatch / stronger signal → not LIVE confirmed MITM for dashboard priority
        if "certificado desconocido" not in blob and "proxy" not in blob:
            return True
    return False


def _collect_incidents() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    try:
        from database import SessionLocal, Alerta
        from services.alert_reconciliation_service import RESOLVED_LEVEL
        from services.tenant_scope_service import get_platform_tenant_id

        platform_tid = get_platform_tenant_id()
        db = SessionLocal()
        try:
            query = db.query(Alerta).order_by(Alerta.id.desc())
            if hasattr(Alerta, "tenant_id"):
                query = query.filter(
                    (Alerta.tenant_id == platform_tid) | (Alerta.tenant_id.is_(None))
                )
            for alert in query.limit(20).all():
                if alert.nivel == RESOLVED_LEVEL:
                    continue
                if hasattr(alert, "activa") and alert.activa is False:
                    continue
                estado = (alert.estado or "").lower()
                if estado in ("resuelto", "resolved", "cerrado", "closed"):
                    continue
                if _is_stale_incident(alert.fecha):
                    continue
                titulo_lower = (alert.titulo or "").lower()
                if "high_entropy" in titulo_lower:
                    continue
                nivel = (alert.nivel or "").lower()
                if nivel not in ("critical", "crítico", "critico", "warning", "alta", "high"):
                    continue
                desc = (alert.descripcion or "").strip()
                presented: Dict[str, Any] = {"evidence_items": [], "evidence_summary": None}
                conf_from_row = getattr(alert, "confianza", None)
                evid_payload: dict = {}
                if alert.evidencia_json:
                    try:
                        evid_payload = json.loads(alert.evidencia_json)
                        if isinstance(evid_payload, dict):
                            presented = _present_evidence(evid_payload)
                            conf_from_row = conf_from_row or evid_payload.get("confidence")
                    except (TypeError, ValueError, json.JSONDecodeError):
                        pass
                if not presented.get("evidence_items") and desc and not desc.startswith(("{", "[")):
                    presented = _present_evidence(desc)
                if not _alert_has_verifiable_evidence(alert, desc, presented):
                    continue
                if _is_not_verifiable_mitm_alert(alert, presented, desc):
                    continue
                impact = desc[:200] if desc else (presented.get("evidence_summary") or "")
                conf = conf_from_row if conf_from_row not in (None, "") else "NOT_AVAILABLE"
                row = {
                    "kind": "incident",
                    "score": 88 if "crit" in nivel else 72,
                    "name": alert.titulo or "Incidente de seguridad",
                    "level": alert.nivel or "Warning",
                    "origin": "Centro de incidentes / SIEM",
                    "asset": alert.ip_afectada or socket.gethostname(),
                    "impact": impact,
                    "probability": _probability_label(88 if "crit" in nivel else 72),
                    "inaction": "El incidente puede escalar si no se investiga y contiene.",
                    "recommendation": alert.recomendacion or "Revisar detalle en Incidentes y aplicar playbook de contención.",
                    "evidence_summary": presented.get("evidence_summary"),
                    "evidence_items": presented.get("evidence_items"),
                    "fecha_analisis": alert.fecha,
                    "action_label": "Ir a Incidentes",
                    "action_url": "/incidentes",
                    "confianza": conf,
                    "data_state": "HISTORICAL" if _is_stale_incident(alert.fecha) else "LIVE_CACHE",
                }
                items.append(row)
        finally:
            db.close()
    except Exception as exc:
        logger.debug("Dashboard priority incidents: %s", exc)
    return items


def _threat_candidate(threat: dict) -> Optional[Dict[str, Any]]:
    # Do not invent severity "high" when the source omitted it.
    raw_sev = threat.get("severity")
    if raw_sev is None or str(raw_sev).strip() == "":
        return None
    severity = str(raw_sev).upper()
    score = {"CRITICAL": 95, "HIGH": 88, "MEDIUM": 70, "LOW": 55}.get(severity)
    if score is None:
        # Unknown severity vocabulary — do not invent a default score.
        return None
    ttype = threat.get("type") or "amenaza"
    details = threat.get("details") or {}
    presented = _present_evidence(details)
    impact = (
        details.get("message")
        or presented.get("evidence_summary")
        or "Actividad anómala confirmada por el motor de amenazas."
    )
    asset = details.get("ip") or details.get("email") or socket.gethostname()
    return {
        "kind": "threat",
        "score": score,
        "name": f"Amenaza detectada: {str(ttype).upper()}",
        "level": _risk_label(score),
        "origin": details.get("source") or "Motor XDR / security_engine",
        "asset": asset,
        "impact": impact,
        "probability": _probability_label(score),
        "inaction": "Riesgo de compromiso de integridad de red o datos en tránsito.",
        "recommendation": "Aislar conexión sospechosa, revisar en XDR y ejecutar mitigación sectorial.",
        "evidence_summary": presented.get("evidence_summary"),
        "evidence_items": presented.get("evidence_items"),
        "action_label": "Ir a XDR / Amenazas",
        "action_url": "/xdr",
    }


def _process_threat_candidate(proc: dict) -> Dict[str, Any]:
    score = 86
    evidence_text = proc.get("command_line") or proc.get("path") or proc.get("description")
    presented = _present_evidence(evidence_text, proc)
    return {
        "kind": "threat",
        "score": score,
        "name": f"Proceso sospechoso: {proc.get('name') or 'desconocido'}",
        "level": _risk_label(score),
        "origin": proc.get("path") or "advanced_detector",
        "asset": socket.gethostname(),
        "impact": proc.get("description") or evidence_text or "Patrón de ejecución de riesgo detectado.",
        "probability": _probability_label(score),
        "inaction": "Posible persistencia, robo de credenciales o ejecución de código no autorizado.",
        "recommendation": "Validar proceso en XDR, terminar solo tras confirmación y revisar inicio automático.",
        "evidence_summary": presented.get("evidence_summary"),
        "evidence_items": presented.get("evidence_items"),
        "action_label": "Ir a XDR / Amenazas",
        "action_url": "/xdr",
    }


def _vulnerability_candidate(vuln: dict) -> Dict[str, Any]:
    score = _severity_score(vuln)
    if score < 25:
        score = 45
    name = vuln.get("nombre") or vuln.get("titulo") or "Hallazgo de seguridad"
    riesgo = vuln.get("riesgo") or vuln.get("severidad") or "Detectado"
    equipo = vuln.get("ip") or socket.gethostname()
    desc = vuln.get("descripcion") or ""
    evidencia = vuln.get("evidencia") or {}
    archivo = evidencia.get("archivo") if isinstance(evidencia, dict) else None
    if not archivo:
        archivo = vuln.get("archivo")
    presented = _present_evidence(evidencia if isinstance(evidencia, dict) else desc, vuln)
    return {
        "kind": "vulnerability",
        "score": score,
        "name": name,
        "level": _risk_label(score),
        "asset": equipo,
        "origin": vuln.get("motor") or vuln.get("fuente") or "Motor de vulnerabilidades",
        "impact": _vuln_exploit_hint(vuln),
        "probability": _probability_label(score),
        "inaction": "Superficie de ataque expuesta; un actor podría explotar el componente afectado.",
        "recommendation": _vuln_remediation(vuln),
        "evidence_summary": presented.get("evidence_summary") or (desc[:200] if desc else None),
        "evidence_items": presented.get("evidence_items"),
        "why": desc[:200] if desc else None,
        "action_label": "Ir a Vulnerabilidades",
        "action_url": "/vulnerabilidades",
        "risk_raw": str(riesgo),
        "motor": vuln.get("motor") or vuln.get("fuente"),
        "archivo": archivo,
        "fecha_analisis": vuln.get("fecha_analisis") or (
            evidencia.get("fecha_analisis") if isinstance(evidencia, dict) else None
        ),
        "confianza": vuln.get("confianza") or "ALTA",
    }


def _stable_payload(last_analysis: str) -> Dict[str, Any]:
    return {
        "status": "success",
        "priority_type": "stable",
        "title": "Estado general estable",
        "summary": [
            "Actualmente no existen vulnerabilidades críticas verificadas.",
            "La protección permanece activa.",
        ],
        "last_analysis": last_analysis,
        "recommendation": "Continuar con la monitorización.",
        "action_label": None,
        "action_url": None,
        "tone": "calm",
        "has_verified_priority": False,
    }


def _public_details(best: Dict[str, Any]) -> Dict[str, Any]:
    """DTO de detalle para UI — sin dicts internos."""
    return {
        "origin": best.get("origin"),
        "asset": best.get("asset"),
        "impact": best.get("impact"),
        "probability": best.get("probability"),
        "inaction": best.get("inaction"),
        "why": best.get("why"),
        "risk_raw": best.get("risk_raw"),
        "motor": best.get("motor"),
        "archivo": best.get("archivo"),
        "fecha_analisis": best.get("fecha_analisis"),
        "confianza": best.get("confianza"),
        "evidence_summary": best.get("evidence_summary"),
        "evidence_items": best.get("evidence_items") or [],
    }


def get_current_priority(user_email: Optional[str] = None) -> Dict[str, Any]:
    """Devuelve el hallazgo de mayor prioridad o estado estable basado en datos reales."""
    from services.novus_security_integration import novus_security

    cache = dict(novus_security._threat_cache or {})
    if not cache.get("last_scan"):
        try:
            from services.http_shell_service import schedule_threat_scan_if_stale

            schedule_threat_scan_if_stale()
        except Exception as exc:
            logger.debug("Priority threat cache schedule: %s", exc)
    if not cache.get("vulnerabilities"):
        try:
            cache["vulnerabilities"] = novus_security.get_cached_vulnerabilities()
        except Exception as exc:
            logger.debug("Priority vuln load: %s", exc)
            cache.setdefault("vulnerabilities", [])

    last_analysis = _resolve_last_analysis(user_email, cache)
    candidates: List[Dict[str, Any]] = []

    for threat in cache.get("threats") or []:
        if not _threat_has_verified_evidence(threat):
            continue
        ttype = str(threat.get("type") or "").lower()
        details = threat.get("details") or {}
        if ttype == "mitm" or "mitm" in str(details.get("incident") or "").lower():
            # Do not surface NOT_VERIFIABLE / trust-store MITM as current priority
            if details.get("status") == "NOT_VERIFIABLE" or details.get("data_state") == "NOT_VERIFIABLE":
                continue
            anomalies = " ".join(str(a) for a in (details.get("anomalies") or [])).lower()
            if "not_verifiable" in anomalies or "trust store" in anomalies:
                continue
            if "ssl stripping" in anomalies and "certificado desconocido" not in anomalies:
                continue
        candidate = _threat_candidate(threat)
        if not candidate:
            continue
        candidate["motor"] = details.get("motor") or details.get("source") or "security_engine"
        # Confidence must come from the source — never invent Alta/Media.
        conf = details.get("confidence") or details.get("confianza")
        candidate["confianza"] = conf if conf not in (None, "") else "NOT_AVAILABLE"
        candidate["fecha_analisis"] = details.get("timestamp") or last_analysis
        candidates.append(candidate)

    suspicious = cache.get("suspicious_processes") or []
    suspicious_pids = set()
    for proc in suspicious:
        if not proc.get("pid"):
            continue
        proc_evidence = proc.get("command_line") or proc.get("path") or proc.get("description")
        if not proc_evidence or proc_evidence == "Proceso en ejecución":
            continue
        candidate = _process_threat_candidate(proc)
        candidate["motor"] = "advanced_detector.scan_running_processes"
        conf = proc.get("confidence") or proc.get("confianza")
        candidate["confianza"] = conf if conf not in (None, "") else "NOT_AVAILABLE"
        candidate["fecha_analisis"] = last_analysis
        candidate["archivo"] = proc.get("path")
        candidates.append(candidate)
        suspicious_pids.add(str(proc["pid"]))

    for inc in (_collect_incidents() if cache.get("last_scan") else []):
        if not inc.get("evidence_summary") and not inc.get("impact"):
            continue
        if "mitm" in str(inc.get("name") or "").lower() and _is_not_verifiable_mitm_alert(
            type("A", (), {"titulo": inc.get("name")})(),
            {"evidence_summary": inc.get("evidence_summary"), "evidence_items": inc.get("evidence_items")},
            str(inc.get("impact") or ""),
        ):
            continue
        inc["motor"] = "Centro de incidentes / SQLite Alerta"
        # Do not invent ALTA — use source confidence or NOT_AVAILABLE
        if not inc.get("confianza"):
            inc["confianza"] = "NOT_AVAILABLE"
        candidates.append(inc)

    for vuln in cache.get("vulnerabilities") or []:
        if not vuln.get("verificacion_completa"):
            continue
        vid = str(vuln.get("id") or "")
        nombre = vuln.get("nombre") or ""
        fuente = vuln.get("fuente") or ""
        evidencia = vuln.get("evidencia") or {}

        if vid.startswith("FIND-PROC-"):
            pid = vid.replace("FIND-PROC-", "")
            if pid in suspicious_pids:
                continue
            desc = vuln.get("descripcion") or ""
            if not desc or desc == "Proceso en ejecución":
                continue

        if vid.startswith("FIND-PORT-"):
            if "Puerto" not in nombre and not vuln.get("descripcion"):
                continue

        if fuente == "vulnerability_scanner":
            if not evidencia.get("archivo") and not evidencia.get("permisos_medidos"):
                if vuln.get("type") != "firewall_disabled":
                    continue

        if fuente == "database":
            continue

        if not (evidencia or vuln.get("descripcion") or vid.startswith("FIND-")):
            continue

        candidates.append(_vulnerability_candidate(vuln))

    candidates = [c for c in candidates if c.get("score", 0) >= 70]

    if not candidates:
        return _stable_payload(last_analysis)

    best = max(
        candidates,
        key=lambda c: (c.get("score", 0), c["kind"] == "threat", c["kind"] == "incident"),
    )

    display_last_analysis = best.get("fecha_analisis") or last_analysis

    payload: Dict[str, Any] = {
        "status": "success",
        "priority_type": best["kind"],
        "title": best["name"],
        "level": best["level"],
        "last_analysis": display_last_analysis,
        "recommendation": best["recommendation"],
        "action_label": best["action_label"],
        "action_url": best["action_url"],
        "tone": "alert" if best["score"] >= 70 else "watch",
        "has_verified_priority": True,
        "details": _public_details(best),
        "total_issues_detected": len(candidates),
    }
    return payload
