"""
Reconciliación de alertas — corrige el ORIGEN incorrecto (BD, registry, reportes)
sin desactivar motores ni ocultar detecciones reales en la UI.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime

from utils.logger import logger

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "reports")
INDEX_FILE = os.path.join(REPORTS_DIR, "index.json")
RESOLVED_LEVEL = "Resuelto-FalsoPositivo"
RECONCILE_NOTE = "[RECONCILIADO: falso positivo histórico — sin evidencia activa del motor]"
DOC_IP_NOTE = "[RECONCILIADO: IP de documentación RFC 5737 — origen de prueba/laboratorio, no evidencia operativa]"


def _alert_contains_documentation_ip(alert) -> bool:
    from utils.ip_validation import is_documentation_ip, text_contains_documentation_ip

    if is_documentation_ip(getattr(alert, "ip_afectada", None)):
        return True
    desc = alert.descripcion or ""
    if text_contains_documentation_ip(desc):
        return True
    ev = getattr(alert, "evidencia_json", None) or ""
    return text_contains_documentation_ip(ev)


def reconcile_documentation_ip_audit_logs(db_session) -> int:
    """Etiqueta logs LOGIN_FAILED de laboratorio (RFC 5737) para excluirlos del motor."""
    from database import Log
    from utils.ip_validation import extract_ips_from_text, is_documentation_ip

    updated = 0
    tag = "[EXCLUIDO: IP RFC 5737 — log de laboratorio/prueba, no evidencia operativa]"
    for row in db_session.query(Log).filter(Log.evento == "LOGIN_FAILED").all():
        if tag in (row.detalle or ""):
            continue
        ips = extract_ips_from_text(row.detalle)
        if any(is_documentation_ip(ip) for ip in ips):
            row.detalle = f"{row.detalle or ''} {tag}".strip()
            updated += 1
    if updated:
        db_session.commit()
        logger.info("Etiquetados %s log(s) LOGIN_FAILED con IP RFC 5737", updated)
    return updated


def reconcile_documentation_ip_alerts(db_session) -> int:
    """Marca alertas con IPs RFC 5737 — contaminación de tests, no evidencia real."""
    from database import Alerta

    updated = 0
    for alert in db_session.query(Alerta).all():
        if alert.nivel == RESOLVED_LEVEL:
            continue
        if DOC_IP_NOTE in (alert.descripcion or ""):
            continue
        if not _alert_contains_documentation_ip(alert):
            continue
        alert.nivel = RESOLVED_LEVEL
        alert.descripcion = f"{alert.descripcion or ''}\n{DOC_IP_NOTE}".strip()
        alert.recomendacion = "Alerta de laboratorio/prueba con IP RFC 5737 — excluida del dashboard."
        if hasattr(alert, "estado"):
            alert.estado = "resuelto"
        if hasattr(alert, "activa"):
            alert.activa = False
        updated += 1
    if updated:
        db_session.commit()
        logger.info("Reconciliadas %s alerta(s) con IP de documentación RFC 5737", updated)
    return updated


def purge_documentation_ip_registry(security_engine) -> int:
    """Elimina entradas del threat_registry vinculadas a IPs de documentación."""
    from utils.ip_validation import is_documentation_ip, text_contains_documentation_ip

    removed = 0
    kept = []
    for entry in security_engine.threat_registry or []:
        details = entry.get("details") or {}
        ip = details.get("ip") if isinstance(details, dict) else None
        evidence = entry.get("evidence") or details
        if is_documentation_ip(ip) or text_contains_documentation_ip(str(evidence)):
            removed += 1
        else:
            kept.append(entry)
    security_engine.threat_registry = kept
    if removed:
        logger.info("Purged %s documentation-IP entries from threat_registry", removed)
    return removed


def _has_active_ransomware_evidence(threat_cache: dict) -> bool:
    for threat in (threat_cache or {}).get("threats") or []:
        if str(threat.get("type") or "").lower() == "ransomware":
            details = threat.get("details") or {}
            if details.get("verified") or details.get("evidence"):
                return True
    return False


def _has_active_entropy_evidence(threat_cache: dict) -> bool:
    for threat in (threat_cache or {}).get("threats") or []:
        ttype = str(threat.get("type") or "").lower()
        details = threat.get("details") or {}
        if "entropy" in ttype and details.get("verified"):
            return True
    return False


def reconcile_database_alerts(db_session, threat_cache: dict | None = None) -> int:
    """Marca alertas históricas sin respaldo del motor activo (ransomware, entropía)."""
    from services.novus_security_integration import novus_security

    cache = dict(threat_cache or novus_security._threat_cache or {})
    active_ransom = _has_active_ransomware_evidence(cache)
    active_entropy = _has_active_entropy_evidence(cache)

    from database import Alerta

    updated = 0
    alerts = db_session.query(Alerta).all()
    for alert in alerts:
        titulo = (alert.titulo or "").lower()
        desc = (alert.descripcion or "").lower()
        if alert.nivel == RESOLVED_LEVEL:
            continue
        if RECONCILE_NOTE in (alert.descripcion or ""):
            continue

        is_ransom = "ransomware" in titulo or "ransomware" in desc
        is_entropy = "high_entropy" in titulo or "high_entropy" in desc

        if is_ransom and not active_ransom:
            alert.nivel = RESOLVED_LEVEL
            alert.descripcion = f"{alert.descripcion or ''}\n{RECONCILE_NOTE}".strip()
            alert.recomendacion = (
                "Alerta histórica reconciliada: no hay evidencia activa del motor Ransom Sentinel."
            )
            updated += 1
        elif is_entropy and not active_entropy:
            alert.nivel = RESOLVED_LEVEL
            alert.descripcion = f"{alert.descripcion or ''}\n{RECONCILE_NOTE}".strip()
            alert.recomendacion = (
                "Alerta histórica reconciliada: entropía aislada sin confirmación del motor."
            )
            updated += 1
    if updated:
        db_session.commit()
        logger.info("Reconciliadas %s alerta(s) históricas en SQLite", updated)
    return updated


def purge_unverified_ransomware_registry(security_engine) -> int:
    """Elimina entradas ransomware del threat_registry en memoria sin evidencia verificable."""
    removed = 0
    kept = []
    for entry in security_engine.threat_registry or []:
        label = str(
            entry.get("threat") or entry.get("threat_type") or entry.get("incident") or ""
        ).lower()
        if "ransom" in label:
            if entry.get("verified") and (entry.get("evidence") or entry.get("indicators")):
                kept.append(entry)
            else:
                removed += 1
        else:
            kept.append(entry)
    security_engine.threat_registry = kept
    if removed:
        logger.info("Purged %s unverified ransomware entries from threat_registry", removed)
    return removed


def tag_false_positive_reports() -> int:
    """Etiqueta reportes JSON históricos generados por falsos positivos de ransomware."""
    if not os.path.exists(INDEX_FILE):
        return 0
    try:
        with open(INDEX_FILE, "r", encoding="utf-8") as handle:
            index = json.load(handle)
    except Exception:
        return 0

    tagged = 0
    patterns = [
        re.compile(r"ransomware threat detected", re.I),
        re.compile(r"high_entropy threat detected", re.I),
    ]
    for entry in index:
        resumen = entry.get("resumen") or ""
        if "[RECONCILIADO" in resumen:
            continue
        if not any(p.search(resumen) for p in patterns):
            continue
        entry["resumen"] = f"{resumen} {RECONCILE_NOTE}"
        entry["estado"] = RESOLVED_LEVEL
        tagged += 1

    if tagged:
        with open(INDEX_FILE, "w", encoding="utf-8") as handle:
            json.dump(index, handle, indent=2, ensure_ascii=False)
        logger.info("Etiquetados %s reporte(s) ransomware históricos en index.json", tagged)
    return tagged


def reconcile_documentation_ip_blocks(db_session) -> int:
    """Expira bloqueos históricos con IPs RFC 5737 (lab/test)."""
    from database import IPBloqueada
    from utils.ip_validation import is_documentation_ip

    updated = 0
    for row in db_session.query(IPBloqueada).filter(
        IPBloqueada.status.in_(("active", "pending_admin"))
    ).all():
        if not is_documentation_ip(row.direccion_ip):
            continue
        row.status = "expired"
        note = "RFC5737 lab — reconciliado"
        row.block_reason = f"{row.block_reason or row.razon or ''} [{note}]".strip()
        updated += 1
    if updated:
        db_session.commit()
        logger.info("Expirados %s bloqueo(s) con IP de documentación", updated)
    return updated


AUTH_STALE_NOTE = "[RECONCILIADO: sin LOGIN_FAILED verificable en ventana 24h — alerta auth retirada]"


def reconcile_stale_auth_brute_alerts(db_session) -> int:
    """Resuelve alertas brute_force / RUNTIME auth cuya IP no tiene fallos recientes."""
    from database import Alerta, IPBloqueada
    from services.auth_anomaly_evidence_service import ip_has_recent_login_failures

    updated = 0
    for alert in db_session.query(Alerta).all():
        if alert.nivel == RESOLVED_LEVEL:
            continue
        if AUTH_STALE_NOTE in (alert.descripcion or ""):
            continue
        titulo = (alert.titulo or "").lower()
        is_auth = "brute" in titulo or "runtime_brute" in titulo or (alert.motor or "") == "audit_logs"
        if not is_auth:
            continue
        ip = alert.ip_afectada
        if not ip:
            continue
        if ip_has_recent_login_failures(db_session, ip):
            continue
        alert.nivel = RESOLVED_LEVEL
        alert.descripcion = f"{alert.descripcion or ''}\n{AUTH_STALE_NOTE}".strip()
        alert.recomendacion = "Sin evidencia auth activa en ventana 24h."
        if hasattr(alert, "estado"):
            alert.estado = "resuelto"
        if hasattr(alert, "activa"):
            alert.activa = False
        updated += 1

    blocks = 0
    for row in db_session.query(IPBloqueada).filter(IPBloqueada.status == "active").all():
        ip = row.direccion_ip
        if not ip:
            continue
        reason = f"{row.block_reason or row.razon or ''}".lower()
        if "auth" not in reason and "brute" not in reason:
            continue
        if ip_has_recent_login_failures(db_session, ip):
            continue
        row.status = "expired"
        row.block_reason = f"{row.block_reason or row.razon or ''} [expirado: sin fallos auth 24h]".strip()
        blocks += 1

    if updated or blocks:
        db_session.commit()
        logger.info(
            "Auth stale reconcile: %s alerta(s), %s bloqueo(s) IP",
            updated,
            blocks,
        )
    return updated + blocks


def reconcile_active_defense_stale_auth() -> int:
    """Cierra incidentes active_defense auth sin evidencia en ventana 24h."""
    try:
        from services.active_defense_orchestrator import _load_state, _save_state
        from services.auth_anomaly_evidence_service import auth_details_pass_gate
    except Exception:
        return 0

    state = _load_state()
    kept: list = []
    moved = 0
    for entry in state.get("active") or []:
        tt = str(entry.get("threat_type") or entry.get("category") or "").lower()
        if "brute" not in tt and tt not in ("auth_credentials", "auth_anomaly"):
            kept.append(entry)
            continue
        raw = entry.get("evidence") or entry.get("details") or {}
        if not isinstance(raw, dict):
            moved += 1
            entry["status"] = "resolved"
            entry["resolution"] = "sin_evidencia_auth_verificable"
            state.setdefault("resolved", []).append(entry)
            continue
        ok, _ = auth_details_pass_gate(
            {**raw, "verified": True, "event_type": "brute_force", "source": raw.get("source") or "auth_access_audit"}
        )
        if ok:
            kept.append(entry)
        else:
            moved += 1
            entry["status"] = "resolved"
            entry["resolution"] = "sin_evidencia_auth_verificable"
            state.setdefault("resolved", []).append(entry)
    if moved:
        state["active"] = kept
        _save_state(state)
        logger.info("Active defense: %s incidente(s) auth cerrados por falta de evidencia", moved)
    return moved


def reconcile_platform_evidence_doc_ips(db_session) -> int:
    """Marca evidencias de plataforma con IPs RFC 5737 como excluidas."""
    from database import PlatformEvidence
    from utils.ip_validation import text_contains_documentation_ip

    updated = 0
    tag = "[EXCLUIDO: IP RFC 5737 — no evidencia operativa]"
    for row in db_session.query(PlatformEvidence).all():
        blob = f"{row.descripcion or ''} {row.evidence_json or ''}"
        if tag in blob:
            continue
        if text_contains_documentation_ip(blob):
            row.descripcion = f"{row.descripcion or ''} {tag}".strip()[:1000]
            row.estado = "excluido"
            updated += 1
    if updated:
        db_session.commit()
        logger.info("Excluidas %s evidencia(s) platform con IP RFC 5737", updated)
    return updated


def reconcile_stale_security_alerts() -> dict:
    """Ejecuta reconciliación completa al arranque — origen incorrecto, motores intactos."""
    from database import SessionLocal
    from services.novus_security_integration import novus_security

    db = SessionLocal()
    try:
        db_count = reconcile_database_alerts(db, novus_security._threat_cache)
        doc_ip_count = reconcile_documentation_ip_alerts(db)
        doc_blocks = reconcile_documentation_ip_blocks(db)
        audit_logs_tagged = reconcile_documentation_ip_audit_logs(db)
        platform_evidence = reconcile_platform_evidence_doc_ips(db)
        auth_stale = reconcile_stale_auth_brute_alerts(db)
        ad_auth = reconcile_active_defense_stale_auth()
    finally:
        db.close()

    registry_count = purge_unverified_ransomware_registry(novus_security.security_engine)
    doc_registry = purge_documentation_ip_registry(novus_security.security_engine)
    report_count = tag_false_positive_reports()
    return {
        "alerts_reconciled": db_count,
        "documentation_ip_reconciled": doc_ip_count,
        "documentation_ip_blocks_reconciled": doc_blocks,
        "audit_logs_documentation_tagged": audit_logs_tagged,
        "platform_evidence_doc_excluded": platform_evidence,
        "auth_stale_reconciled": auth_stale,
        "active_defense_auth_closed": ad_auth,
        "registry_purged": registry_count,
        "documentation_ip_registry_purged": doc_registry,
        "reports_tagged": report_count,
        "timestamp": datetime.now().isoformat(),
    }
