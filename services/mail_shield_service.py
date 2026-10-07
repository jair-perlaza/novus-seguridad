"""Persistencia, cuarentena, alertas y estadísticas — NOVUS Mail Shield."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _tenant() -> str:
    from services.tenant_scope_service import get_platform_tenant_id
    return get_platform_tenant_id()


def _map_event_type(classification: str, risk: float) -> str:
    c = (classification or "").lower()
    if "phishing" in c:
        return "phishing_detected"
    if "malicioso" in c or "malware" in c:
        return "malware_detected"
    if "ingeniería" in c or "bec" in c:
        return "bec_detected"
    if "spam" in c:
        return "spam_detected"
    if risk >= 75:
        return "mail_high_risk"
    if risk >= 45:
        return "mail_suspicious"
    return "mail_analyzed"


def ingest_analysis_record(
    mailbox_user_id,
    provider: str,
    record: Dict[str, Any],
    *,
    auto_action: bool = True,
) -> Optional[Dict[str, Any]]:
    """Registra análisis real y aplica política si está autorizado."""
    from services.mail_shield_config import effective_block_threshold, load_mail_shield_config
    from database import SessionLocal, MailShieldEvent

    if not record or not record.get("message_id"):
        return None

    cfg = load_mail_shield_config()
    if not cfg.get("enabled"):
        return None

    risk = float(record.get("risk_score") or 0)
    classification = record.get("classification") or "Desconocido"
    event_type = _map_event_type(classification, risk)
    severity = "critico" if risk >= 75 else ("alto" if risk >= 45 else "info")
    action = "logged"

    evidence = {
        "verified": True,
        "provider": provider,
        "message_id": record.get("message_id"),
        "subject": record.get("subject"),
        "sender": record.get("sender"),
        "domain": record.get("domain"),
        "classification": classification,
        "authentication": record.get("authentication"),
        "urls_found": record.get("urls_found"),
        "attachments": record.get("attachments"),
        "findings": record.get("findings"),
        "technical_summary": record.get("technical_summary"),
        "analyzed_at": record.get("analyzed_at"),
        "source": "mail_shield_official_api",
    }

    if cfg.get("analyze_links_with_web_shield") and record.get("urls_found"):
        link_ev = []
        for url in (record.get("urls_found") or [])[:5]:
            try:
                from services.web_shield_analyzer import analyze_url
                link_ev.append(analyze_url(url, whitelist=cfg.get("whitelist_domains"), blacklist=cfg.get("blacklist_domains")))
            except Exception:
                pass
        if link_ev:
            evidence["link_analysis"] = link_ev

    block_t = effective_block_threshold(cfg)
    if auto_action and cfg.get("auto_quarantine") and risk >= block_t and provider == "google_workspace":
        try:
            from services.gmail_analyzer_service import execute_action
            res = execute_action(mailbox_user_id, "quarantine", record["message_id"], confirmed=True)
            if res.get("status") == "success":
                action = "quarantined"
                event_type = "mail_quarantined"
                _record_quarantine(mailbox_user_id, provider, record, reason="Política Mail Shield", action=action)
        except Exception as exc:
            logger.debug("auto quarantine: %s", exc)

    db = SessionLocal()
    try:
        dup = (
            db.query(MailShieldEvent)
            .filter(
                MailShieldEvent.tenant_id == _tenant(),
                MailShieldEvent.provider == provider,
                MailShieldEvent.message_id == record.get("message_id"),
            )
            .first()
        )
        if dup:
            return _event_dict(dup)
        row = MailShieldEvent(
            tenant_id=_tenant(),
            provider=provider,
            mailbox_user_id=str(mailbox_user_id),
            message_id=record.get("message_id"),
            event_type=event_type,
            severity=severity,
            action_taken=action,
            subject=(record.get("subject") or "")[:500],
            sender=record.get("sender"),
            risk_score=int(risk),
            timestamp=_now(),
            evidence_json=json.dumps(evidence, ensure_ascii=False),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        out = _event_dict(row)
    except Exception as exc:
        db.rollback()
        logger.error("mail_shield ingest: %s", exc)
        return None
    finally:
        db.close()

    if severity in ("alto", "critico") or risk >= block_t:
        _emit_alert(out, evidence)

    return out


def _record_quarantine(mailbox_user_id, provider, record, reason, action):
    from database import SessionLocal, MailShieldQuarantine

    db = SessionLocal()
    try:
        db.add(MailShieldQuarantine(
            tenant_id=_tenant(),
            provider=provider,
            message_id=record.get("message_id"),
            item_type="message",
            reason=reason,
            mailbox_user_id=str(mailbox_user_id),
            affected_user=record.get("sender"),
            action_taken=action,
            timestamp=_now(),
            evidence_json=json.dumps(record, ensure_ascii=False),
        ))
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("quarantine record: %s", exc)
    finally:
        db.close()


def _emit_alert(event_row: Dict[str, Any], evidence: Dict[str, Any]) -> None:
    try:
        from services.evidence_center_service import record_evidence
        record_evidence(
            motor="novus_mail_shield",
            description=f"Mail Shield: {event_row.get('event_type')} — {event_row.get('subject')}",
            categoria="amenaza_detectada",
            nivel_riesgo=event_row.get("severity") or "alto",
            accion_ejecutada=event_row.get("action_taken"),
            source_event_id=f"MS-{event_row.get('id')}",
            evidence=evidence,
            dedupe_key=f"mail_shield:{event_row.get('message_id')}",
        )
    except Exception as exc:
        logger.debug("mail alert evidence: %s", exc)


def _event_dict(row) -> Dict[str, Any]:
    ev = {}
    try:
        ev = json.loads(row.evidence_json or "{}")
    except Exception:
        pass
    return {
        "id": row.id,
        "provider": row.provider,
        "event_type": row.event_type,
        "severity": row.severity,
        "action_taken": row.action_taken,
        "subject": row.subject,
        "sender": row.sender,
        "risk_score": row.risk_score,
        "timestamp": row.timestamp,
        "message_id": row.message_id,
        "evidence": ev,
    }


def list_events(limit: int = 50, provider: Optional[str] = None) -> List[Dict[str, Any]]:
    from database import SessionLocal, MailShieldEvent

    db = SessionLocal()
    try:
        q = db.query(MailShieldEvent).filter(MailShieldEvent.tenant_id == _tenant())
        if provider:
            q = q.filter(MailShieldEvent.provider == provider)
        rows = q.order_by(MailShieldEvent.id.desc()).limit(limit).all()
        return [_event_dict(r) for r in rows]
    finally:
        db.close()


def list_quarantine(limit: int = 50) -> List[Dict[str, Any]]:
    from database import SessionLocal, MailShieldQuarantine

    db = SessionLocal()
    try:
        rows = (
            db.query(MailShieldQuarantine)
            .filter(MailShieldQuarantine.tenant_id == _tenant())
            .order_by(MailShieldQuarantine.id.desc())
            .limit(limit)
            .all()
        )
        out = []
        for r in rows:
            ev = {}
            try:
                ev = json.loads(r.evidence_json or "{}")
            except Exception:
                pass
            out.append({
                "id": r.id,
                "provider": r.provider,
                "message_id": r.message_id,
                "item_type": r.item_type,
                "reason": r.reason,
                "timestamp": r.timestamp,
                "action_taken": r.action_taken,
                "evidence": ev,
            })
        return out
    finally:
        db.close()


def get_stats() -> Dict[str, Any]:
    from database import SessionLocal, MailShieldEvent, MailShieldQuarantine
    from sqlalchemy import func

    tid = _tenant()
    db = SessionLocal()
    try:
        base = db.query(MailShieldEvent).filter(MailShieldEvent.tenant_id == tid)
        total = base.count()
        if total == 0:
            return {
                "emails_analyzed": 0,
                "emails_blocked": 0,
                "emails_quarantined": 0,
                "phishing_detected": 0,
                "bec_detected": 0,
                "malware_detected": 0,
                "attachments_analyzed": 0,
                "attachments_blocked": 0,
                "last_analysis_at": "No existen datos disponibles",
                "has_data": False,
            }
        return {
            "has_data": True,
            "emails_analyzed": total,
            "emails_blocked": base.filter(MailShieldEvent.action_taken == "blocked").count(),
            "emails_quarantined": db.query(MailShieldQuarantine).filter(MailShieldQuarantine.tenant_id == tid).count(),
            "phishing_detected": base.filter(MailShieldEvent.event_type == "phishing_detected").count(),
            "bec_detected": base.filter(MailShieldEvent.event_type == "bec_detected").count(),
            "malware_detected": base.filter(MailShieldEvent.event_type == "malware_detected").count(),
            "attachments_analyzed": 0,
            "attachments_blocked": 0,
            "last_analysis_at": db.query(func.max(MailShieldEvent.timestamp)).filter(MailShieldEvent.tenant_id == tid).scalar() or "No existen datos disponibles",
        }
    finally:
        db.close()


def get_integration_status(user_id) -> Dict[str, Any]:
    from services.gmail_oauth_service import get_connection_status as gmail_conn, get_setup_instructions as gmail_setup
    from services.microsoft365_oauth_service import get_connection_status as m365_conn, get_setup_instructions as m365_setup

    if user_id is None:
        gs = gmail_setup()
        ms = m365_setup()
        return {
            "google_workspace": {"oauth_configured": gs.get("configured"), "connected": False, "setup": gs},
            "microsoft365": {"oauth_configured": ms.get("configured"), "connected": False, "setup": ms},
            "summary_message": "Integración no configurada" if not (gs.get("configured") or ms.get("configured")) else "Esperando autorización del cliente (OAuth)",
            "any_connected": False,
        }

    g = gmail_conn(user_id)
    m = m365_conn(user_id)
    any_connected = g.get("connected") or m.get("connected")
    any_oauth = g.get("oauth_configured") or m.get("oauth_configured")
    if not any_oauth:
        message = "Integración no configurada"
    elif not any_connected:
        message = "Esperando autorización del cliente (OAuth)"
    else:
        message = "Activa"
    return {
        "google_workspace": {**g, "setup": gmail_setup()},
        "microsoft365": {**m, "setup": m365_setup()},
        "summary_message": message,
        "any_connected": any_connected,
    }


def executive_report() -> Dict[str, Any]:
    stats = get_stats()
    if not stats.get("has_data"):
        return {
            "status": "no_data",
            "message": "No existen datos disponibles — conecte Google Workspace o Microsoft 365.",
            "stats": stats,
        }
    events = list_events(limit=200)
    by_type: Dict[str, int] = {}
    for e in events:
        by_type[e["event_type"]] = by_type.get(e["event_type"], 0) + 1
    return {
        "status": "ok",
        "generated_at": _now(),
        "stats": stats,
        "events_by_type": by_type,
        "recommendations": [
            "Revise cuarentena y falsos positivos semanalmente.",
            "Mantenga DMARC/DKIM/SPF en el tenant de correo.",
            "Use listas blanca/negra corporativas en Mail Shield.",
        ],
    }


def explain_for_kernel(event_id: int) -> Optional[Dict[str, Any]]:
    from database import SessionLocal, MailShieldEvent

    db = SessionLocal()
    try:
        row = db.query(MailShieldEvent).filter(MailShieldEvent.id == event_id).first()
        if not row:
            return None
        ev = json.loads(row.evidence_json or "{}")
        return {
            "what": row.event_type,
            "mail_subject": row.subject,
            "affected_user_mailbox": row.mailbox_user_id,
            "sender": row.sender,
            "evidence": ev,
            "protections": row.action_taken,
            "risk_score": row.risk_score,
            "recommendations": ev.get("findings") or [],
        }
    finally:
        db.close()
