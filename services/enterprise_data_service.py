"""Servicios de persistencia en dominios empresariales — solo datos reales."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from utils.logger import logger


def _ts_parts() -> tuple[str, str, str, str]:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return ts, ts[:10], ts[11:], ts


def record_security_event_domain(
    *,
    event_type: str,
    tenant_id: Optional[str],
    user_email: Optional[str] = None,
    equipment: Optional[str] = None,
    severity: Optional[str] = None,
    motor: Optional[str] = None,
    evidence: Optional[dict] = None,
    status: str = "recorded",
    action_taken: Optional[str] = None,
    legacy_ref: Optional[str] = None,
    event_id: Optional[str] = None,
) -> Optional[str]:
    if evidence is not None and evidence.get("verified") is False:
        return None
    from core.enterprise_databases.engines import SecurityEventsSessionLocal
    from core.enterprise_databases.schema import SecurityEventRecord

    ts, fecha, hora, _ = _ts_parts()
    eid = event_id or f"SEV-{uuid.uuid4().hex[:14]}"
    db = SecurityEventsSessionLocal()
    try:
        if legacy_ref:
            dup = db.query(SecurityEventRecord).filter(SecurityEventRecord.legacy_ref == legacy_ref).first()
            if dup:
                return dup.id
        row = SecurityEventRecord(
            id=eid,
            tenant_id=tenant_id,
            event_type=event_type[:80],
            event_date=fecha,
            event_time=hora,
            timestamp=ts,
            user_email=user_email,
            equipment=(equipment or "")[:256] or None,
            severity=severity,
            status=status,
            action_taken=action_taken,
            motor=motor,
            evidence_json=json.dumps(evidence or {}, ensure_ascii=False)[:12000],
            legacy_ref=legacy_ref,
        )
        db.add(row)
        db.commit()
        return eid
    except Exception as exc:
        db.rollback()
        logger.debug("record_security_event_domain: %s", exc)
        return None
    finally:
        db.close()


def record_audit_domain(
    *,
    action: str,
    user_email: Optional[str] = None,
    tenant_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    equipment: Optional[str] = None,
    outcome: Optional[str] = None,
    detail: Optional[dict] = None,
) -> None:
    from core.enterprise_databases.engines import AuditSessionLocal
    from core.enterprise_databases.schema import AuditLogRecord

    ts, fecha, hora, _ = _ts_parts()
    db = AuditSessionLocal()
    try:
        db.add(AuditLogRecord(
            tenant_id=tenant_id,
            user_email=user_email,
            event_date=fecha,
            event_time=hora,
            timestamp=ts,
            equipment=equipment,
            ip_address=ip_address,
            action=action[:120],
            outcome=outcome,
            detail_json=json.dumps(detail or {}, ensure_ascii=False)[:8000],
        ))
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.debug("record_audit_domain: %s", exc)
    finally:
        db.close()


def record_evidence_domain(
    *,
    evidence_id: str,
    tenant_id: Optional[str],
    evidence_type: str,
    motor: Optional[str],
    metadata: Optional[dict],
    related_event_id: Optional[str] = None,
    file_path: Optional[str] = None,
    content_hash: Optional[str] = None,
) -> None:
    from core.enterprise_databases.engines import EvidenceSessionLocal
    from core.enterprise_databases.schema import EvidenceRecord

    ts, _, _, _ = _ts_parts()
    db = EvidenceSessionLocal()
    try:
        if db.query(EvidenceRecord).filter(EvidenceRecord.id == evidence_id).first():
            return
        db.add(EvidenceRecord(
            id=evidence_id,
            tenant_id=tenant_id,
            related_event_id=related_event_id,
            evidence_type=evidence_type[:80],
            file_path=file_path,
            content_hash=content_hash,
            timestamp=ts,
            motor=motor,
            metadata_json=json.dumps(metadata or {}, ensure_ascii=False)[:12000],
            legacy_evidence_id=evidence_id,
        ))
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.debug("record_evidence_domain: %s", exc)
    finally:
        db.close()


def sync_network_profile_to_history(
    *,
    scope_id: str,
    tenant_id: Optional[str],
    lookup_key: str,
    identification: dict,
    state: dict,
    first_analysis_at: Optional[str],
    last_analysis_at: Optional[str],
) -> None:
    from core.enterprise_databases.engines import HistorySessionLocal
    from core.enterprise_databases.schema import NetworkProfileRecord

    db = HistorySessionLocal()
    try:
        row = db.query(NetworkProfileRecord).filter(NetworkProfileRecord.scope_id == scope_id).first()
        payload_id = json.dumps(identification, sort_keys=True, ensure_ascii=False)
        if not row:
            db.add(NetworkProfileRecord(
                scope_id=scope_id,
                tenant_id=tenant_id,
                lookup_key=lookup_key,
                identification_json=payload_id[:8000],
                first_analysis_at=first_analysis_at or last_analysis_at,
                last_analysis_at=last_analysis_at,
                state_json=json.dumps(state, ensure_ascii=False)[:8000],
            ))
        else:
            row.lookup_key = lookup_key
            row.tenant_id = tenant_id or row.tenant_id
            row.identification_json = payload_id[:8000]
            row.last_analysis_at = last_analysis_at
            row.state_json = json.dumps(state, ensure_ascii=False)[:8000]
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.debug("sync_network_profile_to_history: %s", exc)
    finally:
        db.close()


def sync_analysis_session_to_history(session_row: dict, tenant_id: Optional[str]) -> None:
    from core.enterprise_databases.engines import HistorySessionLocal
    from core.enterprise_databases.schema import HistoryAnalysisSession

    sid = session_row.get("session_id")
    if not sid:
        return
    db = HistorySessionLocal()
    try:
        existing = db.query(HistoryAnalysisSession).filter(
            HistoryAnalysisSession.session_audit_id == sid
        ).first()
        if existing:
            existing.status = session_row.get("status") or existing.status
            existing.finished_at = session_row.get("finished_at")
            existing.duration_sec = str(session_row.get("duration_sec")) if session_row.get("duration_sec") is not None else None
            existing.motors_json = json.dumps(session_row.get("motors_used") or [], ensure_ascii=False)
        else:
            db.add(HistoryAnalysisSession(
                scope_id=session_row.get("scope_id"),
                session_audit_id=sid,
                tenant_id=tenant_id,
                user_email=session_row.get("user_email"),
                equipment_json=json.dumps(session_row.get("equipment") or {}, ensure_ascii=False),
                started_at=session_row.get("started_at"),
                finished_at=session_row.get("finished_at"),
                duration_sec=str(session_row.get("duration_sec")) if session_row.get("duration_sec") is not None else None,
                motors_json=json.dumps(session_row.get("motors_used") or [], ensure_ascii=False),
                status=session_row.get("status") or "running",
            ))
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.debug("sync_analysis_session_to_history: %s", exc)
    finally:
        db.close()


def persist_kernel_insights(insights_payload: dict) -> None:
    from core.enterprise_databases.engines import KernelSessionLocal
    from core.enterprise_databases.schema import (
        KernelPatternRecord,
        KernelRecommendationRecord,
        KernelTrendRecord,
    )

    if not insights_payload.get("sufficient_data"):
        return
    ts, _, _, _ = _ts_parts()
    scope = insights_payload.get("scope_id") or "global"
    db = KernelSessionLocal()
    try:
        key_base = hashlib.sha256(json.dumps(insights_payload, sort_keys=True, default=str).encode()).hexdigest()[:16]
        db.add(KernelTrendRecord(
            trend_key=f"{scope}:{key_base}",
            summary=f"event_count={insights_payload.get('event_count')} threat_count={insights_payload.get('threat_event_count')}",
            sufficient_data=True,
            created_at=ts,
            payload_json=json.dumps(insights_payload, ensure_ascii=False, default=str)[:12000],
        ))
        for ins in insights_payload.get("insights") or []:
            kind = ins.get("kind") or "pattern"
            db.add(KernelPatternRecord(
                pattern_key=f"{scope}:{kind}:{key_base}",
                scope_id=scope,
                description=(ins.get("summary") or "")[:2000],
                source="network_security_history.build_kernel_network_insights",
                confidence="derived_from_verified_events",
                derived_from_event_count=int(insights_payload.get("event_count") or 0),
                created_at=ts,
                payload_json=json.dumps(ins, ensure_ascii=False, default=str)[:8000],
            ))
        db.add(KernelRecommendationRecord(
            recommendation_key=f"{scope}:auto:{key_base}",
            summary="Conclusiones derivadas de historial verificable (sin PII).",
            risk_model="event_frequency_and_severity",
            created_at=ts,
            payload_json=json.dumps({"insights": insights_payload.get("insights")}, ensure_ascii=False)[:8000],
        ))
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.debug("persist_kernel_insights: %s", exc)
    finally:
        db.close()


FORBIDDEN_STUDY_KEYS = frozenset({
    "email", "user_email", "empresa", "usuario", "nombre", "company", "nit", "direccion",
    "address", "phone", "telefono", "correo", "ip", "public_ip", "hostname", "client_name",
})


def save_anonymized_study_case(payload: dict, *, source_ref: Optional[str] = None) -> Optional[str]:
    """Solo campos permitidos — sin identificadores de cliente."""
    from core.enterprise_databases.engines import StudyCasesSessionLocal
    from core.enterprise_databases.schema import AnonymizedStudyCase

    clean = {k: v for k, v in payload.items() if k.lower() not in FORBIDDEN_STUDY_KEYS}
    ts, _, _, _ = _ts_parts()
    case_id = clean.get("id") or f"NOVUS-SC-{uuid.uuid4().hex[:10]}"
    db = StudyCasesSessionLocal()
    try:
        if db.query(AnonymizedStudyCase).filter(AnonymizedStudyCase.id == case_id).first():
            return case_id
        db.add(AnonymizedStudyCase(
            id=case_id,
            sector=clean.get("sector"),
            attack_type=clean.get("attack_type") or clean.get("tipo"),
            techniques_json=json.dumps(clean.get("techniques") or clean.get("techniques_json") or [], ensure_ascii=False),
            vulnerabilities_json=json.dumps(clean.get("vulnerabilities") or [], ensure_ascii=False),
            response_time_sec=str(clean.get("response_time_sec") or clean.get("tiempo_respuesta_sec") or ""),
            mechanisms_json=json.dumps(clean.get("mechanisms") or [], ensure_ascii=False),
            outcome=str(clean.get("outcome") or clean.get("resultado") or "")[:4000],
            lessons_json=json.dumps(clean.get("lessons") or clean.get("lecciones") or [], ensure_ascii=False),
            recommendations_json=json.dumps(clean.get("recommendations") or [], ensure_ascii=False),
            source_internal_ref=source_ref,
            created_at=ts,
        ))
        db.commit()
        record_audit_domain(
            action="study_case_anonymized_persisted",
            outcome="success",
            detail={"case_id": case_id, "source_ref": source_ref},
        )
        return case_id
    except Exception as exc:
        db.rollback()
        logger.error("save_anonymized_study_case: %s", exc)
        return None
    finally:
        db.close()


def list_anonymized_study_cases(limit: int = 50) -> List[dict]:
    from core.enterprise_databases.engines import StudyCasesSessionLocal
    from core.enterprise_databases.schema import AnonymizedStudyCase

    db = StudyCasesSessionLocal()
    try:
        rows = db.query(AnonymizedStudyCase).order_by(AnonymizedStudyCase.created_at.desc()).limit(limit).all()
        out = []
        for r in rows:
            out.append({
                "id": r.id,
                "sector": r.sector,
                "attack_type": r.attack_type,
                "techniques": json.loads(r.techniques_json or "[]"),
                "vulnerabilities": json.loads(r.vulnerabilities_json or "[]"),
                "response_time_sec": r.response_time_sec,
                "mechanisms": json.loads(r.mechanisms_json or "[]"),
                "outcome": r.outcome,
                "lessons": json.loads(r.lessons_json or "[]"),
                "recommendations": json.loads(r.recommendations_json or "[]"),
                "created_at": r.created_at,
            })
        return out
    finally:
        db.close()


def create_support_access_token(
    *,
    tenant_id: str,
    authorized_by_email: str,
    purpose: str,
    ttl_minutes: int = 60,
) -> Dict[str, Any]:
    from core.enterprise_databases.engines import AuditSessionLocal
    from core.enterprise_databases.schema import SupportAccessTokenRecord

    token = uuid.uuid4().hex
    now = datetime.now()
    created = now.strftime("%Y-%m-%d %H:%M:%S")
    expires = (now + timedelta(minutes=max(5, min(ttl_minutes, 480)))).strftime("%Y-%m-%d %H:%M:%S")
    db = AuditSessionLocal()
    try:
        db.add(SupportAccessTokenRecord(
            token=token,
            tenant_id=tenant_id,
            authorized_by_email=authorized_by_email,
            purpose=purpose[:500],
            created_at=created,
            expires_at=expires,
            status="active",
        ))
        db.commit()
    finally:
        db.close()
    record_audit_domain(
        action="support_access_token_created",
        user_email=authorized_by_email,
        tenant_id=tenant_id,
        outcome="success",
        detail={"expires_at": expires, "purpose": purpose[:200]},
    )
    return {"token": token, "expires_at": expires, "tenant_id": tenant_id}


def validate_support_token(token: str, support_email: str) -> Dict[str, Any]:
    from core.enterprise_databases.engines import AuditSessionLocal
    from core.enterprise_databases.schema import SupportAccessTokenRecord

    db = AuditSessionLocal()
    try:
        row = db.query(SupportAccessTokenRecord).filter(SupportAccessTokenRecord.token == token).first()
        if not row or row.status != "active":
            return {"valid": False, "reason": "token_not_found"}
        if row.expires_at < datetime.now().strftime("%Y-%m-%d %H:%M:%S"):
            row.status = "expired"
            db.commit()
            return {"valid": False, "reason": "expired"}
        row.used_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        row.used_by_email = support_email
        row.status = "used"
        db.commit()
        record_audit_domain(
            action="support_access_token_used",
            user_email=support_email,
            tenant_id=row.tenant_id,
            outcome="success",
            detail={"authorized_by": row.authorized_by_email, "purpose": row.purpose},
        )
        return {"valid": True, "tenant_id": row.tenant_id, "expires_at": row.expires_at}
    except Exception as exc:
        db.rollback()
        return {"valid": False, "reason": str(exc)[:120]}
    finally:
        db.close()


def hash_file_sha256(path: str) -> Optional[str]:
    if not path or not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def get_architecture_status() -> Dict[str, Any]:
    from core.enterprise_databases.paths import DOMAIN_LABELS, LEGACY_MONOLITH, ensure_data_dir

    ensure_data_dir()
    domains = {}
    for key, (label, path) in DOMAIN_LABELS.items():
        domains[key] = {
            "label": label,
            "path": path,
            "exists": os.path.isfile(path),
            "size_bytes": os.path.getsize(path) if os.path.isfile(path) else 0,
        }
    return {
        "domains": domains,
        "legacy_monolith": {"path": LEGACY_MONOLITH, "exists": os.path.isfile(LEGACY_MONOLITH)},
        "separation": "Por dominio — sin mezcla física de tablas entre bases",
    }
