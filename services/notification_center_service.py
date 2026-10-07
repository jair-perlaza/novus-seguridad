"""
Centro de Notificaciones / Eventos Inteligentes — solo eventos reales de motores NOVUS.
Persistencia SQL: novus_notifications.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, or_

from utils.logger import logger

CATEGORIES = frozenset(
    {
        "seguridad",
        "amenazas",
        "kernel_ia",
        "escaneos",
        "reportes",
        "usuarios",
        "dispositivos",
        "red",
        "cumplimiento",
        "sistema",
        "actualizaciones",
        "comportamiento",
    }
)
PRIORITIES = frozenset({"info", "warning", "high", "critical"})
STATUSES = frozenset({"unread", "read", "archived"})
NOTIFICATION_KINDS = frozenset({"security", "system"})
SECURITY_CATEGORIES = frozenset({"seguridad", "amenazas", "comportamiento", "red", "dispositivos", "cumplimiento"})
SYSTEM_CATEGORIES = frozenset({"sistema", "reportes", "escaneos", "usuarios", "actualizaciones", "kernel_ia"})


def _now_parts() -> Tuple[str, str, str]:
    now = datetime.now()
    return (
        now.strftime("%Y-%m-%d %H:%M:%S"),
        now.strftime("%Y-%m-%d"),
        now.strftime("%H:%M:%S"),
    )


def _norm_priority(p: str) -> str:
    p = (p or "info").lower().strip()
    mapping = {
        "informacion": "info",
        "información": "info",
        "advertencia": "warning",
        "media": "warning",
        "medium": "warning",
        "alta": "high",
        "critica": "critical",
        "crítica": "critical",
    }
    p = mapping.get(p, p)
    return p if p in PRIORITIES else "info"


def _norm_category(c: str) -> str:
    c = (c or "sistema").lower().strip().replace(" ", "_")
    aliases = {
        "comportamiento_del_cliente": "comportamiento",
        "behavior": "comportamiento",
        "compliance": "cumplimiento",
        "network": "red",
        "devices": "dispositivos",
        "users": "usuarios",
        "scans": "escaneos",
        "threats": "amenazas",
        "security": "seguridad",
        "kernel": "kernel_ia",
    }
    c = aliases.get(c, c)
    return c if c in CATEGORIES else "sistema"


def _derive_notification_kind(category: str, explicit: Optional[str] = None) -> str:
    if explicit in NOTIFICATION_KINDS:
        return explicit
    cat = _norm_category(category)
    if cat in SECURITY_CATEGORIES:
        return "security"
    return "system"


def _norm_email(email: str) -> str:
    return (email or "").strip().lower()


def _norm_tenant(tenant_id: Optional[str]) -> Optional[str]:
    tid = (tenant_id or "").strip()
    return tid or None


def _apply_user_scope(q, email: str, tenant_id: Optional[str] = None, *, include_broadcast: bool = False):
    """
    Scope estricto por usuario (índice user_email) — evita MULTI-INDEX OR
    que escaneaba user_email IS NULL en cada listado (causa raíz p95 ~21s).
    Broadcast (user_email NULL) solo si include_broadcast=True.
    Tenant: filas del tenant o broadcasts de plataforma (tenant_id NULL) del mismo usuario.
    """
    from database import NovusNotification

    email = _norm_email(email)
    if include_broadcast:
        q = q.filter(
            or_(NovusNotification.user_email == email, NovusNotification.user_email.is_(None))
        )
    else:
        q = q.filter(NovusNotification.user_email == email)
    tid = _norm_tenant(tenant_id)
    if tid:
        q = q.filter(
            or_(NovusNotification.tenant_id == tid, NovusNotification.tenant_id.is_(None))
        )
    return q


def _apply_kind_scope(q, notification_kind: Optional[str]):
    from database import NovusNotification

    if notification_kind == "security":
        return q.filter(NovusNotification.category.in_(tuple(SECURITY_CATEGORIES)))
    if notification_kind == "system":
        return q.filter(NovusNotification.category.in_(tuple(SYSTEM_CATEGORIES)))
    return q


def _apply_list_filters(
    q,
    *,
    status: Optional[str],
    category: Optional[str],
    priority: Optional[str],
):
    from database import NovusNotification

    if status and status != "all":
        if status == "unread":
            q = q.filter(NovusNotification.status == "unread")
        elif status == "archived":
            q = q.filter(NovusNotification.status == "archived")
        else:
            q = q.filter(NovusNotification.status == status)
    else:
        q = q.filter(NovusNotification.status != "archived")
    if category and category not in ("all", "todas"):
        q = q.filter(NovusNotification.category == _norm_category(category))
    if priority and priority not in ("all",):
        if priority in ("criticas", "críticas", "critical"):
            q = q.filter(NovusNotification.priority == "critical")
        else:
            q = q.filter(NovusNotification.priority == _norm_priority(priority))
    return q


def _count_unread(
    db,
    email: str,
    *,
    tenant_id: Optional[str] = None,
    notification_kind: Optional[str] = None,
) -> int:
    """
    Unread count for badge.
    kind=security → threat-grade only (not APE observations flooding 99+).
    """
    from database import NovusNotification

    q = db.query(func.count(NovusNotification.id))
    q = _apply_user_scope(q, email, tenant_id)
    q = q.filter(NovusNotification.status == "unread")
    q = _apply_kind_scope(q, notification_kind)
    if notification_kind == "security":
        # Exclude behavioral observations (adaptive_profile_engine) from threat badge.
        # They remain listable under category filters; badge = confirmed/threat-grade unread.
        q = q.filter(
            or_(
                NovusNotification.category == "amenazas",
                NovusNotification.priority.in_(("high", "critical")),
            )
        )
        q = q.filter(
            or_(
                NovusNotification.source_motor.is_(None),
                NovusNotification.source_motor != "adaptive_profile_engine",
            )
        )
        # Lab fixtures never inflate LIVE client badge unless explicitly allowed
        import os as _os

        allow_lab = _os.environ.get("NOVUS_ALLOW_TEST_FIXTURE_NOTIFS", "").strip() == "1"
        if not allow_lab:
            q = q.filter(
                or_(
                    NovusNotification.title.is_(None),
                    ~NovusNotification.title.ilike("%TEST_FIXTURE%"),
                )
            )
    return int(q.scalar() or 0)


def emit_notification(
    *,
    title: str,
    description: Optional[str] = None,
    category: str = "sistema",
    priority: str = "info",
    notification_kind: Optional[str] = None,
    user_email: Optional[str] = None,
    tenant_id: Optional[str] = None,
    related_user: Optional[str] = None,
    related_equipment: Optional[str] = None,
    detail_url: Optional[str] = None,
    incident_url: Optional[str] = None,
    source_motor: Optional[str] = None,
    source_ref: Optional[str] = None,
    payload: Optional[dict] = None,
) -> Dict[str, Any]:
    """Crea una notificación real. Dedup por source_motor+source_ref si ambos existen."""
    if not title or not str(title).strip():
        return {"ok": False, "reason": "empty_title"}
    from database import SessionLocal, NovusNotification
    from utils.data_provenance import validate_security_notification

    cat = _norm_category(category)
    pri = _norm_priority(priority)
    kind = _derive_notification_kind(cat, notification_kind)
    ts, fecha, hora = _now_parts()
    payload_obj = dict(payload or {})
    payload_obj.setdefault("notification_kind", kind)
    payload_obj.setdefault("data_origin", "live")
    if kind == "security":
        ok_sec, sec_reason = validate_security_notification(
            source_motor=source_motor,
            source_ref=source_ref,
            payload=payload_obj,
        )
        if not ok_sec:
            logger.warning(
                "emit_notification blocked security notification: %s title=%r motor=%s",
                sec_reason,
                title[:80],
                source_motor,
            )
            return {"ok": False, "reason": sec_reason or "security_evidence_required"}
    db = SessionLocal()
    try:
        if source_motor and source_ref:
            existing = (
                db.query(NovusNotification)
                .filter(
                    NovusNotification.source_motor == source_motor,
                    NovusNotification.source_ref == str(source_ref),
                    NovusNotification.status != "archived",
                )
                .first()
            )
            if existing:
                return {
                    "ok": True,
                    "deduped": True,
                    "notification_id": existing.notification_id,
                }
        nid = f"NTF-{uuid.uuid4().hex[:14]}"
        row = NovusNotification(
            notification_id=nid,
            user_email=(user_email or "").strip().lower() or None,
            tenant_id=tenant_id,
            category=cat,
            priority=pri,
            title=str(title)[:240],
            description=(description or "")[:4000] or None,
            status="unread",
            related_user=related_user,
            related_equipment=related_equipment,
            detail_url=detail_url,
            incident_url=incident_url,
            source_motor=source_motor,
            source_ref=str(source_ref) if source_ref is not None else None,
            event_date=fecha,
            event_time=hora,
            created_at=ts,
            payload_json=json.dumps(payload_obj, ensure_ascii=False, default=str)[:8000]
            if payload_obj
            else None,
        )
        db.add(row)
        db.commit()
        try:
            from services.http_endpoint_cache import invalidate

            invalidate("/api/notifications")
        except Exception:
            pass
        return {"ok": True, "notification_id": nid}
    except Exception as exc:
        db.rollback()
        logger.error("emit_notification: %s", exc)
        return {"ok": False, "error": str(exc)[:200]}
    finally:
        db.close()


def _serialize(row) -> Dict[str, Any]:
    payload = None
    if row.payload_json:
        try:
            payload = json.loads(row.payload_json)
        except Exception:
            payload = None
    kind = _derive_notification_kind(row.category or "sistema")
    if payload and isinstance(payload, dict):
        kind = payload.get("notification_kind") or kind
    return {
        "notification_id": row.notification_id,
        "title": row.title,
        "description": row.description,
        "category": row.category,
        "notification_kind": kind,
        "priority": row.priority,
        "status": row.status,
        "event_date": row.event_date,
        "event_time": row.event_time,
        "created_at": row.created_at,
        "related_user": row.related_user,
        "related_equipment": row.related_equipment,
        "detail_url": row.detail_url,
        "incident_url": row.incident_url,
        "source_motor": row.source_motor,
        "source_ref": row.source_ref,
        "read_at": row.read_at,
        "archived_at": row.archived_at,
        "payload": payload,
    }


def _tenant_allows_row(row, tenant_id: Optional[str]) -> bool:
    tid = _norm_tenant(tenant_id)
    if not tid or not row.tenant_id:
        return True
    return str(row.tenant_id).strip() == tid


def list_notifications(
    user_email: str,
    *,
    tenant_id: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    priority: Optional[str] = None,
    notification_kind: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    from database import SessionLocal, NovusNotification
    from utils.data_provenance import validate_security_notification

    email = _norm_email(user_email)
    try:
        sync_canonical_alerts_to_notifications(email, tenant_id=tenant_id)
    except Exception as exc:
        logger.debug("sync_canonical_alerts (list): %s", exc)

    limit = max(1, min(int(limit or 50), 100))
    offset = max(0, int(offset or 0))
    db = SessionLocal()
    try:
        base = db.query(NovusNotification)
        base = _apply_user_scope(base, email, tenant_id)
        base = _apply_list_filters(base, status=status, category=category, priority=priority)
        base = _apply_kind_scope(base, notification_kind)

        unread = _count_unread(db, email, tenant_id=tenant_id, notification_kind=notification_kind)

        rows = (
            base.order_by(NovusNotification.created_at.desc(), NovusNotification.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        items: List[Dict[str, Any]] = []
        for row in rows:
            if not _tenant_allows_row(row, tenant_id):
                continue
            item = _serialize(row)
            if item.get("notification_kind") == "security":
                ok_sec, _ = validate_security_notification(
                    source_motor=item.get("source_motor"),
                    source_ref=item.get("source_ref"),
                    payload=item.get("payload"),
                )
                if not ok_sec:
                    continue
            items.append(item)

        return {
            "status": "success",
            "unread_count": unread,
            "count": len(items),
            "limit": limit,
            "offset": offset,
            "has_more": len(rows) >= limit,
            "notifications": items,
            "categories": sorted(CATEGORIES),
            "filters": [
                "all",
                "unread",
                "critical",
                "security",
                "system",
                "seguridad",
                "amenazas",
                "sistema",
                "kernel_ia",
                "red",
                "reportes",
                "usuarios",
                "escaneos",
            ],
            "notification_kinds": sorted(NOTIFICATION_KINDS),
        }
    finally:
        db.close()


def get_notification(
    notification_id: str,
    user_email: str,
    *,
    tenant_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    from database import SessionLocal, NovusNotification

    email = _norm_email(user_email)
    db = SessionLocal()
    try:
        row = (
            db.query(NovusNotification)
            .filter(NovusNotification.notification_id == notification_id)
            .first()
        )
        if not row:
            return None
        if row.user_email and row.user_email != email:
            return None
        if not _tenant_allows_row(row, tenant_id):
            return None
        return _serialize(row)
    finally:
        db.close()


def mark_read(
    notification_id: str,
    user_email: str,
    *,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    from database import SessionLocal, NovusNotification

    email = _norm_email(user_email)
    db = SessionLocal()
    try:
        row = (
            db.query(NovusNotification)
            .filter(NovusNotification.notification_id == notification_id)
            .first()
        )
        if not row or (row.user_email and row.user_email != email):
            return {"ok": False, "reason": "not_found"}
        if not _tenant_allows_row(row, tenant_id):
            return {"ok": False, "reason": "not_found"}
        if row.status == "archived":
            return {"ok": False, "reason": "archived"}
        row.status = "read"
        row.read_at = _now_parts()[0]
        db.commit()
        try:
            from services.http_endpoint_cache import invalidate

            invalidate("/api/notifications")
        except Exception:
            pass
        return {"ok": True, "notification_id": notification_id, "status": "read"}
    except Exception as exc:
        db.rollback()
        return {"ok": False, "error": str(exc)[:200]}
    finally:
        db.close()


def archive_notification(
    notification_id: str,
    user_email: str,
    *,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    from database import SessionLocal, NovusNotification

    email = _norm_email(user_email)
    db = SessionLocal()
    try:
        row = (
            db.query(NovusNotification)
            .filter(NovusNotification.notification_id == notification_id)
            .first()
        )
        if not row or (row.user_email and row.user_email != email):
            return {"ok": False, "reason": "not_found"}
        if not _tenant_allows_row(row, tenant_id):
            return {"ok": False, "reason": "not_found"}
        row.status = "archived"
        row.archived_at = _now_parts()[0]
        db.commit()
        try:
            from services.http_endpoint_cache import invalidate

            invalidate("/api/notifications")
        except Exception:
            pass
        return {"ok": True, "notification_id": notification_id, "status": "archived"}
    except Exception as exc:
        db.rollback()
        return {"ok": False, "error": str(exc)[:200]}
    finally:
        db.close()


def unread_count(
    user_email: str,
    *,
    tenant_id: Optional[str] = None,
    notification_kind: Optional[str] = None,
) -> int:
    from database import SessionLocal

    # Pull verified canonical security alerts into the bell (deduped).
    try:
        sync_canonical_alerts_to_notifications(user_email, tenant_id=tenant_id)
    except Exception as exc:
        logger.debug("sync_canonical_alerts (unread): %s", exc)

    db = SessionLocal()
    try:
        return _count_unread(
            db,
            user_email,
            tenant_id=tenant_id,
            notification_kind=notification_kind,
        )
    finally:
        db.close()


_SYNC_LAST: Dict[str, float] = {}
_SYNC_LOCK = __import__("threading").Lock()
_SYNC_MIN_INTERVAL_SEC = 45.0


def _priority_from_risk(risk: Optional[str]) -> str:
    s = str(risk or "").upper()
    if "CRIT" in s:
        return "critical"
    if "HIGH" in s or "ALTA" in s:
        return "high"
    if "MED" in s or "WARN" in s:
        return "warning"
    if s in ("", "NOT_AVAILABLE", "UNKNOWN", "NONE"):
        return "info"
    if "LOW" in s or "INFO" in s:
        return "info"
    return "warning"


def sync_canonical_alerts_to_notifications(
    user_email: str,
    *,
    tenant_id: Optional[str] = None,
    limit: int = 40,
) -> Dict[str, Any]:
    """
    Bridge: alerts_canonical_service → notification center (campanita).
    Does not invent severity/confidence/evidence. Dedupes on source_ref.
    Tenant scope preserved via get_canonical_alerts(tenant_id=...).
    """
    import time as _time

    email = _norm_email(user_email)
    if not email:
        return {"ok": False, "reason": "no_email"}
    tid = _norm_tenant(tenant_id)
    cache_key = f"{email}|{tid or '-'}"
    now = _time.time()
    with _SYNC_LOCK:
        last = _SYNC_LAST.get(cache_key, 0.0)
        if (now - last) < _SYNC_MIN_INTERVAL_SEC:
            return {"ok": True, "skipped": True, "reason": "throttle"}
        _SYNC_LAST[cache_key] = now

    try:
        from services.alerts_canonical_service import get_canonical_alerts
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:160]}

    if not tid:
        return {"ok": True, "synced": 0, "reason": "no_tenant"}

    try:
        alerts = get_canonical_alerts(include_resolved=False, limit=limit, tenant_id=tid)
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:160]}

    synced = 0
    skipped = 0
    for alert in alerts or []:
        if not isinstance(alert, dict):
            skipped += 1
            continue
        # Lab fixtures: never as LIVE client malware. Only when explicitly allowed.
        blob = json.dumps(alert, ensure_ascii=False, default=str).lower()
        is_lab_fixture = any(
            m in blob
            for m in (
                "test_fixture",
                "synthetic_test_only",
                "eicar-standard",
                "csv_bas_validation",
                "test_harness",
            )
        )
        allow_lab = False
        if is_lab_fixture:
            import os as _os

            env = (_os.environ.get("NOVUS_ENV") or "").strip().lower()
            allow_lab = (
                _os.environ.get("NOVUS_ALLOW_TEST_FIXTURE_NOTIFS", "").strip() == "1"
                or env in ("lab", "test", "testing", "development", "dev")
            )
            if not allow_lab:
                skipped += 1
                continue
        aid = str(alert.get("id") or alert.get("event_id") or "").strip()
        if not aid:
            skipped += 1
            continue
        risk = alert.get("risk_level")
        if str(risk or "").upper() in ("NOT_AVAILABLE", "UNKNOWN"):
            # Informational only if explicitly info/low — skip unconfirmed severity as "threat"
            skipped += 1
            continue
        motor = str(alert.get("motor") or alert.get("fuente") or "alerts_canonical").strip()
        evidence_items = alert.get("evidence_items") or []
        evidence_summary = alert.get("evidence_summary")
        if not evidence_items and not evidence_summary and not alert.get("verified"):
            skipped += 1
            continue
        conf = alert.get("confidence")
        if conf is None or str(conf).strip() == "":
            conf = "NOT_AVAILABLE"
        ts = alert.get("timestamp") or alert.get("date") or "NOT_AVAILABLE"
        base_title = str(alert.get("threat_type") or "Alerta de seguridad")[:200]
        title = (f"[TEST_FIXTURE] {base_title}" if is_lab_fixture else base_title)[:240]
        desc_parts = [
            f"Severidad: {risk or 'NOT_AVAILABLE'}",
            f"Confianza: {conf}",
            f"Estado: {alert.get('status') or 'NOT_AVAILABLE'}",
            f"Origen: {alert.get('origin') or alert.get('origin_ip') or 'NOT_AVAILABLE'}",
            f"event_id/ref: {aid}",
        ]
        if is_lab_fixture:
            desc_parts.insert(0, "TEST_FIXTURE · SYNTHETIC_TEST_ONLY · no es malware LIVE de cliente")
        if evidence_summary:
            desc_parts.append(str(evidence_summary)[:500])
        payload = {
            "event_id": alert.get("event_id") or aid,
            "alert_id": aid,
            "evidence": evidence_summary or evidence_items,
            "evidence_items": evidence_items,
            "evidence_id": alert.get("finding_id") or alert.get("event_id") or aid,
            "finding_id": alert.get("finding_id"),
            "severity": risk,
            "confidence": conf,
            "timestamp": ts,
            "threat_type": alert.get("threat_type"),
            "status": alert.get("status"),
            "remediation_status": alert.get("remediation_status") or "NOT_AVAILABLE",
            "verifiable": True,
            "data_origin": "alerts_canonical_service",
            "scope": alert.get("scope") or "NOT_AVAILABLE",
            "tenant_id": tid,
            "test_fixture": bool(is_lab_fixture),
            "synthetic_test_only": bool(is_lab_fixture),
            "data_state": "TEST_FIXTURE" if is_lab_fixture else "LIVE",
        }
        out = emit_notification(
            title=title,
            description=" · ".join(desc_parts)[:4000],
            category="amenazas",
            priority=_priority_from_risk(str(risk) if risk else None),
            notification_kind="security",
            user_email=email,
            tenant_id=tid,
            related_equipment=str(alert.get("origin") or alert.get("origin_ip") or "")[:240] or None,
            detail_url="/incidentes",
            incident_url="/incidentes",
            source_motor=motor[:120],
            source_ref=aid[:240],
            payload=payload,
        )
        if out.get("ok") and not out.get("deduped"):
            synced += 1
        else:
            skipped += 1
    return {"ok": True, "synced": synced, "skipped": skipped, "tenant_id": tid}