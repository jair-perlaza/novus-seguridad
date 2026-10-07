"""
Protección avanzada contra accesos no autorizados — respuesta escalonada por origen.
No bloquea la API completa; solo limita IP/dispositivo/sesión con evidencia verificable.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from flask import has_request_context, request, session

from utils.logger import logger

INCIDENTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "auth_protection")
INCIDENTS_FILE = os.path.join(INCIDENTS_DIR, "incidents.jsonl")


def _cfg() -> dict:
    from services.auth_protection_config import get_auth_protection_config
    return get_auth_protection_config()


def _now() -> datetime:
    return datetime.now()


def _now_str() -> str:
    return _now().strftime("%Y-%m-%d %H:%M:%S")


def _ensure_incidents_dir() -> None:
    os.makedirs(INCIDENTS_DIR, exist_ok=True)


def build_device_fingerprint(user_agent: Optional[str], ip: Optional[str] = None) -> str:
    ua = (user_agent or "unknown").strip()[:512]
    raw = f"{ua}|{(ip or '')[:64]}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def get_session_id() -> str:
    if has_request_context():
        sid = session.get("_auth_protection_sid")
        if not sid:
            sid = uuid.uuid4().hex[:16]
            session["_auth_protection_sid"] = sid
        return sid
    return "no-session"


def _request_context() -> Dict[str, str]:
    if not has_request_context():
        return {"ip": "unknown", "user_agent": "", "session_id": "no-session"}
    from core.security import get_client_ip
    ip = get_client_ip()
    ua = request.headers.get("User-Agent", "")
    return {
        "ip": ip,
        "user_agent": ua,
        "session_id": get_session_id(),
        "device_fingerprint": build_device_fingerprint(ua, ip),
    }


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _window_start() -> str:
    return (_now() - timedelta(minutes=_cfg()["failure_window_minutes"])).strftime("%Y-%m-%d %H:%M:%S")


def _count_recent_failures(db, ip: str, device_fp: str, session_id: str) -> Dict[str, int]:
    from database import AuthAccessEvent

    since = _window_start()
    def _fail_q():
        return db.query(AuthAccessEvent).filter(
            AuthAccessEvent.success.is_(False),
            AuthAccessEvent.timestamp >= since,
        )

    by_ip = _fail_q().filter(AuthAccessEvent.ip_address == ip).count()
    by_device = _fail_q().filter(AuthAccessEvent.device_fingerprint == device_fp).count()
    by_session = (
        _fail_q().filter(AuthAccessEvent.session_id == session_id).count()
        if session_id and session_id != "no-session"
        else 0
    )
    return {
        "ip": by_ip,
        "device": by_device,
        "session": by_session,
        "max": max(by_ip, by_device, by_session),
    }


def _get_active_sanction(db, origin_type: str, origin_key: str):
    from database import AuthOriginSanction

    row = (
        db.query(AuthOriginSanction)
        .filter(
            AuthOriginSanction.origin_type == origin_type,
            AuthOriginSanction.origin_key == origin_key,
            AuthOriginSanction.status == "active",
        )
        .order_by(AuthOriginSanction.id.desc())
        .first()
    )
    if not row:
        return None
    until = _parse_ts(row.blocked_until)
    if until and until <= _now():
        row.status = "expired"
        row.updated_at = _now_str()
        db.commit()
        return None
    return row


def is_origin_blocked(ip: str, device_fp: Optional[str] = None, session_id: Optional[str] = None) -> Dict[str, Any]:
    """Comprueba si el origen está bloqueado temporalmente (solo ese origen)."""
    from database import SessionLocal, IPBloqueada

    device_fp = device_fp or build_device_fingerprint(None, ip)
    session_id = session_id or "no-session"
    db = SessionLocal()
    try:
        ip_row = db.query(IPBloqueada).filter(IPBloqueada.direccion_ip == str(ip)).first()
        if ip_row and ip_row.status in ("active", "pending_admin"):
            if ip_row.requires_admin_review or ip_row.status == "pending_admin":
                return {
                    "blocked": True,
                    "origin_type": "ip",
                    "origin_key": ip,
                    "sanction_level": 3,
                    "blocked_until": None,
                    "incident_id": None,
                    "reason": ip_row.block_reason or ip_row.razon,
                    "requires_admin_review": True,
                }
            until = _parse_ts(ip_row.blocked_until)
            if until and until <= _now():
                ip_row.status = "expired"
                db.commit()
            elif ip_row.status == "active":
                remaining = None
                if until:
                    remaining = max(0, int((until - _now()).total_seconds()))
                return {
                    "blocked": True,
                    "origin_type": "ip",
                    "origin_key": ip,
                    "sanction_level": 2,
                    "blocked_until": ip_row.blocked_until,
                    "remaining_seconds": remaining,
                    "incident_id": None,
                    "reason": ip_row.block_reason or ip_row.razon,
                }

        for otype, okey in (("ip", ip), ("device", device_fp), ("session", session_id)):
            if otype == "session" and session_id in ("no-session", ""):
                continue
            sanction = _get_active_sanction(db, otype, okey)
            if sanction and sanction.sanction_level >= 2:
                remaining = None
                until = _parse_ts(sanction.blocked_until)
                if until:
                    remaining = max(0, int((until - _now()).total_seconds()))
                return {
                    "blocked": True,
                    "origin_type": otype,
                    "origin_key": okey,
                    "sanction_level": sanction.sanction_level,
                    "blocked_until": sanction.blocked_until,
                    "remaining_seconds": remaining,
                    "incident_id": sanction.incident_id,
                    "reason": sanction.reason,
                    "requires_admin_review": sanction.sanction_level >= 3 and not sanction.blocked_until,
                }
        return {"blocked": False}
    finally:
        db.close()


def check_login_allowed(req=None) -> Dict[str, Any]:
    """Verifica si el origen actual puede intentar autenticarse."""
    ctx = _request_context()
    status = is_origin_blocked(ctx["ip"], ctx["device_fingerprint"], ctx["session_id"])
    if status.get("blocked"):
        if status.get("requires_admin_review"):
            return {
                "allowed": False,
                "message": (
                    "Origen bloqueado por reincidencia persistente. "
                    "Se requiere revisión y autorización de un administrador."
                ),
                **status,
            }
        until = status.get("blocked_until") or "próximamente"
        return {
            "allowed": False,
            "message": (
                f"Origen temporalmente bloqueado por intentos repetidos de acceso no autorizado. "
                f"Reintente después de {until}."
            ),
            **status,
        }
    out = {"allowed": True, **ctx}
    try:
        from services.zero_trust_session_service import evaluate_session_risk

        out["zero_trust"] = evaluate_session_risk(
            ip=ctx["ip"],
            user_agent=ctx.get("user_agent"),
            session_id=ctx.get("session_id"),
        )
    except Exception:
        pass
    return out


def _client_os(user_agent: Optional[str]) -> str:
    try:
        from services.login_session_audit_service import parse_client_from_user_agent
        return parse_client_from_user_agent(user_agent).get("os_name", "No disponible")
    except Exception:
        return "No disponible"


def _block_duration_minutes(recurrence: int) -> Optional[int]:
    cfg = _cfg()
    admin_after = cfg.get("admin_review_after_recurrences", 2)
    if recurrence >= admin_after:
        return None
    if recurrence >= 1:
        return cfg.get("recurrence_block_minutes", 1440)
    return cfg.get("first_block_minutes", 30)


def _sync_ip_bloqueada(
    db,
    ip: str,
    reason: str,
    *,
    failed_attempts: int = 0,
    email: Optional[str] = None,
    user_agent: Optional[str] = None,
    blocked_until: Optional[str] = None,
    recurrence: int = 0,
    requires_admin: bool = False,
    evidence: Optional[dict] = None,
) -> None:
    from database import IPBloqueada

    ts = _now_str()
    existing = db.query(IPBloqueada).filter(IPBloqueada.direccion_ip == str(ip)).first()
    payload = {
        "razon": reason,
        "blocked_at": ts,
        "blocked_until": blocked_until,
        "failed_attempts": failed_attempts,
        "target_email": email,
        "user_agent": (user_agent or "")[:512] if user_agent else None,
        "os_name": _client_os(user_agent),
        "block_reason": reason,
        "evidence_json": json.dumps(evidence or {}, ensure_ascii=False),
        "recurrence_count": recurrence,
        "requires_admin_review": requires_admin,
        "status": "pending_admin" if requires_admin else "active",
    }
    if existing:
        for k, v in payload.items():
            setattr(existing, k, v)
    else:
        db.add(IPBloqueada(direccion_ip=str(ip), **payload))


def _upsert_sanction(
    db,
    origin_type: str,
    origin_key: str,
    level: int,
    failed_attempts: int,
    blocked_until: Optional[str],
    incident_id: Optional[str],
    reason: str,
    evidence: dict,
    recurrence: int = 0,
):
    from database import AuthOriginSanction

    row = _get_active_sanction(db, origin_type, origin_key)
    if row:
        row.sanction_level = max(row.sanction_level, level)
        row.failed_attempts = failed_attempts
        row.recurrence_count = max(row.recurrence_count, recurrence)
        if blocked_until:
            row.blocked_until = blocked_until
        row.incident_id = incident_id or row.incident_id
        row.reason = reason
        row.evidence_json = json.dumps(evidence, ensure_ascii=False)
        row.updated_at = _now_str()
    else:
        db.add(
            AuthOriginSanction(
                origin_type=origin_type,
                origin_key=origin_key,
                sanction_level=level,
                failed_attempts=failed_attempts,
                recurrence_count=recurrence,
                blocked_until=blocked_until,
                incident_id=incident_id,
                status="active",
                reason=reason,
                evidence_json=json.dumps(evidence, ensure_ascii=False),
            )
        )


def _create_incident(
    ip: str,
    email: Optional[str],
    device_fp: str,
    session_id: str,
    level: int,
    failed_counts: dict,
    reason: str,
    actions: List[str],
    confidence: str,
    risk: str,
) -> Dict[str, Any]:
    incident_id = f"AUTH-{uuid.uuid4().hex[:10].upper()}"
    incident = {
        "id": incident_id,
        "type": "unauthorized_access_attempt",
        "timestamp": _now_str(),
        "level": level,
        "ip": ip,
        "email": email,
        "device_fingerprint": device_fp,
        "session_id": session_id,
        "reason": reason,
        "confidence": confidence,
        "risk": risk,
        "evidence": {
            "failed_counts_window": failed_counts,
            "window_minutes": _cfg()["failure_window_minutes"],
            "thresholds": _cfg(),
        },
        "actions_executed": actions,
        "status": "open",
    }
    _ensure_incidents_dir()
    try:
        with open(INCIDENTS_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(incident, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.error("auth_protection incident write: %s", exc)
    return incident


def _notify_kernel(incident: dict) -> None:
    try:
        from services.defense_coordinator import defense_coordinator

        defense_coordinator.notify_kernel_incident(
            "auth_protection_service",
            "AUTH_PROTECTION_INCIDENT",
            incident.get("reason", "")[:400],
            incident_id=incident.get("id"),
            severity=incident.get("risk", "medium"),
            evidence=incident.get("evidence"),
        )
    except Exception as exc:
        logger.debug("auth_protection kernel notify: %s", exc)


def _record_defense(phase: str, action: str, outcome: str, evidence: dict, **kwargs) -> None:
    try:
        from services.defense_evidence_registry import record_defense_event

        record_defense_event(
            phase=phase,
            action=action,
            motor="auth_protection_service",
            outcome=outcome,
            threat_type="unauthorized_access",
            evidence=evidence,
            reversible=kwargs.get("reversible", True),
            revert_key=kwargs.get("revert_key"),
            detail=kwargs.get("detail"),
            confidence=kwargs.get("confidence"),
            finding_id=kwargs.get("finding_id"),
        )
    except Exception as exc:
        logger.debug("auth_protection defense record: %s", exc)


def _current_sanction_level(db, ip: str) -> int:
    from database import AuthOriginSanction

    row = (
        db.query(AuthOriginSanction)
        .filter(
            AuthOriginSanction.origin_type == "ip",
            AuthOriginSanction.origin_key == ip,
            AuthOriginSanction.status == "active",
        )
        .order_by(AuthOriginSanction.sanction_level.desc())
        .first()
    )
    if not row:
        return 0
    until = _parse_ts(row.blocked_until)
    if until and until <= _now() and row.sanction_level >= 2:
        row.status = "expired"
        row.updated_at = _now_str()
        db.commit()
        return 0
    return int(row.sanction_level or 0)


def _run_adaptive_defense_async(incident: dict) -> None:
    import threading

    def _worker():
        _activate_adaptive_defense(incident)

    threading.Thread(target=_worker, daemon=True).start()


def _activate_adaptive_defense(incident: dict) -> Optional[dict]:
    try:
        from services.adaptive_defense_engine import activate_after_failed_remediation

        finding = {
            "id": incident["id"],
            "ip": incident.get("ip"),
            "type": "brute_force_auth",
            "severity": "high",
            "verified": True,
            "evidence": incident.get("evidence"),
        }
        return activate_after_failed_remediation(
            incident["id"],
            finding,
            remediation_result={"status": "failed", "reason": "auth_brute_force"},
            user_email=incident.get("email"),
        )
    except Exception as exc:
        logger.debug("auth_protection adaptive defense: %s", exc)
        return None


def _next_recurrence(db, ip: str) -> int:
    from database import AuthOriginSanction

    row = (
        db.query(AuthOriginSanction)
        .filter(AuthOriginSanction.origin_type == "ip", AuthOriginSanction.origin_key == ip)
        .order_by(AuthOriginSanction.id.desc())
        .first()
    )
    if not row:
        return 0
    if row.status == "active" and row.sanction_level >= 2:
        return int(row.recurrence_count or 0)
    if row.status in ("expired", "revoked"):
        return int(row.recurrence_count or 0) + 1
    return int(row.recurrence_count or 0)


def _target_level(total: int) -> int:
    cfg = _cfg()
    if total >= cfg["block_attempt"]:
        return 2
    if total >= cfg["monitoring_attempt"]:
        return 1
    if total >= 1:
        return 0
    return 0


def _evaluate_escalation(
    db,
    ip: str,
    email: Optional[str],
    device_fp: str,
    session_id: str,
    route: str,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    cfg = _cfg()
    counts = _count_recent_failures(db, ip, device_fp, session_id)
    total = counts["max"] + 1
    current = _current_sanction_level(db, ip)
    target = _target_level(total)
    result: Dict[str, Any] = {"sanction_level": current, "actions": [], "incident": None, "risk_level": "bajo"}

    if total <= cfg["risk_log_attempts_max"]:
        result["risk_level"] = "medio" if total >= 2 else "bajo"
        if total == cfg["risk_log_attempts_max"]:
            result["risk_level"] = "elevado"
        _record_defense(
            "detect", "auth_failure_logged", "detected",
            {"ip": ip, "email": email, "attempt": total, "failed_counts": counts, "verified": True},
            detail=f"Intento fallido {total}/{cfg['risk_log_attempts_max']} — riesgo {result['risk_level']}",
            confidence="Media",
        )
        return result

    if target == 0 or (target == 1 and current >= 1):
        if target == 0:
            return result

    evidence = {
        "ip": ip,
        "email": email,
        "device_fingerprint": device_fp,
        "session_id": session_id,
        "route": route,
        "user_agent": user_agent,
        "os_name": _client_os(user_agent),
        "failed_counts": counts,
        "attempt_number": total,
        "verified": True,
    }

    if target >= 2 and total >= cfg["block_attempt"]:
        recurrence = _next_recurrence(db, ip)
        minutes = _block_duration_minutes(recurrence)
        requires_admin = minutes is None
        if requires_admin:
            blocked_until = None
            reason = (
                f"Reincidencia persistente: {total} intentos fallidos desde {ip}. "
                "Revisión administrativa requerida."
            )
            level = 3
            actions = ["block_origin", "admin_review", "notify_kernel"]
            risk = "critico"
        else:
            blocked_until = (_now() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
            reason = (
                f"Bloqueo automático: {total} intentos fallidos desde {ip} "
                f"({'reincidencia' if recurrence else 'primer bloqueo'})"
            )
            level = 2 if recurrence == 0 else 3
            actions = ["block_origin", "register_evidence", "notify_kernel"]
            if recurrence >= 1:
                actions.append("adaptive_defense")
            risk = "alto" if recurrence == 0 else "critico"

        incident = _create_incident(
            ip, email, device_fp, session_id, level, counts, reason, actions, "Alta", risk,
        )
        incident["evidence"]["user_agent"] = user_agent
        incident["evidence"]["os_name"] = _client_os(user_agent)
        incident["evidence"]["blocked_until"] = blocked_until
        incident["evidence"]["recurrence"] = recurrence
        _upsert_sanction(
            db, "ip", ip, level, total, blocked_until, incident["id"], reason, evidence, recurrence,
        )
        _sync_ip_bloqueada(
            db, ip, reason,
            failed_attempts=total, email=email, user_agent=user_agent,
            blocked_until=blocked_until, recurrence=recurrence,
            requires_admin=requires_admin, evidence=evidence,
        )
        if recurrence >= 1 and not requires_admin:
            _run_adaptive_defense_async(incident)
        _notify_kernel(incident)
        _record_defense(
            "contain", f"auth_origin_block_l{level}", "success", evidence,
            revert_key=ip, detail=reason, confidence="Alta", finding_id=incident["id"],
        )
        result.update({"sanction_level": level, "actions": actions, "incident": incident, "risk_level": risk})
        return result

    if target >= 1 and total >= cfg["monitoring_attempt"]:
        reason = f"Monitoreo reforzado: {total} intentos fallidos consecutivos desde {ip}"
        _upsert_sanction(db, "ip", ip, 1, total, None, None, reason, evidence)
        _record_defense(
            "detect", "auth_monitoring_reinforced", "detected", evidence,
            detail=reason, confidence="Media",
        )
        result.update({"sanction_level": 1, "actions": ["increase_monitoring"], "risk_level": "elevado"})
        return result

    return result


def record_auth_attempt(
    *,
    success: bool,
    email: Optional[str] = None,
    route: str = "login",
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Registra intento y aplica escalación solo al origen atacante."""
    from database import SessionLocal, AuthAccessEvent, registrar_log_seguridad

    ctx = _request_context()
    ip = ip or ctx["ip"]
    user_agent = user_agent if user_agent is not None else ctx["user_agent"]
    session_id = session_id or ctx["session_id"]
    device_fp = build_device_fingerprint(user_agent, ip)

    db = SessionLocal()
    try:
        escalation: Dict[str, Any] = {"sanction_level": 0}
        if not success:
            try:
                from services.hostile_environment_service import evaluate_login_pattern_escalation
                evaluate_login_pattern_escalation(db, ip, email)
            except Exception as exc:
                logger.debug("login pattern escalation: %s", exc)
            escalation = _evaluate_escalation(db, ip, email, device_fp, session_id, route, user_agent)

        event = AuthAccessEvent(
            ip_address=ip,
            email=email,
            device_fingerprint=device_fp,
            session_id=session_id,
            user_agent=(user_agent or "")[:512],
            route=route,
            success=success,
            sanction_level=escalation.get("sanction_level", 0),
            incident_id=(escalation.get("incident") or {}).get("id"),
            evidence_json=json.dumps(
                {"failed_counts": escalation.get("incident", {}).get("evidence", {}).get("failed_counts_window")}
                if escalation.get("incident")
                else {},
                ensure_ascii=False,
            )
            if escalation.get("incident")
            else None,
        )
        db.add(event)

        evt = "LOGIN_SUCCESS" if success else "LOGIN_FAILED"
        detail = f"email={email or 'unknown'} ip={ip} device={device_fp[:12]} route={route}"
        if escalation.get("sanction_level"):
            detail += f" sanction_level={escalation['sanction_level']}"
        registrar_log_seguridad(db, evt, detail)
        db.commit()

        return {
            "recorded": True,
            "ip": ip,
            "device_fingerprint": device_fp,
            "success": success,
            **escalation,
        }
    except Exception as exc:
        db.rollback()
        logger.error("record_auth_attempt: %s", exc)
        return {"recorded": False, "error": str(exc)}
    finally:
        db.close()


def apply_ip_block_from_scan(ip: str, evidence: dict, threat_type: str = "brute_force") -> None:
    """Integración con escaneo background de novus_security_integration."""
    from database import SessionLocal

    if not ip or ip == "unknown":
        return
    cfg = _cfg()
    db = SessionLocal()
    try:
        attempts = int(evidence.get("attempts") or cfg["block_attempt"])
        minutes = _block_duration_minutes(0) or cfg.get("first_block_minutes", 30)
        blocked_until = (_now() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
        reason = f"Auth anomaly scan — {threat_type}: {evidence.get('evidence', '')[:100]}"
        _upsert_sanction(
            db, "ip", str(ip), 2, attempts, blocked_until, None, reason, evidence,
        )
        _sync_ip_bloqueada(
            db, str(ip), reason,
            failed_attempts=attempts,
            user_agent=evidence.get("user_agent"),
            blocked_until=blocked_until,
            evidence=evidence,
        )
        db.commit()
        _record_defense(
            "contain", "block_ip_auth_scan", "success", evidence,
            revert_key=str(ip), detail=reason, confidence="Alta",
        )
    except Exception as exc:
        db.rollback()
        logger.debug("apply_ip_block_from_scan: %s", exc)
    finally:
        db.close()


def _remaining_seconds(blocked_until: Optional[str]) -> Optional[int]:
    until = _parse_ts(blocked_until)
    if not until:
        return None
    return max(0, int((until - _now()).total_seconds()))


def list_blocked_ips(
    limit: int = 100,
    query: Optional[str] = None,
    include_expired: bool = False,
) -> List[Dict[str, Any]]:
    from database import SessionLocal, IPBloqueada
    from utils.ip_validation import is_documentation_ip

    db = SessionLocal()
    try:
        q = db.query(IPBloqueada).order_by(IPBloqueada.id.desc())
        if not include_expired:
            q = q.filter(IPBloqueada.status.in_(("active", "pending_admin")))
        rows = q.limit(limit * 3).all()
        out: List[Dict[str, Any]] = []
        needle = (query or "").strip().lower()
        for row in rows:
            if is_documentation_ip(row.direccion_ip):
                continue
            if needle and needle not in (row.direccion_ip or "").lower():
                if needle not in (row.target_email or "").lower():
                    continue
            evidence = {}
            try:
                evidence = json.loads(row.evidence_json or "{}")
            except Exception:
                pass
            out.append({
                "ip": row.direccion_ip,
                "blocked_at": row.blocked_at,
                "blocked_until": row.blocked_until,
                "remaining_seconds": _remaining_seconds(row.blocked_until),
                "failed_attempts": row.failed_attempts,
                "target_email": row.target_email,
                "user_agent": row.user_agent,
                "os_name": row.os_name,
                "reason": row.block_reason or row.razon,
                "recurrence_count": row.recurrence_count,
                "requires_admin_review": bool(row.requires_admin_review),
                "status": row.status,
                "evidence": evidence,
            })
            if len(out) >= limit:
                break
        return out
    finally:
        db.close()


def get_block_detail(ip: str) -> Optional[Dict[str, Any]]:
    from database import SessionLocal, IPBloqueada, AuthOriginSanction, AuthAccessEvent

    db = SessionLocal()
    try:
        row = db.query(IPBloqueada).filter(IPBloqueada.direccion_ip == str(ip)).first()
        if not row:
            return None
        evidence = {}
        try:
            evidence = json.loads(row.evidence_json or "{}")
        except Exception:
            pass
        sanctions = (
            db.query(AuthOriginSanction)
            .filter(AuthOriginSanction.origin_type == "ip", AuthOriginSanction.origin_key == str(ip))
            .order_by(AuthOriginSanction.id.desc())
            .limit(20)
            .all()
        )
        since = _window_start()
        failures = (
            db.query(AuthAccessEvent)
            .filter(
                AuthAccessEvent.ip_address == str(ip),
                AuthAccessEvent.success.is_(False),
                AuthAccessEvent.timestamp >= since,
            )
            .order_by(AuthAccessEvent.id.desc())
            .limit(50)
            .all()
        )
        return {
            "ip": row.direccion_ip,
            "blocked_at": row.blocked_at,
            "blocked_until": row.blocked_until,
            "remaining_seconds": _remaining_seconds(row.blocked_until),
            "failed_attempts": row.failed_attempts,
            "target_email": row.target_email,
            "user_agent": row.user_agent,
            "os_name": row.os_name,
            "reason": row.block_reason or row.razon,
            "recurrence_count": row.recurrence_count,
            "requires_admin_review": bool(row.requires_admin_review),
            "status": row.status,
            "evidence": evidence,
            "sanction_history": [
                {
                    "level": s.sanction_level,
                    "status": s.status,
                    "blocked_until": s.blocked_until,
                    "reason": s.reason,
                    "incident_id": s.incident_id,
                    "updated_at": s.updated_at,
                }
                for s in sanctions
            ],
            "recent_failures": [
                {
                    "timestamp": f.timestamp,
                    "email": f.email,
                    "user_agent": f.user_agent,
                    "route": f.route,
                }
                for f in failures
            ],
        }
    finally:
        db.close()


def unblock_ip(ip: str, admin_email: Optional[str] = None) -> Dict[str, Any]:
    from database import SessionLocal, IPBloqueada, AuthOriginSanction

    db = SessionLocal()
    try:
        row = db.query(IPBloqueada).filter(IPBloqueada.direccion_ip == str(ip)).first()
        if not row:
            return {"success": False, "message": "IP no encontrada en el registro de bloqueos"}
        row.status = "revoked"
        row.block_reason = f"Desbloqueo manual por administrador ({admin_email or 'admin'})"
        sanctions = (
            db.query(AuthOriginSanction)
            .filter(
                AuthOriginSanction.origin_type == "ip",
                AuthOriginSanction.origin_key == str(ip),
                AuthOriginSanction.status == "active",
            )
            .all()
        )
        for s in sanctions:
            s.status = "revoked"
            s.updated_at = _now_str()
            s.reason = f"Revocado manualmente — {s.reason or ''}"[:500]
        db.commit()
        _record_defense(
            "recover", "auth_ip_manual_unblock", "success",
            {"ip": ip, "admin": admin_email, "verified": True},
            revert_key=str(ip),
            detail=f"IP {ip} desbloqueada manualmente",
            confidence="Alta",
        )
        return {"success": True, "ip": ip, "message": "IP desbloqueada correctamente"}
    except Exception as exc:
        db.rollback()
        logger.error("unblock_ip: %s", exc)
        return {"success": False, "message": str(exc)}
    finally:
        db.close()


def list_incidents(limit: int = 30, incident_id: Optional[str] = None) -> List[dict]:
    if not os.path.isfile(INCIDENTS_FILE):
        return []
    rows: List[dict] = []
    try:
        with open(INCIDENTS_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception as exc:
        logger.debug("list_incidents read: %s", exc)
        return []

    if incident_id:
        return [r for r in rows if r.get("id") == incident_id]
    return list(reversed(rows[-limit:]))


def get_incident(incident_id: str) -> Optional[dict]:
    matches = list_incidents(incident_id=incident_id)
    return matches[0] if matches else None


def get_protection_status() -> Dict[str, Any]:
    from database import SessionLocal, AuthAccessEvent, AuthOriginSanction

    db = SessionLocal()
    try:
        since = _window_start()
        recent_failures = db.query(AuthAccessEvent).filter(
            AuthAccessEvent.success.is_(False),
            AuthAccessEvent.timestamp >= since,
        ).count()
        active_sanctions = db.query(AuthOriginSanction).filter(
            AuthOriginSanction.status == "active",
            AuthOriginSanction.sanction_level >= 2,
        ).count()
        monitoring = db.query(AuthOriginSanction).filter(
            AuthOriginSanction.status == "active",
            AuthOriginSanction.sanction_level == 1,
        ).count()
        return {
            "thresholds": _cfg(),
            "recent_failures_window": recent_failures,
            "active_blocks": active_sanctions,
            "elevated_monitoring": monitoring,
            "incidents_total": len(list_incidents(limit=1000)),
            "blocked_ips_total": len(list_blocked_ips(limit=1000)),
        }
    finally:
        db.close()


def get_kernel_context(incident_id: Optional[str] = None) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {
        "module": "auth_protection",
        "status": get_protection_status(),
        "incidents": list_incidents(limit=15),
        "blocked_ips": list_blocked_ips(limit=10),
    }
    if incident_id:
        ctx["selected_incident"] = get_incident(incident_id)
    try:
        from services.device_connection_monitor import get_recent_connection_summary
        ctx["device_connections"] = get_recent_connection_summary(limit=15)
    except Exception as exc:
        ctx["device_connections_error"] = str(exc)
    return ctx


def answer_kernel_query(question: str) -> Optional[str]:
    q = (question or "").lower()
    auth_triggers = (
        "acceso no autorizado", "brute force", "fuerza bruta", "login fallido",
        "bloqueo ip", "auth protection", "intentos fallidos", "credential",
        "centro de bloqueos", "ip bloqueada",
    )
    device_triggers = (
        "dispositivo", "dispositivos", "conectado", "desconect",
        "conexion de red", "conexión de red", "historial dispositivo",
        "cambio de ip", "hostname", "arp",
    )
    if not any(t in q for t in auth_triggers + device_triggers):
        return None

    cfg = _cfg()
    status = get_protection_status()
    lines: List[str] = []

    if any(t in q for t in auth_triggers):
        lines.extend([
            "Protección de autenticación NOVUS (por origen, no bloqueo global):",
            f"• Fallos recientes ({cfg['failure_window_minutes']} min): {status['recent_failures_window']}",
            f"• Orígenes bloqueados: {status['active_blocks']}",
            f"• Monitoreo reforzado: {status['elevated_monitoring']}",
            f"• Umbrales: riesgo 1-{cfg['risk_log_attempts_max']}, monitoreo={cfg['monitoring_attempt']}, bloqueo={cfg['block_attempt']}",
            f"• Bloqueo inicial: {cfg['first_block_minutes']} min | Reincidencia: {cfg['recurrence_block_minutes']} min",
        ])
        blocked = list_blocked_ips(limit=5)
        if blocked:
            lines.append("IPs bloqueadas (evidencia real):")
            for b in blocked[:3]:
                rem = b.get("remaining_seconds")
                rem_txt = f"{rem // 60} min restantes" if rem is not None else "revisión admin"
                lines.append(
                    f"  - {b['ip']}: {b.get('reason', '')[:60]} ({rem_txt}, intentos={b.get('failed_attempts')})"
                )
        incidents = list_incidents(limit=3)
        if incidents:
            lines.append("Incidentes recientes:")
            for inc in incidents:
                lines.append(
                    f"  - {inc.get('id')}: {inc.get('reason', '')[:80]} "
                    f"(riesgo={inc.get('risk')}, confianza={inc.get('confidence')})"
                )

    if any(t in q for t in device_triggers):
        try:
            from services.device_connection_monitor import list_events, get_recent_connection_summary
            events = list_events(limit=8)
            if events:
                lines.append("Eventos recientes de conexión/desconexión (ARP/AIE):")
                for ev in events[:5]:
                    lines.append(
                        f"  - [{ev.get('timestamp')}] {ev.get('event_type')} "
                        f"{ev.get('ip') or ev.get('mac')} "
                        f"trust={ev.get('trust_score')} riesgo={ev.get('risk_level')}"
                    )
            else:
                lines.append("Sin eventos de conexión/desconexión registrados aún (requieren escaneos ARP consecutivos).")
        except Exception as exc:
            lines.append(f"Monitoreo de dispositivos: error consultando eventos — {exc}")

    return "\n".join(lines) if lines else None


class AuthProtectionService:
    check_login_allowed = staticmethod(check_login_allowed)
    is_origin_blocked = staticmethod(is_origin_blocked)
    record_auth_attempt = staticmethod(record_auth_attempt)
    list_incidents = staticmethod(list_incidents)
    get_incident = staticmethod(get_incident)
    get_protection_status = staticmethod(get_protection_status)
    get_kernel_context = staticmethod(get_kernel_context)
    answer_kernel_query = staticmethod(answer_kernel_query)
    apply_ip_block_from_scan = staticmethod(apply_ip_block_from_scan)
    list_blocked_ips = staticmethod(list_blocked_ips)
    get_block_detail = staticmethod(get_block_detail)
    unblock_ip = staticmethod(unblock_ip)


auth_protection = AuthProtectionService()
