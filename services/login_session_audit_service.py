"""
Auditoría avanzada de inicio de sesión y monitoreo posterior al acceso.
Solo datos legítimos disponibles (IP, User-Agent, motores NOVUS).
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from flask import has_request_context as flask_has_request_context

from utils.logger import logger


def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_client_from_user_agent(user_agent: Optional[str]) -> Dict[str, str]:
    """Extrae OS, navegador y tipo de dispositivo del User-Agent (sin inventar datos)."""
    ua = (user_agent or "").strip()
    if not ua:
        return {"os_name": "No disponible", "browser": "No disponible", "device_type": "Desconocido"}

    os_name = "No disponible"
    if "Windows NT 10" in ua:
        os_name = "Windows 10/11"
    elif "Windows" in ua:
        os_name = "Windows"
    elif "Mac OS X" in ua or "Macintosh" in ua:
        os_name = "macOS"
    elif "Android" in ua:
        os_name = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        os_name = "iOS"
    elif "Linux" in ua:
        os_name = "Linux"

    browser = "No disponible"
    if "Edg/" in ua:
        browser = "Microsoft Edge"
    elif "Chrome/" in ua and "Chromium" not in ua:
        browser = "Chrome"
    elif "Firefox/" in ua:
        browser = "Firefox"
    elif "Safari/" in ua and "Chrome" not in ua:
        browser = "Safari"
    elif "curl/" in ua.lower():
        browser = "curl"
    elif "python-requests" in ua.lower():
        browser = "Python requests"

    device_type = "Desktop"
    if re.search(r"iPad|Tablet", ua, re.I):
        device_type = "Tablet"
    elif re.search(r"Mobile|Android.*Mobile|iPhone", ua, re.I):
        device_type = "Mobile"

    return {"os_name": os_name, "browser": browser, "device_type": device_type}


def count_recent_failed_attempts(email: str, ip: str, window_minutes: int = 15) -> int:
    from database import SessionLocal, AuthAccessEvent

    cutoff = (datetime.now() - timedelta(minutes=window_minutes)).strftime("%Y-%m-%d %H:%M:%S")
    db = SessionLocal()
    try:
        q = db.query(AuthAccessEvent).filter(
            AuthAccessEvent.success.is_(False),
            AuthAccessEvent.timestamp >= cutoff,
        )
        if email:
            q = q.filter(AuthAccessEvent.email == email)
        if ip:
            q = q.filter(AuthAccessEvent.ip_address == ip)
        return q.count()
    finally:
        db.close()


def _config_fingerprint() -> str:
    try:
        from services.config_service import load_config
        cfg = load_config()
        raw = json.dumps(cfg, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    except Exception as exc:
        logger.debug("config fingerprint: %s", exc)
        return "unavailable"


def run_post_login_security_check(user_email: str, ip: str, session_audit_id: str) -> Dict[str, Any]:
    """Verificación rápida post-login usando motores reales de NOVUS."""
    evidence: Dict[str, Any] = {"session_audit_id": session_audit_id, "checked_at": _now_str()}
    risks: List[Dict[str, Any]] = []
    actions: List[Dict[str, Any]] = []

    try:
        from services.novus_security_integration import novus_security
        anomalies = novus_security._detect_auth_anomalies()
        evidence["auth_anomalies"] = anomalies[:10] if anomalies else []
        if anomalies:
            risks.append({
                "type": "auth_anomaly",
                "severity": "medium",
                "detail": f"{len(anomalies)} anomalía(s) de autenticación detectada(s)",
                "source": "novus_security._detect_auth_anomalies",
            })
    except Exception as exc:
        evidence["auth_anomalies_error"] = str(exc)[:200]

    try:
        from services.novus_security_integration import novus_security

        summary = novus_security.get_cached_security_summary() or {}
        cache = summary.get("threats") or {}
        vulns = summary.get("vulnerabilities") or cache.get("vulnerabilities") or []
        count = len(vulns) if isinstance(vulns, list) else 0
        evidence["vulnerability_count"] = count
        evidence["vulnerability_source"] = "get_cached_security_summary"
        if count > 0:
            risks.append({
                "type": "vulnerabilities",
                "severity": "low" if count < 5 else "medium",
                "detail": f"{count} vulnerabilidad(es) en caché del motor",
                "source": "novus_security.scan_vulnerabilities",
            })
    except Exception as exc:
        evidence["vulnerabilities_error"] = str(exc)[:200]

    cfg_fp = _config_fingerprint()
    evidence["config_fingerprint"] = cfg_fp

    from database import SessionLocal, LoginSessionAudit
    db = SessionLocal()
    try:
        prev = (
            db.query(LoginSessionAudit)
            .filter(LoginSessionAudit.user_email == user_email, LoginSessionAudit.login_result == "success")
            .order_by(LoginSessionAudit.login_at.desc())
            .offset(1)
            .first()
        )
        if prev and prev.config_fingerprint and prev.config_fingerprint != cfg_fp and cfg_fp != "unavailable":
            risks.append({
                "type": "config_change",
                "severity": "medium",
                "detail": "Huella de configuración distinta a la sesión anterior",
                "source": "config_service.load_config",
            })
    finally:
        db.close()

    try:
        from database import SessionLocal, NetworkDeviceInventory
        db = SessionLocal()
        try:
            total = db.query(NetworkDeviceInventory).count()
            unknown = db.query(NetworkDeviceInventory).filter(
                (NetworkDeviceInventory.vendor.is_(None)) | (NetworkDeviceInventory.vendor == "")
            ).count()
            evidence["network_devices"] = {"total": total, "unknown_vendor": unknown}
            if unknown > 0 and total > 0 and unknown / max(total, 1) >= 0.5:
                risks.append({
                    "type": "unknown_devices",
                    "severity": "low",
                    "detail": f"{unknown}/{total} dispositivos sin vendor consolidado",
                    "source": "network_device_inventory",
                })
        finally:
            db.close()
    except Exception as exc:
        evidence["network_devices_error"] = str(exc)[:200]

    try:
        from services.auth_protection_service import auth_protection
        prot = auth_protection.get_protection_status()
        evidence["auth_protection"] = prot
        if prot.get("active_sanctions", 0) > 0:
            risks.append({
                "type": "active_sanctions",
                "severity": "medium",
                "detail": f"{prot.get('active_sanctions')} sanción(es) activa(s) en el sistema",
                "source": "auth_protection.get_protection_status",
            })
    except Exception as exc:
        evidence["auth_protection_error"] = str(exc)[:200]

    try:
        from services.defense_evidence_registry import list_recent_events, record_defense_event
        recent = list_recent_events(limit=15)
        evidence["defense_events_recent"] = len(recent)
        detect_events = [e for e in recent if e.get("phase") in ("detect", "contain", "respond")]
        if detect_events:
            evidence["defense_events_sample"] = detect_events[:5]
            risks.append({
                "type": "defense_activity",
                "severity": "info",
                "detail": f"{len(detect_events)} evento(s) recientes de defensa",
                "source": "defense_evidence_registry",
            })
        record_defense_event(
            phase="audit",
            action="post_login_security_check",
            motor="login_session_audit_service",
            outcome="success",
            user_email=user_email,
            detail=f"session={session_audit_id} risks={len(risks)}",
            evidence={"risk_count": len(risks), "ip": ip},
        )
        actions.append({"action": "post_login_check", "motor": "login_session_audit_service", "status": "completed"})
    except Exception as exc:
        evidence["defense_registry_error"] = str(exc)[:200]

    high = sum(1 for r in risks if r.get("severity") in ("high", "medium"))
    if high >= 2:
        security_status = "alert"
    elif risks:
        security_status = "warning"
    else:
        security_status = "clean"

    return {
        "security_status": security_status,
        "evidence": evidence,
        "risks": risks,
        "actions": actions,
    }


def open_login_session(
    *,
    user_id: int,
    user_email: str,
    ip: str,
    session_id: str,
    user_agent: str,
    login_result: str = "success",
    route: str = "login",
) -> Dict[str, Any]:
    """Registra sesión exitosa + ejecuta verificación post-login."""
    from database import SessionLocal, LoginSessionAudit, registrar_log_seguridad

    client = parse_client_from_user_agent(user_agent)
    attempts = count_recent_failed_attempts(user_email, ip) + 1
    audit_id = f"LS-{uuid.uuid4().hex[:12]}"
    cfg_fp = _config_fingerprint()

    tenant_id = None
    try:
        from database import SessionLocal as _SL, Usuario
        from services.tenant_scope_service import resolve_tenant_id

        _db = _SL()
        try:
            urow = _db.query(Usuario).filter(Usuario.id == user_id).first()
            if urow:
                tenant_id = resolve_tenant_id(urow)
        finally:
            _db.close()
    except Exception:
        pass

    db = SessionLocal()
    try:
        row = LoginSessionAudit(
            id=audit_id,
            tenant_id=tenant_id,
            user_id=user_id,
            user_email=user_email,
            login_at=_now_str(),
            ip_address=ip,
            session_id=session_id,
            os_name=client["os_name"],
            browser=client["browser"],
            device_type=client["device_type"],
            user_agent=(user_agent or "")[:512],
            login_result=login_result,
            attempt_count=attempts,
            config_fingerprint=cfg_fp,
            security_status="pending",
            active=True,
        )
        db.add(row)
        registrar_log_seguridad(
            db,
            "SESSION_START",
            f"user={user_email} ip={ip} session={session_id} device={client['device_type']} attempts={attempts}",
        )
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("open_login_session: %s", exc)
        return {"success": False, "error": str(exc)}
    finally:
        db.close()

    _run_post_login_check_async(user_email, ip, audit_id, user_id=int(user_id))

    try:
        from services.behavior_baseline_service import record_login_activity_async

        record_login_activity_async(
            user_email,
            ip,
            audit_id,
            browser=client.get("browser"),
            os_name=client.get("os_name"),
        )
    except Exception as bae_exc:
        logger.debug("behavior login hook: %s", bae_exc)

    try:
        from services.enterprise_data_service import record_audit_domain
        from services.tenant_scope_service import resolve_tenant_id

        class _AuditUser:
            email = user_email
            nit_pyme = None
            company_id = None

        au = _AuditUser()
        try:
            from database import SessionLocal, Usuario

            _db = SessionLocal()
            try:
                urow = _db.query(Usuario).filter(Usuario.id == user_id).first()
                if urow:
                    au.nit_pyme = urow.nit_pyme
            finally:
                _db.close()
        except Exception:
            pass
        record_audit_domain(
            action="login_session_open",
            user_email=user_email,
            tenant_id=resolve_tenant_id(au),
            ip_address=ip,
            equipment=client.get("device_type"),
            outcome="success",
            detail={"session_audit_id": audit_id, "browser": client.get("browser")},
        )
    except Exception:
        pass

    if flask_has_request_context():
        from flask import session as flask_session
        flask_session["_novus_login_session_id"] = audit_id

    return {
        "success": True,
        "session_audit_id": audit_id,
        "attempt_count": attempts,
        "client": client,
        "security_status": "pending",
        "risks_count": 0,
    }


def _run_post_login_check_async(user_email: str, ip: str, audit_id: str, user_id: Optional[int] = None) -> None:
    """Ejecuta verificación post-login y monitoreo continuo sin bloquear la respuesta HTTP de login."""
    from services.bounded_background import submit_background

    def _worker():
        try:
            from services.continuous_monitoring_orchestrator import start_post_login_monitoring

            start_post_login_monitoring(user_email, user_id, ip, audit_id)
        except Exception as exc:
            logger.error("post_login monitoring start: %s", exc, exc_info=True)

        try:
            _persist_post_login_check(user_email, ip, audit_id)
        except Exception as exc:
            logger.error("post_login check persist: %s", exc, exc_info=True)

    submit_background(_worker, name=f"PostLoginCheck-{audit_id[:8]}")


def _persist_post_login_check(user_email: str, ip: str, audit_id: str) -> None:
    from database import SessionLocal, LoginSessionAudit

    check = run_post_login_security_check(user_email, ip, audit_id)
    db = SessionLocal()
    try:
        row = db.query(LoginSessionAudit).filter(LoginSessionAudit.id == audit_id).first()
        if row:
            row.security_status = check["security_status"]
            row.post_login_check_json = json.dumps(check["evidence"], ensure_ascii=False)[:8000]
            row.risks_json = json.dumps(check["risks"], ensure_ascii=False)[:4000]
            row.actions_json = json.dumps(check["actions"], ensure_ascii=False)[:2000]
            db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("post_login persist: %s", exc)
    finally:
        db.close()


def close_login_session(
    session_audit_id: Optional[str] = None,
    user_email: Optional[str] = None,
    *,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Cierra sesión activa registrando hora y duración."""
    from database import SessionLocal, LoginSessionAudit, registrar_log_seguridad
    from services.tenant_isolation_service import tenant_ids_match

    if not session_audit_id and flask_has_request_context():
        from flask import session as flask_session
        session_audit_id = flask_session.get("_novus_login_session_id")

    db = SessionLocal()
    try:
        row = None
        if session_audit_id:
            row = db.query(LoginSessionAudit).filter(
                LoginSessionAudit.id == session_audit_id, LoginSessionAudit.active.is_(True),
            ).first()
        elif user_email:
            row = (
                db.query(LoginSessionAudit)
                .filter(LoginSessionAudit.user_email == user_email, LoginSessionAudit.active.is_(True))
                .order_by(LoginSessionAudit.login_at.desc())
                .first()
            )
        if not row:
            return {"closed": False, "reason": "no_active_session"}
        if tenant_id and not tenant_ids_match(row.tenant_id, tenant_id):
            return {"closed": False, "reason": "forbidden"}

        logout_at = _now_str()
        try:
            login_dt = datetime.strptime(row.login_at, "%Y-%m-%d %H:%M:%S")
            logout_dt = datetime.strptime(logout_at, "%Y-%m-%d %H:%M:%S")
            duration = int((logout_dt - login_dt).total_seconds())
        except Exception:
            duration = None

        row.logout_at = logout_at
        row.duration_seconds = duration
        row.active = False
        registrar_log_seguridad(
            db,
            "SESSION_END",
            f"user={row.user_email} session={row.session_id} duration_sec={duration}",
        )
        db.commit()
        closed_id = row.id
        try:
            from services.continuous_monitoring_orchestrator import release_user_monitoring_session

            release_user_monitoring_session(row.user_email)
        except Exception as rel_exc:
            logger.debug("release monitoring session: %s", rel_exc)
        # Server-side revoke of THIS session id only (never by email — would block future logins).
        try:
            from services.swarm_defense.session_revoke import revoke_user_sessions

            revoke_user_sessions(
                session_id=closed_id,
                reason="user_logout",
                actor="logout",
            )
        except Exception as rev_exc:
            logger.warning("logout session revoke: %s", rev_exc)
        return {"closed": True, "session_audit_id": closed_id, "duration_seconds": duration}
    except Exception as exc:
        db.rollback()
        logger.error("close_login_session: %s", exc)
        return {"closed": False, "error": str(exc)}
    finally:
        db.close()


def is_login_session_active(session_audit_id: Optional[str]) -> bool:
    """
    True solo si el id de auditoría NOVUS existe y sigue active=True.
    Fuente canónica server-side para invalidar cookies firmadas reutilizadas tras logout.
    """
    if not session_audit_id:
        return False
    from database import SessionLocal, LoginSessionAudit

    db = SessionLocal()
    try:
        row = (
            db.query(LoginSessionAudit.active)
            .filter(LoginSessionAudit.id == str(session_audit_id))
            .first()
        )
        if row is None:
            return False
        return bool(row[0])
    except Exception as exc:
        logger.debug("is_login_session_active: %s", exc)
        return False
    finally:
        db.close()


def list_login_sessions(
    limit: int = 50,
    email: Optional[str] = None,
    *,
    tenant_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    from database import SessionLocal, LoginSessionAudit
    from utils.ip_validation import is_documentation_ip
    from services.tenant_isolation_service import sql_tenant_filter

    if not tenant_id:
        return []

    db = SessionLocal()
    try:
        q = db.query(LoginSessionAudit).order_by(LoginSessionAudit.login_at.desc())
        q = sql_tenant_filter(q, LoginSessionAudit, tenant_id)
        if email:
            q = q.filter(LoginSessionAudit.user_email == email)
        rows = q.limit(min(limit * 2, 400)).all()
        out = []
        for row in rows:
            if is_documentation_ip(row.ip_address):
                continue
            out.append(_serialize_session(row))
            if len(out) >= min(limit, 200):
                break
        return out
    finally:
        db.close()


def get_login_session(
    session_id: str,
    detail: bool = True,
    *,
    tenant_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    from database import SessionLocal, LoginSessionAudit
    from services.tenant_isolation_service import tenant_ids_match

    if not tenant_id:
        return None

    db = SessionLocal()
    try:
        row = db.query(LoginSessionAudit).filter(LoginSessionAudit.id == session_id).first()
        if not row or not tenant_ids_match(row.tenant_id, tenant_id):
            return None
        return _serialize_session(row, detail=True) if row else None
    finally:
        db.close()


def _serialize_session(row, detail: bool = False) -> Dict[str, Any]:
    base = {
        "id": row.id,
        "user_email": row.user_email,
        "user_id": row.user_id,
        "login_at": row.login_at,
        "logout_at": row.logout_at,
        "duration_seconds": row.duration_seconds,
        "ip_address": row.ip_address,
        "session_id": row.session_id,
        "os_name": row.os_name,
        "browser": row.browser,
        "device_type": row.device_type,
        "login_result": row.login_result,
        "attempt_count": row.attempt_count,
        "security_status": row.security_status,
        "active": row.active,
    }
    if detail:
        for key, attr, default in (
            ("post_login_check", "post_login_check_json", "{}"),
            ("risks", "risks_json", "[]"),
            ("actions", "actions_json", "[]"),
        ):
            raw = getattr(row, attr) or default
            try:
                base[key] = json.loads(raw)
            except Exception:
                base[key] = raw
        base["user_agent"] = row.user_agent
        base["config_fingerprint"] = row.config_fingerprint
    return base


def finalize_successful_login(user, route: str = "login") -> Dict[str, Any]:
    """Hook unificado tras login_user exitoso."""
    from flask import has_request_context, request
    from core.security import get_client_ip
    from services.auth_protection_service import auth_protection, get_session_id

    ip = get_client_ip() if has_request_context() else "unknown"
    ua = request.headers.get("User-Agent", "") if has_request_context() else ""
    sid = get_session_id()
    try:
        from services.loadtest_runtime import is_loadtest_email

        if is_loadtest_email(user.email):
            from flask import session as flask_session

            provisional = f"LS-LT-{uuid.uuid4().hex[:12]}"
            flask_session["_novus_login_session_id"] = provisional
            return {"status": "ok", "loadtest_audit": "skipped", "session_audit_id": provisional}
    except Exception:
        pass
    auth_protection.record_auth_attempt(
        success=True, email=user.email, route=route, ip=ip, user_agent=ua, session_id=sid,
    )
    return open_login_session(
        user_id=int(user.id),
        user_email=user.email,
        ip=ip,
        session_id=sid,
        user_agent=ua,
        login_result="success",
        route=route,
    )
