"""
Registro empresarial con aprobación manual del administrador principal (CEO).
"""
from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from werkzeug.security import generate_password_hash

from utils.logger import logger

# Safe, non-enumerating message key for NIT / identity conflicts.
NIT_CONFLICT_ERROR = "registration_data_rejected"


def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _normalize_nit(nit: Optional[str]) -> str:
    """Normalize NIT for storage and uniqueness (strip + collapse internal spaces)."""
    raw = (nit or "").strip()
    if not raw:
        return ""
    return " ".join(raw.split())


def _nit_owned_by_usuario(db, nit: str, *, exclude_email: Optional[str] = None) -> bool:
    from database import Usuario

    if not nit:
        return False
    q = db.query(Usuario).filter(Usuario.nit_pyme == nit)
    if exclude_email:
        q = q.filter(Usuario.email != exclude_email.strip().lower())
    return q.first() is not None


def _nit_held_by_open_request(
    db, nit: str, *, exclude_request_id: Optional[int] = None, exclude_email: Optional[str] = None
) -> bool:
    from database import RegistrationRequest

    if not nit:
        return False
    q = (
        db.query(RegistrationRequest)
        .filter(
            RegistrationRequest.nit == nit,
            RegistrationRequest.status.in_(("pending", "approved")),
        )
    )
    if exclude_request_id is not None:
        q = q.filter(RegistrationRequest.id != exclude_request_id)
    if exclude_email:
        q = q.filter(RegistrationRequest.email != exclude_email.strip().lower())
    return q.first() is not None


def create_registration_request(
    *,
    email: str,
    company_name: str,
    nit: str,
    sector: Optional[str] = None,
    servicio: Optional[str] = None,
    empleados: Optional[str] = None,
    infra: Optional[dict] = None,
    request_ip: Optional[str] = None,
) -> Dict[str, Any]:
    from database import SessionLocal, RegistrationRequest, Usuario

    email = (email or "").strip().lower()
    nit_norm = _normalize_nit(nit)
    if not nit_norm:
        return {"ok": False, "error": NIT_CONFLICT_ERROR}
    db = SessionLocal()
    try:
        if db.query(Usuario).filter(Usuario.email == email).first():
            return {"ok": False, "error": "email_already_registered"}
        existing = db.query(RegistrationRequest).filter(RegistrationRequest.email == email).first()
        if existing and existing.status in ("pending", "approved"):
            return {"ok": False, "error": "registration_already_pending", "status": existing.status}

        # 1 EMPRESA = 1 CUENTA = 1 TENANT — reject duplicate NIT early (no enumeration detail).
        if _nit_owned_by_usuario(db, nit_norm) or _nit_held_by_open_request(db, nit_norm):
            return {"ok": False, "error": NIT_CONFLICT_ERROR}

        req = RegistrationRequest(
            email=email,
            company_name=company_name.strip(),
            nit=nit_norm,
            sector=sector,
            servicio=servicio,
            empleados=empleados,
            infra_json=json.dumps(infra or {}, ensure_ascii=False),
            status="pending",
            request_ip=request_ip,
            created_at=_now_str(),
        )
        db.add(req)
        db.commit()
        db.refresh(req)
        _notify_ceo_new_request(req)
        return {"ok": True, "request_id": req.id, "status": "pending"}
    except Exception as exc:
        db.rollback()
        logger.error("create_registration_request: %s", exc, exc_info=True)
        return {"ok": False, "error": "internal_error"}
    finally:
        db.close()


def _notify_ceo_new_request(req) -> None:
    from services.email_delivery_service import send_to_ceo

    body = (
        f"Nueva solicitud de registro NOVUS\n\n"
        f"Empresa: {req.company_name}\n"
        f"NIT: {req.nit}\n"
        f"Email: {req.email}\n"
        f"Sector: {req.sector or '—'}\n"
        f"Servicio: {req.servicio or '—'}\n"
        f"IP solicitud: {req.request_ip or '—'}\n"
        f"Fecha: {req.created_at}\n\n"
        f"Acción requerida: autorizar o rechazar desde el panel de administración."
    )
    send_to_ceo(
        subject=f"[NOVUS] Solicitud de registro pendiente — {req.company_name}",
        body=body,
        category="registration",
    )


def list_pending_requests() -> List[dict]:
    from database import SessionLocal, RegistrationRequest

    db = SessionLocal()
    try:
        rows = (
            db.query(RegistrationRequest)
            .filter(RegistrationRequest.status.in_(("pending", "approved")))
            .order_by(RegistrationRequest.created_at.desc())
            .all()
        )
        return [_serialize(r) for r in rows]
    finally:
        db.close()


def list_all_requests(limit: int = 50) -> List[dict]:
    from database import SessionLocal, RegistrationRequest

    db = SessionLocal()
    try:
        rows = db.query(RegistrationRequest).order_by(RegistrationRequest.created_at.desc()).limit(limit).all()
        return [_serialize(r) for r in rows]
    finally:
        db.close()


def _serialize(r) -> dict:
    return {
        "id": r.id,
        "email": r.email,
        "company_name": r.company_name,
        "nit": r.nit,
        "sector": r.sector,
        "servicio": r.servicio,
        "status": r.status,
        "created_at": r.created_at,
        "approved_by": r.approved_by,
        "approved_at": r.approved_at,
        "request_ip": r.request_ip,
        "has_setup_token": bool(r.setup_token and r.status == "approved"),
    }


def approve_request(request_id: int, approver_email: str, base_url: str) -> Dict[str, Any]:
    from database import SessionLocal, RegistrationRequest, registrar_log_seguridad

    db = SessionLocal()
    try:
        req = db.query(RegistrationRequest).filter(RegistrationRequest.id == request_id).first()
        if not req:
            return {"ok": False, "error": "not_found"}
        if req.status != "pending":
            return {"ok": False, "error": "invalid_status", "status": req.status}

        nit_norm = _normalize_nit(req.nit)
        if nit_norm and nit_norm != req.nit:
            req.nit = nit_norm
        if not nit_norm or _nit_owned_by_usuario(db, nit_norm):
            return {"ok": False, "error": NIT_CONFLICT_ERROR}

        token = secrets.token_urlsafe(32)
        expires = (datetime.now() + timedelta(hours=72)).strftime("%Y-%m-%d %H:%M:%S")
        req.status = "approved"
        req.setup_token = token
        req.token_expires_at = expires
        req.approved_by = approver_email
        req.approved_at = _now_str()
        registrar_log_seguridad(
            db,
            "REGISTRO_APROBADO",
            f"Email {req.email} aprobado por {approver_email}",
        )
        db.commit()

        setup_url = f"{base_url.rstrip('/')}/completar-registro?token={token}"
        _send_setup_link(req.email, req.company_name, setup_url, approver_email)
        return {"ok": True, "setup_url": setup_url, "email": req.email}
    except Exception as exc:
        db.rollback()
        logger.error("approve_request: %s", exc, exc_info=True)
        return {"ok": False, "error": "internal_error"}
    finally:
        db.close()


def reject_request(request_id: int, rejector_email: str, reason: str = "") -> Dict[str, Any]:
    from database import SessionLocal, RegistrationRequest, registrar_log_seguridad

    db = SessionLocal()
    try:
        req = db.query(RegistrationRequest).filter(RegistrationRequest.id == request_id).first()
        if not req:
            return {"ok": False, "error": "not_found"}
        if req.status != "pending":
            return {"ok": False, "error": "invalid_status", "status": req.status}
        req.status = "rejected"
        req.rejected_by = rejector_email
        req.rejected_at = _now_str()
        req.rejection_reason = (reason or "").strip() or None
        registrar_log_seguridad(
            db,
            "REGISTRO_RECHAZADO",
            f"Email {req.email} rechazado por {rejector_email}: {reason or 'sin motivo'}",
        )
        db.commit()
        return {"ok": True}
    except Exception as exc:
        db.rollback()
        logger.error("reject_request: %s", exc, exc_info=True)
        return {"ok": False, "error": "internal_error"}
    finally:
        db.close()


def _send_setup_link(applicant_email: str, company_name: str, setup_url: str, approver: str) -> None:
    from services.email_delivery_service import send_email, send_to_ceo

    body = (
        f"Su solicitud de registro para {company_name} ha sido autorizada.\n\n"
        f"Complete su registro estableciendo su contraseña:\n{setup_url}\n\n"
        f"Este enlace expira en 72 horas.\n"
        f"Autorizado por: {approver}"
    )
    send_email(
        applicant_email,
        subject=f"[NOVUS] Complete su registro — {company_name}",
        body=body,
        category="registration_setup",
    )
    send_to_ceo(
        subject=f"[NOVUS] Registro autorizado — {company_name}",
        body=f"Autorización emitida para {applicant_email}\nEnlace: {setup_url}",
        category="registration",
    )


def get_request_by_token(token: str):
    from database import SessionLocal, RegistrationRequest

    if not token:
        return None
    db = SessionLocal()
    try:
        req = db.query(RegistrationRequest).filter(RegistrationRequest.setup_token == token).first()
        if not req or req.status != "approved":
            return None
        if req.token_expires_at:
            try:
                exp = datetime.strptime(req.token_expires_at, "%Y-%m-%d %H:%M:%S")
                if datetime.now() > exp:
                    return None
            except ValueError:
                pass
        return req
    finally:
        db.close()


def complete_registration(token: str, password: str) -> Dict[str, Any]:
    from sqlalchemy.exc import IntegrityError

    from database import SessionLocal, RegistrationRequest, Usuario, registrar_log_seguridad

    if not password or len(password) < 10:
        return {"ok": False, "error": "password_too_short"}
    if not token or not str(token).strip():
        return {"ok": False, "error": "invalid_token"}

    db = SessionLocal()
    try:
        req = db.query(RegistrationRequest).filter(RegistrationRequest.setup_token == token).first()
        if not req or req.status != "approved":
            return {"ok": False, "error": "invalid_token"}
        if req.token_expires_at:
            try:
                exp = datetime.strptime(req.token_expires_at, "%Y-%m-%d %H:%M:%S")
                if datetime.now() > exp:
                    return {"ok": False, "error": "token_expired"}
            except ValueError:
                pass
        if db.query(Usuario).filter(Usuario.email == req.email).first():
            return {"ok": False, "error": "email_already_registered"}

        nit_norm = _normalize_nit(req.nit)
        if not nit_norm:
            return {"ok": False, "error": NIT_CONFLICT_ERROR}
        if nit_norm != req.nit:
            req.nit = nit_norm
        # Token is bound to this request only — NIT comes from the approved request, never from client.
        if _nit_owned_by_usuario(db, nit_norm, exclude_email=req.email):
            return {"ok": False, "error": NIT_CONFLICT_ERROR}

        trial_expiry = (datetime.now() + timedelta(days=15)).strftime("%Y-%m-%d")
        usuario = Usuario(
            email=req.email,
            hashed_password=generate_password_hash(password),
            sector=req.sector,
            nit_pyme=nit_norm,
            is_temporal=True,
            trial_expiry=trial_expiry,
            is_active=True,
            role="company_admin",
        )
        db.add(usuario)
        req.status = "completed"
        req.setup_token = None
        registrar_log_seguridad(
            db,
            "REGISTRO_COMPLETADO",
            f"Empresa {req.company_name} | NIT {nit_norm} | email {req.email}",
        )
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            logger.warning(
                "complete_registration: NIT uniqueness conflict (IntegrityError) for request_id=%s",
                getattr(req, "id", None),
            )
            return {"ok": False, "error": NIT_CONFLICT_ERROR}

        try:
            from services.tenant_scope_service import provision_tenant_network_monitoring
            from services.network_scan_coordinator import schedule_network_discovery

            provision_tenant_network_monitoring(nit_norm, enabled=True, manual=False)
            # Allow SYNTHETIC_TEST_ONLY / ops harness to skip live LAN ARP (no engine disable).
            if os.environ.get("NOVUS_SKIP_NETWORK_DISCOVERY", "").strip().lower() not in (
                "1",
                "true",
                "yes",
                "on",
            ):
                schedule_network_discovery(consumer="registration_complete", force=False)
        except Exception as mon_exc:
            logger.warning("Monitoring provision on register complete: %s", mon_exc)

        try:
            # Heavy sector/engine wiring — skip under synthetic harness to avoid side scans.
            if os.environ.get("NOVUS_SKIP_NETWORK_DISCOVERY", "").strip().lower() not in (
                "1",
                "true",
                "yes",
                "on",
            ):
                from services.config_service import load_config, save_config
                from services.sector_shield_service import normalize_sector
                from services.sector_profile_service import apply_sector_profile_for_user

                if req.sector:
                    normalized = normalize_sector(req.sector)
                    cfg = load_config()
                    cfg["sector_activo"] = normalized
                    save_config(cfg)
                apply_sector_profile_for_user(req.email)
        except Exception as cfg_err:
            logger.debug("Sector config sync on register complete: %s", cfg_err)

        return {"ok": True, "email": req.email, "user_id": usuario.id}
    except Exception as exc:
        db.rollback()
        logger.error("complete_registration: %s", exc, exc_info=True)
        return {"ok": False, "error": "internal_error"}
    finally:
        db.close()


def registration_status_for_email(email: str) -> Optional[str]:
    from database import SessionLocal, RegistrationRequest

    email = (email or "").strip().lower()
    if not email:
        return None
    db = SessionLocal()
    try:
        req = (
            db.query(RegistrationRequest)
            .filter(RegistrationRequest.email == email)
            .order_by(RegistrationRequest.created_at.desc())
            .first()
        )
        return req.status if req else None
    finally:
        db.close()
