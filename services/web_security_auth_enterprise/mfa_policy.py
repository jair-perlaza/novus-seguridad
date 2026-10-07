"""
Política MFA — cuentas administrativas deben tener TOTP activo (server-side).
No sustituye política legal/empresarial; enforcement técnico únicamente.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Union

from services.rbac_service import (
    ADMIN_ROLES,
    ROLE_NOVUS_CREATOR,
    get_user_role,
    normalize_role,
)
from utils.logger import logger

# Roles con MFA obligatorio (no todos los usuarios).
# P0-4: super_admin | company_admin | novus_creator — MFA REQUIRED.
# analyst/client: OPTIONAL (política actual, no ampliar).
# Sesión: AUTHENTICATED parcial = enrollment flag sin _novus_login_session_id;
# MFA_VERIFIED/full = finalize_successful_login → _novus_login_session_id.
MFA_MANDATORY_ROLES = frozenset(set(ADMIN_ROLES) | {ROLE_NOVUS_CREATOR})

MFA_ENROLLMENT_ALLOWED_ENDPOINTS = frozenset({
    "auth.login",
    "auth.logout_seguro",
    "auth.mfa_setup",
    "static",
    "wsae_api.wsae_status",
    "wsae_api.mfa_enroll",
    "wsae_api.mfa_enable",
    "wsae_api.mfa_status",
})

MFA_ENROLLMENT_ALLOWED_PREFIXES = (
    "/api/wsae/mfa",
    "/api/wsae/status",
)


def role_requires_mfa(role: Optional[str]) -> bool:
    return normalize_role(role) in MFA_MANDATORY_ROLES


def user_requires_mfa(user_or_email: Any) -> bool:
    if user_or_email is None:
        return False
    if isinstance(user_or_email, str):
        from database import SessionLocal, Usuario

        email = user_or_email.strip().lower()
        db = SessionLocal()
        try:
            u = db.query(Usuario).filter(Usuario.email == email).first()
            role = getattr(u, "role", None) if u else None
        finally:
            db.close()
        return role_requires_mfa(role)
    return role_requires_mfa(get_user_role(user_or_email))


def mfa_disable_allowed(user_or_email: Any) -> bool:
    """Administradores no pueden desactivar MFA mientras la política esté activa."""
    return not user_requires_mfa(user_or_email)


def check_mfa_login_gate(user, email: str) -> Dict[str, Any]:
    """
    Tras contraseña válida, determina el siguiente paso MFA.
    Returns action: ok | verify | enroll
    """
    from services.web_security_auth_enterprise.mfa_totp import is_mfa_enabled

    em = (email or getattr(user, "email", "") or "").strip().lower()
    mandatory = user_requires_mfa(user)
    enabled = is_mfa_enabled(em)

    if enabled:
        return {
            "action": "verify",
            "mandatory": mandatory,
            "mfa_enabled": True,
            "email": em,
        }
    if mandatory:
        return {
            "action": "enroll",
            "mandatory": True,
            "mfa_enabled": False,
            "email": em,
            "message": "Las cuentas administrativas deben activar MFA (TOTP) antes de acceder a NOVUS.",
        }
    return {
        "action": "ok",
        "mandatory": False,
        "mfa_enabled": False,
        "email": em,
    }


def enrollment_route_allowed(*, path: str, endpoint: Optional[str]) -> bool:
    p = (path or "").lower()
    if endpoint and endpoint in MFA_ENROLLMENT_ALLOWED_ENDPOINTS:
        return True
    return any(p.startswith(prefix.lower()) for prefix in MFA_ENROLLMENT_ALLOWED_PREFIXES)


def complete_enrollment_session(user, *, route: str = "mfa_enrollment_complete") -> None:
    """Finaliza sesión NOVUS tras activar MFA en flujo de inscripción obligatoria."""
    from flask import has_request_context, session

    if has_request_context():
        session.pop("_wsae_mfa_enrollment_required", None)
        session.pop("_wsae_mfa_enrollment_email", None)
        session.modified = True
    try:
        from services.login_session_audit_service import finalize_successful_login

        finalize_successful_login(user, route=route)
    except Exception as exc:
        logger.warning("complete_enrollment_session: %s", exc)


def audit_mfa_policy_event(
    email: str,
    action: str,
    *,
    detail: Optional[Dict[str, Any]] = None,
    risk_level: str = "warning",
) -> None:
    try:
        from services.web_security_auth_enterprise.publish import publish_wsae, seal_wsae
        from datetime import datetime, timezone

        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        fid = f"WSAE-MFA-POLICY-{action}-{abs(hash(email + action + ts)) % 10**10}"
        ev = {
            "user_email": email,
            "action": action,
            "detail": detail or {},
            "timestamp_utc": ts,
            "policy": "admin_mfa_mandatory",
        }
        publish_wsae(
            action=action,
            evidence=ev,
            threat_type="auth_mfa_policy",
            finding_id=fid,
            risk_level=risk_level,
            user_email=email,
        )
        seal_wsae(finding_id=fid, action=action, evidence=ev, risk_level=risk_level)
    except Exception as exc:
        logger.debug("mfa policy audit: %s", exc)
