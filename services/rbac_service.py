"""
Control de Acceso Basado en Roles (RBAC) — NOVUS.
Fuente canónica de permisos por rol y módulo.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from utils.logger import logger

ROLE_SUPER_ADMIN = "super_admin"
ROLE_NOVUS_CREATOR = "novus_creator"
ROLE_COMPANY_ADMIN = "company_admin"
ROLE_ANALYST = "analyst"
ROLE_CLIENT = "client"

ROLES: Dict[str, str] = {
    ROLE_SUPER_ADMIN: "Super Administrador",
    ROLE_NOVUS_CREATOR: "Creador NOVUS",
    ROLE_COMPANY_ADMIN: "Administrador de Empresa",
    ROLE_ANALYST: "Analista / Operador",
    ROLE_CLIENT: "Cliente",
}

ALL_ROLES: Tuple[str, ...] = (
    ROLE_SUPER_ADMIN,
    ROLE_NOVUS_CREATOR,
    ROLE_COMPANY_ADMIN,
    ROLE_ANALYST,
    ROLE_CLIENT,
)
ADMIN_ROLES: Tuple[str, ...] = (ROLE_SUPER_ADMIN, ROLE_COMPANY_ADMIN)
SOC_ROLES: Tuple[str, ...] = (ROLE_SUPER_ADMIN, ROLE_COMPANY_ADMIN, ROLE_ANALYST)

# Visibilidad de módulos UI / rutas
MODULE_ACCESS: Dict[str, Tuple[str, ...]] = {
    "dashboard": ALL_ROLES,
    "inteligencia": ALL_ROLES,
    "casos_estudio": (ROLE_SUPER_ADMIN,),
    "network": ALL_ROLES,
    "topology": ALL_ROLES,
    "inventario": ALL_ROLES,
    "vulnerabilidades": SOC_ROLES + (ROLE_CLIENT,),
    "xdr": SOC_ROLES,
    "incidentes": SOC_ROLES + (ROLE_CLIENT,),
    "endpoints": ALL_ROLES,
    "playbooks": SOC_ROLES,
    "reportes": ALL_ROLES,
    "accesos": SOC_ROLES,
    "centro_bloqueos": ADMIN_ROLES,
    "platform_health": SOC_ROLES,
    "centro_evidencias": SOC_ROLES,
    "manual_defense_center": SOC_ROLES,
    "centro_defensa": SOC_ROLES,
    "historial_dispositivos": ALL_ROLES,
    "historial_seguridad_red": ALL_ROLES,
    "centro_casos_estudio_novus": (ROLE_NOVUS_CREATOR,),
    "verificador_evidencias": SOC_ROLES + (ROLE_SUPER_ADMIN, ROLE_COMPANY_ADMIN),
    "compliance_center": SOC_ROLES,
    "web_shield": SOC_ROLES,
    "mail_shield": SOC_ROLES,
    "configuracion": ADMIN_ROLES,
}

# Recursos API (prefijos lógicos)
API_ACCESS: Dict[str, Tuple[str, ...]] = {
    "ndci": (ROLE_SUPER_ADMIN,),
    "ndci.kernel": (ROLE_SUPER_ADMIN,),
    "enterprise.study_cases": (ROLE_NOVUS_CREATOR,),
    "enterprise.architecture": ADMIN_ROLES + (ROLE_NOVUS_CREATOR,),
    "forensic.evidence": SOC_ROLES + (ROLE_SUPER_ADMIN, ROLE_COMPANY_ADMIN),
    "kernel.enterprise.v2": SOC_ROLES + (ROLE_CLIENT,),
    "system.kill_process": ADMIN_ROLES + (ROLE_ANALYST,),
    "system.ai_files": ADMIN_ROLES + (ROLE_ANALYST,),
    "wsae.mfa_admin": ALL_ROLES,
}


def normalize_role(role: Optional[str]) -> str:
    raw = (role or ROLE_ANALYST).lower().strip().replace(" ", "_").replace("-", "_")
    aliases = {
        "admin": ROLE_COMPANY_ADMIN,
        "administrator": ROLE_COMPANY_ADMIN,
        "superadmin": ROLE_SUPER_ADMIN,
        "super_administrador": ROLE_SUPER_ADMIN,
        "operador": ROLE_ANALYST,
        "operator": ROLE_ANALYST,
        "analista": ROLE_ANALYST,
        "user": ROLE_CLIENT,
        "viewer": ROLE_CLIENT,
    }
    if raw in aliases:
        return aliases[raw]
    if raw in ROLES:
        return raw
    return ROLE_ANALYST


def role_label(role: Optional[str]) -> str:
    return ROLES.get(normalize_role(role), role or "Desconocido")


def get_user_role(user) -> str:
    if user is None:
        return ROLE_CLIENT
    return normalize_role(getattr(user, "role", None))


def user_has_any_role(user, roles: Sequence[str]) -> bool:
    return get_user_role(user) in {normalize_role(r) for r in roles}


def can_access_module(user, module: str) -> bool:
    if module == "centro_casos_estudio_novus":
        from services.enterprise_access_control import is_novus_creator

        return is_novus_creator(user)
    allowed = MODULE_ACCESS.get(module, ALL_ROLES)
    return get_user_role(user) in allowed


def can_access_api(user, resource: str) -> bool:
    if resource in ("enterprise.study_cases",):
        from services.enterprise_access_control import is_novus_creator

        return is_novus_creator(user)
    allowed = API_ACCESS.get(resource, ALL_ROLES)
    return get_user_role(user) in allowed


def build_module_access_map(user) -> Dict[str, bool]:
    role = get_user_role(user)
    base = {mod: role in roles for mod, roles in MODULE_ACCESS.items()}
    try:
        from services.v1_runtime_surface import apply_v1_module_access_map

        return apply_v1_module_access_map(base)
    except Exception:
        return base


def can_access_module_by_email(email: Optional[str], module: str) -> bool:
    if not email:
        return False
    from database import SessionLocal, Usuario

    db = SessionLocal()
    try:
        u = db.query(Usuario).filter(Usuario.email == email.strip().lower()).first()
        role = normalize_role(getattr(u, "role", None) if u else None)
        allowed = MODULE_ACCESS.get(module, ALL_ROLES)
        return role in allowed
    finally:
        db.close()


def check_module_access(user, module: str) -> Tuple[bool, str]:
    if can_access_module(user, module):
        return True, ""
    return False, f"Acceso denegado al módulo '{module}' para rol {role_label(get_user_role(user))}"


def check_api_access(user, resource: str) -> Tuple[bool, str]:
    if can_access_api(user, resource):
        return True, ""
    return False, f"Acceso denegado al recurso API '{resource}'"


def record_access_denied(
    user,
    *,
    module: Optional[str] = None,
    resource: Optional[str] = None,
    route: Optional[str] = None,
    detail: Optional[str] = None,
) -> Dict[str, Any]:
    """Auditoría + evidencia + escalación auth_protection por intentos repetidos."""
    from flask import has_request_context, request

    from core.security import get_client_ip

    email = getattr(user, "email", None) if user else None
    role = get_user_role(user) if user else "anonymous"
    ip = get_client_ip() if has_request_context() else "unknown"
    path = route or (request.path if has_request_context() else "unknown")
    target = module or resource or path
    desc = detail or f"Intento de acceso no autorizado a {target}"

    audit_route = f"rbac_denied:{target}"

    try:
        from services.auth_protection_service import record_auth_attempt

        protection = record_auth_attempt(
            success=False,
            email=email,
            route=audit_route,
            ip=ip,
        )
    except Exception as exc:
        logger.debug("rbac auth_protection: %s", exc)
        protection = {}

    try:
        from services.evidence_center_service import record_evidence

        record_evidence(
            motor="rbac_service",
            description=desc,
            categoria="auditoria",
            nivel_riesgo="alto",
            nivel_confianza="Alta",
            estado="denegado",
            accion_ejecutada="access_denied",
            resultado="blocked",
            evidence={
                "email": email,
                "role": role,
                "ip": ip,
                "path": path,
                "module": module,
                "resource": resource,
                "user_agent": request.headers.get("User-Agent", "")[:256] if has_request_context() else "",
                "protection": protection,
            },
        )
    except Exception as exc:
        logger.debug("rbac evidence: %s", exc)

    try:
        from database import SessionLocal, registrar_log_seguridad

        db = SessionLocal()
        try:
            from crypto_vault import CryptoVault

            vault = CryptoVault()
            msg = f"RBAC_DENIED role={role} email={email or 'unknown'} ip={ip} path={path} target={target}"
            registrar_log_seguridad(db, "RBAC_ACCESS_DENIED", msg, vault=vault)
            db.commit()
        finally:
            db.close()
    except Exception as exc:
        logger.debug("rbac db audit: %s", exc)

    logger.warning(f"RBAC denied: {email} role={role} ip={ip} path={path}")
    return {
        "denied": True,
        "email": email,
        "role": role,
        "ip": ip,
        "path": path,
        "module": module,
        "resource": resource,
        "protection": protection,
    }
