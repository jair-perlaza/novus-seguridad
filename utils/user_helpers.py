"""
Helpers for resolving authenticated user context from session and database.
"""
import socket

from flask_login import current_user


def get_current_user_data():
    """
    Build user context for templates from the authenticated session and DB.
    Returns neutral placeholders when data is unavailable.
    """
    if not current_user.is_authenticated:
        return {
            "nombre": "Sin sesión",
            "rol": "N/A",
            "nodo": socket.gethostname(),
            "email": "",
            "sector": "Sin datos disponibles",
            "acceso": "N/A",
            "can_access": {},
        }

    email = current_user.email or ""
    display_name = email.split("@")[0].replace(".", " ").replace("_", " ").title() if email else "Usuario"
    role = getattr(current_user, "role", "user") or "user"
    sector = "Sin datos disponibles"
    sector_key = "otros"
    role_normalized = role

    try:
        from database import SessionLocal, Usuario
        from services.sector_shield_service import normalize_sector
        from services.rbac_service import build_module_access_map, normalize_role, role_label

        db = SessionLocal()
        try:
            usuario = db.query(Usuario).filter(Usuario.email == email).first()
            if usuario and usuario.sector:
                sector = usuario.sector
                sector_key = normalize_sector(usuario.sector)
            if usuario and getattr(usuario, "role", None):
                role_normalized = normalize_role(usuario.role)
        finally:
            db.close()
        can_access = build_module_access_map(current_user)
        role_display = role_label(role_normalized)
    except Exception:
        can_access = {}
        role_display = role

    try:
        from flask import session
        from services.sector_profile_service import get_sector_profile
        if session.get("sector_key"):
            sector_key = session["sector_key"]
        profile = get_sector_profile(sector_key)
    except Exception:
        profile = {}

    return {
        "nombre": display_name,
        "rol": role_normalized,
        "rol_label": role_display,
        "nodo": socket.gethostname(),
        "email": email,
        "sector": sector,
        "sector_key": sector_key,
        "sector_label": profile.get("label", sector_key),
        "dashboard_focus": profile.get("dashboard_focus") or [],
        "acceso": role_normalized,
        "can_access": can_access,
    }
