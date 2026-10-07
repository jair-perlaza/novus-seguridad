"""Limitaciones honestas WSAE — no afirmar OAuth/HSTS/JWT sin evidencia."""
from __future__ import annotations

LIMITATIONS = [
    {
        "capability": "HSTS siempre activo",
        "status": "conditional",
        "audit_mark": "NO CUMPLIDO (condicional)",
        "reason": "HSTS solo con NOVUS_FORCE_HSTS o proxy/Secure; activarlo en HTTP local rompe el acceso.",
    },
    {
        "capability": "OAuth/OIDC login Google/Microsoft/GitHub",
        "status": "framework_ready_credentials_required",
        "audit_mark": "NO IMPLEMENTADO sin credenciales IdP",
        "reason": "Requiere CLIENT_ID/SECRET y redirect URI reales por proveedor. Framework OIDC genérico presente; proveedores no afirmados sin prueba live.",
    },
    {
        "capability": "JWT de negocio",
        "status": "not_implemented",
        "audit_mark": "NO IMPLEMENTADO",
        "reason": "Autenticación de negocio sigue Flask-Login + refresh de sesión WSAE; no API JWT de producto.",
    },
    {
        "capability": "CORS abierto multi-origen",
        "status": "deny_by_default",
        "audit_mark": "política explícita deny/same-origin",
        "reason": "Por defecto no se emiten ACAO; NOVUS_CORS_ORIGINS opcional.",
    },
]
