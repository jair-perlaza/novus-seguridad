"""
T2–T3 — OAuth 2.0 / OIDC framework.
Proveedores solo se marcan disponibles si hay credenciales reales configuradas.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List


PROVIDERS = ("google", "microsoft", "github", "oidc_generic")


def _env(*keys: str) -> bool:
    return all(bool(os.environ.get(k, "").strip()) for k in keys)


def provider_status() -> Dict[str, Any]:
    """Estado real por proveedor — no afirma implementado sin CLIENT_ID/SECRET."""
    status = {
        "google": {
            "configured": _env("NOVUS_OAUTH_GOOGLE_CLIENT_ID", "NOVUS_OAUTH_GOOGLE_CLIENT_SECRET"),
            "scopes_prep": ["openid", "email", "profile"],
            "login_ready": False,
        },
        "microsoft": {
            "configured": _env("NOVUS_OAUTH_MS_CLIENT_ID", "NOVUS_OAUTH_MS_CLIENT_SECRET"),
            "scopes_prep": ["openid", "profile", "email"],
            "login_ready": False,
        },
        "github": {
            "configured": _env("NOVUS_OAUTH_GITHUB_CLIENT_ID", "NOVUS_OAUTH_GITHUB_CLIENT_SECRET"),
            "scopes_prep": ["read:user", "user:email"],
            "login_ready": False,
        },
        "oidc_generic": {
            "configured": _env(
                "NOVUS_OIDC_CLIENT_ID",
                "NOVUS_OIDC_CLIENT_SECRET",
                "NOVUS_OIDC_DISCOVERY_URL",
            ),
            "scopes_prep": ["openid", "profile", "email"],
            "login_ready": False,
        },
    }
    # login_ready solo si configurado Y authlib disponible (fase 1: framework + status API)
    try:
        import importlib.util

        has_authlib = importlib.util.find_spec("authlib") is not None
    except Exception:
        has_authlib = False

    for name, st in status.items():
        # Sin authlib no afirmamos login_ready aunque haya env
        st["login_ready"] = bool(st["configured"] and has_authlib)
        st["authlib_present"] = has_authlib
        st["audit_claim"] = "IMPLEMENTADO" if st["login_ready"] else "NO IMPLEMENTADO (faltan credenciales IdP o authlib)"

    any_ready = any(s["login_ready"] for s in status.values())
    return {
        "providers": status,
        "any_provider_ready": any_ready,
        "framework": "oauth2_oidc_status_gate",
        "note": "No se afirma SSO hasta prueba live con IdP real",
        "rbac_preserved": True,
    }


def list_ready_providers() -> List[str]:
    st = provider_status()
    return [k for k, v in (st.get("providers") or {}).items() if v.get("login_ready")]
