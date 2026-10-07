"""Kernel IA — WSAE (solo análisis)."""
from __future__ import annotations

from typing import Any, Dict

from services.web_security_auth_enterprise.limitations import LIMITATIONS
from services.web_security_auth_enterprise.oauth_oidc import provider_status
from services.web_security_auth_enterprise.mfa_totp import engine_available


def build_kernel_wsae_context() -> Dict[str, Any]:
    return {
        "role": "analyze_only",
        "executes_actions": False,
        "mfa_engine": "pyotp" if engine_available() else "unavailable",
        "oauth": provider_status(),
        "limitations": LIMITATIONS,
        "capabilities": {"analyzes": True, "explains": True, "executes": False},
    }


def answer_kernel_query(question: str) -> str:
    ctx = build_kernel_wsae_context()
    oauth = ctx.get("oauth") or {}
    parts = [
        "Kernel (solo análisis). WSAE=Web Security + Authentication Enterprise.",
        f"MFA TOTP engine={ctx.get('mfa_engine')} (real pyotp, no simulado).",
        f"OAuth/OIDC any_ready={oauth.get('any_provider_ready')} — sin credenciales IdP no se afirma SSO.",
        "HSTS condicional; JWT de negocio no implementado; CSRF API + RBAC peligrosos + path sandbox: sí.",
    ]
    q = (question or "").lower()
    if "oauth" in q or "oidc" in q:
        parts.append(str(oauth.get("note")))
    if "mfa" in q or "totp" in q:
        parts.append("MFA: enroll/verify/disable + recovery codes + sello forense.")
    return " ".join(parts)
