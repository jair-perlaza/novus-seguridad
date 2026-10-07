"""
CSRF para APIs JSON con cookie-auth (métodos mutadores).
"""
from __future__ import annotations

from typing import Optional, Tuple

from flask import has_request_context, request


# Rutas API exentas (login MFA challenge previo a sesión, health, etc.)
CSRF_API_EXEMPT_PREFIXES = (
    "/api/wsae/mfa/challenge",  # during login step-up may use pending token
)


def mutating_method(method: Optional[str] = None) -> bool:
    m = (method or (request.method if has_request_context() else "") or "").upper()
    return m in ("POST", "PUT", "PATCH", "DELETE")


def extract_csrf_token() -> Optional[str]:
    if not has_request_context():
        return None
    tok = request.headers.get("X-CSRF-Token") or request.headers.get("X-CSRFToken")
    if tok:
        return tok
    if request.is_json:
        data = request.get_json(silent=True) or {}
        return data.get("csrf_token") or data.get("_csrf")
    return request.form.get("csrf_token")


def should_enforce_api_csrf() -> bool:
    if not has_request_context():
        return False
    if not request.path.startswith("/api/"):
        return False
    if not mutating_method():
        return False
    path = request.path or ""
    for p in CSRF_API_EXEMPT_PREFIXES:
        if path.startswith(p):
            return False
    # Solo cookie-auth: usuario autenticado o sesión Flask presente
    from flask_login import current_user

    if current_user.is_authenticated:
        return True
    return False


def validate_api_csrf() -> Tuple[bool, str]:
    from services.csrf_service import validate_csrf_token

    if not should_enforce_api_csrf():
        return True, "not_required"
    tok = extract_csrf_token()
    if validate_csrf_token(tok):
        return True, "ok"
    return False, "invalid_or_missing_csrf"
