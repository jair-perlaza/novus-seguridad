"""Tokens CSRF en sesión — formularios HTML y APIs JSON cookie-auth (vía wsae.csrf_api)."""
from __future__ import annotations

import secrets
from datetime import datetime
from typing import Optional

from flask import has_request_context, session


def issue_csrf_token() -> str:
    if not has_request_context():
        return ""
    tok = session.get("_csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["_csrf_token"] = tok
    session.modified = True
    return tok


def validate_csrf_token(submitted: Optional[str]) -> bool:
    if not has_request_context():
        return False
    expected = session.get("_csrf_token") or ""
    if not expected or not submitted:
        return False
    return secrets.compare_digest(str(submitted), str(expected))


def rotate_session_security() -> None:
    """Rotación de tokens de sesión tras login exitoso."""
    if not has_request_context():
        return
    session["_csrf_token"] = secrets.token_urlsafe(32)
    session["_session_nonce"] = secrets.token_urlsafe(16)
    session["_session_rotated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    session.modified = True
