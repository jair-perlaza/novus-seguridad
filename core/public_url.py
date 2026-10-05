"""
URL pública centralizada — evita dependencias hardcodeadas de localhost/127.0.0.1.
Usar NOVUS_PUBLIC_URL cuando NOVUS se expone vía túnel o proxy inverso.
"""
from __future__ import annotations

from typing import Optional

from core.config import Config


def get_public_base_url(request=None) -> str:
    """
    Base URL externa de NOVUS (sin barra final).
    Prioridad: NOVUS_PUBLIC_URL > request.host_url > vacío (forzar configuración).
    """
    configured = (Config.PUBLIC_BASE_URL or "").strip().rstrip("/")
    if configured:
        return configured

    if request is not None:
        try:
            return request.host_url.rstrip("/")
        except Exception:
            pass

    try:
        from flask import has_request_context, request as flask_request

        if has_request_context():
            return flask_request.host_url.rstrip("/")
    except Exception:
        pass

    return ""


def get_oauth_callback_url(request=None) -> str:
    """URI de callback OAuth (Gmail) derivada de la URL pública."""
    base = get_public_base_url(request)
    if base:
        return f"{base}/api/gmail/oauth/callback"
    return ""
