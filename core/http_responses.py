"""Respuestas HTTP seguras — recuperación en lugar de errores visibles."""
from __future__ import annotations

from typing import Any, Optional, Tuple

from flask import jsonify, render_template

from core.recovery_middleware import recovery_html_response, recovery_json_response
from core.user_facing_errors import RECOVERY_USER_MESSAGE, public_error_payload


def api_error_response(
    exc: BaseException,
    *,
    context: str = "",
    extra: Optional[dict] = None,
    message_override: Optional[str] = None,
) -> Tuple[Any, int]:
    public_error_payload(
        exc, context=context, extra=extra, message_override=message_override
    )
    return recovery_json_response(exc)


def export_download_error_response(
    exc: BaseException,
    *,
    context: str = "",
    title: str = "NOVUS",
) -> Tuple[Any, int]:
    public_error_payload(exc, context=context, message_override=RECOVERY_USER_MESSAGE)
    return recovery_html_response(exc)


def api_not_found(message: Optional[str] = None) -> Tuple[Any, int]:
    from werkzeug.exceptions import NotFound

    return recovery_json_response(NotFound())
