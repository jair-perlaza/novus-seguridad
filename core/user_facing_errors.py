"""Mensajes al usuario y registro interno — solo recuperación visible; detalle en logs."""
from __future__ import annotations

import uuid
from typing import Any, Optional, Tuple

from utils.logger import logger

RECOVERY_USER_MESSAGE = "NOVUS está recuperando el servicio..."

# Compatibilidad con imports existentes — mismo texto de recuperación
GENERIC_USER_MESSAGE = RECOVERY_USER_MESSAGE
EXPORT_PDF_MESSAGE = RECOVERY_USER_MESSAGE
NOT_FOUND_MESSAGE = RECOVERY_USER_MESSAGE
FORBIDDEN_MESSAGE = RECOVERY_USER_MESSAGE
VALIDATION_MESSAGE = RECOVERY_USER_MESSAGE


def user_message_for_exception(exc: BaseException) -> str:
    return RECOVERY_USER_MESSAGE


def log_user_facing_error(
    exc: BaseException,
    *,
    context: str = "",
    extra: Optional[dict] = None,
) -> str:
    ref = uuid.uuid4().hex[:10].upper()
    logger.error(
        "[NOVUS-ERR-%s] context=%s extra=%s: %s",
        ref,
        context or "general",
        extra or {},
        exc,
        exc_info=True,
    )
    return ref


def public_error_payload(
    exc: BaseException,
    *,
    context: str = "",
    extra: Optional[dict] = None,
    message_override: Optional[str] = None,
) -> Tuple[dict, str, int]:
    """Payload JSON para cliente — siempre recuperación; HTTP 200."""
    ref = log_user_facing_error(exc, context=context, extra=extra)
    payload = {
        "status": "recovering",
        "message": message_override or RECOVERY_USER_MESSAGE,
        "reference": ref,
        "auto_retry": True,
        "retry_after_sec": 3,
        "_novusRecovery": True,
    }
    return payload, ref, 200
