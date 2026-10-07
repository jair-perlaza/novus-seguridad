"""
Registro de errores HTTP en acceso remoto — trazabilidad completa para auditoría ngrok.
"""
from __future__ import annotations

import json
import os
import traceback
from datetime import datetime
from typing import Any, Dict, Optional

ERROR_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "remote_access")
ERROR_FILE = os.path.join(ERROR_DIR, "http_errors.jsonl")


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def record_http_error(
    *,
    route: str,
    method: str,
    status_code: int,
    error: BaseException,
    ip: Optional[str] = None,
    user: Optional[str] = None,
    user_agent: Optional[str] = None,
    extra: Optional[dict] = None,
) -> Dict[str, Any]:
    os.makedirs(ERROR_DIR, exist_ok=True)
    tb = traceback.format_exception(type(error), error, error.__traceback__)
    entry = {
        "timestamp": _now(),
        "route": route,
        "method": method,
        "status_code": status_code,
        "ip": ip,
        "user": user,
        "user_agent": (user_agent or "")[:512],
        "error_type": type(error).__name__,
        "error_message": str(error),
        "file": getattr(error, "__traceback__", None) and error.__traceback__.tb_frame.f_code.co_filename,
        "line": getattr(error, "__traceback__", None) and error.__traceback__.tb_lineno,
        "function": getattr(error, "__traceback__", None) and error.__traceback__.tb_frame.f_code.co_name,
        "stack_trace": "".join(tb)[-12000:],
        "extra": extra or {},
    }
    try:
        with open(ERROR_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass
    try:
        from services.evidence_center_service import record_evidence
        record_evidence(
            motor="remote_access_audit",
            description=f"HTTP {status_code} {method} {route}: {type(error).__name__}: {str(error)[:200]}",
            categoria="auditoria",
            nivel_riesgo="alto",
            accion_ejecutada="http_error",
            evidence=entry,
        )
    except Exception:
        pass
    return entry
