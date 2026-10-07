"""
Recuperación automática NOVUS — registro interno completo; nunca exponer tracebacks al usuario.
"""
from __future__ import annotations

import json
import os
import threading
import time
import traceback
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import logger

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECOVERY_DIR = os.path.join(ROOT, "data", "novus_recovery")
RECOVERY_LOG = os.path.join(RECOVERY_DIR, "recovery_events.jsonl")

RECOVERY_USER_MESSAGE = "NOVUS está recuperando el servicio..."

_lock = threading.Lock()
_last_recovery_by_module: Dict[str, float] = {}
RECOVERY_COOLDOWN_SEC = 45.0


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def infer_module_from_path(path: str) -> str:
    p = (path or "").lower().strip("/")
    if not p:
        return "dashboard"
    if p.startswith("api/network") or p.startswith("network"):
        return "network"
    if "web-shield" in p or "web_shield" in p:
        return "web_shield"
    if "mail-shield" in p or "mail_shield" in p or "gmail" in p:
        return "mail_shield"
    if "xdr" in p or "amenazas" in p:
        return "xdr"
    if "report" in p or "pdf" in p:
        return "reportes"
    if "playbook" in p or "automatizacion" in p:
        return "playbooks"
    if "defensa" in p or "defense" in p or "manual-defense" in p:
        return "defense"
    if "monitoring" in p or "kernel" in p or p.startswith("api/ai"):
        return "kernel_ia"
    if p.startswith("api/"):
        parts = p.split("/")
        return parts[1] if len(parts) > 1 else "api"
    return p.split("/")[0] if p else "general"


def record_recovery_event(
    *,
    exc: Optional[BaseException],
    route: str,
    method: str,
    user: Optional[str],
    module: str,
    original_status: int,
    recovery_actions: Optional[List[str]] = None,
    recovery_ms: Optional[float] = None,
    reference: Optional[str] = None,
    extra: Optional[dict] = None,
) -> str:
    ref = reference or uuid.uuid4().hex[:12].upper()
    tb = ""
    if exc is not None:
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))[-16000:]
    entry = {
        "timestamp": _now(),
        "reference": ref,
        "route": route,
        "method": method,
        "user": user,
        "module": module,
        "original_status": original_status,
        "error_type": type(exc).__name__ if exc else None,
        "error_message": str(exc)[:4000] if exc else None,
        "stack_trace": tb,
        "recovery_actions": recovery_actions or [],
        "recovery_ms": recovery_ms,
        "extra": extra or {},
    }
    os.makedirs(RECOVERY_DIR, exist_ok=True)
    try:
        with open(RECOVERY_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as log_exc:
        logger.debug("recovery log write: %s", log_exc)
    logger.error(
        "[NOVUS-RECOVERY-%s] module=%s %s %s status=%s user=%s",
        ref,
        module,
        method,
        route,
        original_status,
        user,
        exc_info=exc is not None,
    )
    return ref


def attempt_module_recovery(module: str) -> Tuple[List[str], float]:
    """Reinicia solo módulos afectados cuando es seguro; idempotente con cooldown."""
    mod = (module or "general").lower()
    now = time.time()
    with _lock:
        last = _last_recovery_by_module.get(mod, 0.0)
        if now - last < RECOVERY_COOLDOWN_SEC:
            return [], 0.0
        _last_recovery_by_module[mod] = now

    t0 = time.perf_counter()
    actions: List[str] = []
    try:
        if mod in ("network", "network_api", "topology"):
            try:
                from services.network_monitor_engine import get_monitor_status, start_network_monitor_engine

                if not get_monitor_status().get("active"):
                    start_network_monitor_engine()
                actions.append("network_monitor_engine")
            except Exception as exc:
                logger.debug("recovery network_monitor: %s", exc)
            try:
                from services.network_scanner import start_background_scanner

                start_background_scanner()
                actions.append("network_scanner_background")
            except Exception as exc:
                logger.debug("recovery network_scanner: %s", exc)

        if mod in ("web_shield", "web-shield"):
            try:
                from services.web_shield_engine import get_engine_status, start_web_shield_engine

                if not (get_engine_status() or {}).get("active"):
                    start_web_shield_engine()
                actions.append("web_shield_engine")
            except Exception as exc:
                logger.debug("recovery web_shield: %s", exc)

        if mod in ("mail_shield", "mail-shield", "gmail"):
            try:
                from services.gmail_oauth_service import is_oauth_configured
                from services.microsoft365_oauth_service import is_oauth_configured as m365

                if is_oauth_configured() or m365():
                    from services.mail_shield_engine import start_mail_shield_engine

                    start_mail_shield_engine()
                    actions.append("mail_shield_engine")
            except Exception as exc:
                logger.debug("recovery mail_shield: %s", exc)

        if mod in ("xdr", "endpoint", "endpoints"):
            try:
                from services.lazy_engine_manager import start_if_needed

                start_if_needed("endpoint")
                actions.append("endpoint_lazy_start")
            except Exception as exc:
                logger.debug("recovery endpoint: %s", exc)

        if mod in ("kernel_ia", "ai", "monitoring", "dashboard", "general", "api"):
            try:
                from services.ai_kernel import ai_kernel, start_ai_kernel

                if not getattr(ai_kernel, "_running", False):
                    start_ai_kernel()
                actions.append("ai_kernel")
            except Exception as exc:
                logger.debug("recovery ai_kernel: %s", exc)

        if mod in ("defense", "manual_defense", "centro_defensa"):
            try:
                from services.startup_defense_service import initialize_defense_stack

                initialize_defense_stack()
                actions.append("defense_stack")
            except Exception as exc:
                logger.debug("recovery defense: %s", exc)
    except Exception as exc:
        logger.debug("attempt_module_recovery: %s", exc)

    return actions, round((time.perf_counter() - t0) * 1000, 2)


def schedule_recovery_for_request(
    *,
    path: str,
    method: str,
    user: Optional[str],
    original_status: int,
    exc: Optional[BaseException] = None,
) -> str:
    module = infer_module_from_path(path)
    ref = record_recovery_event(
        exc=exc,
        route=path,
        method=method,
        user=user,
        module=module,
        original_status=original_status,
        reference=None,
    )

    def _worker() -> None:
        actions, ms = attempt_module_recovery(module)
        if actions:
            record_recovery_event(
                exc=None,
                route=path,
                method=method,
                user=user,
                module=module,
                original_status=original_status,
                recovery_actions=actions,
                recovery_ms=ms,
                reference=ref,
                extra={"phase": "recovery_complete"},
            )

    threading.Thread(target=_worker, daemon=True, name=f"NovusRecovery-{ref[:6]}").start()
    return ref


def build_recovery_api_payload(
    *,
    reference: str,
    retry_url: Optional[str] = None,
    login_required: bool = False,
) -> dict:
    return {
        "status": "recovering",
        "message": RECOVERY_USER_MESSAGE,
        "reference": reference,
        "retry_url": retry_url,
        "retry_after_sec": 3,
        "auto_retry": True,
        "login_required": login_required,
        "_novusRecovery": True,
    }
