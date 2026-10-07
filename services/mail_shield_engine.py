"""Motor NOVUS Mail Shield — orquesta sincronización OAuth oficial."""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict

from utils.logger import logger

_running = False
_state: Dict[str, Any] = {"active": False, "last_cycle": None, "last_error": None}


def get_engine_status(user_id=None) -> Dict[str, Any]:
    from services.mail_shield_config import load_mail_shield_config
    from services.mail_shield_service import get_integration_status, get_stats

    uid = user_id or "platform"
    return {
        "engine": "novus_mail_shield",
        "enabled": load_mail_shield_config().get("enabled"),
        "integrations": get_integration_status(uid) if user_id else {"summary_message": "Integración no configurada"},
        "stats": get_stats(),
        "state": dict(_state),
    }


def _sync_gmail_users() -> None:
    from services.gmail_oauth_service import GMAIL_DATA_DIR, is_oauth_configured
    from services.gmail_analyzer_service import sync_new_messages
    from services.mail_shield_analyzer import analyze_gmail_message

    if not is_oauth_configured() or not os.path.isdir(GMAIL_DATA_DIR):
        return
    for uid in os.listdir(GMAIL_DATA_DIR):
        token = os.path.join(GMAIL_DATA_DIR, uid, "token.json")
        if not os.path.isfile(token):
            continue
        user_id = int(uid) if uid.isdigit() else uid
        sync_new_messages(user_id)


def _sync_m365_users() -> None:
    from services.microsoft365_oauth_service import is_oauth_configured, sync_messages
    from services.mail_shield_token_vault import BASE
    import os

    if not is_oauth_configured() or not os.path.isdir(BASE):
        return
    m365_root = os.path.join(BASE, "microsoft365")
    if not os.path.isdir(m365_root):
        return
    for uid in os.listdir(m365_root):
        sync_messages(int(uid) if uid.isdigit() else uid)


def _cycle() -> None:
    global _state
    try:
        from services.mail_shield_config import load_mail_shield_config
        if not load_mail_shield_config().get("enabled"):
            return
        _sync_gmail_users()
        _sync_m365_users()
        _state["last_cycle"] = time.strftime("%Y-%m-%d %H:%M:%S")
    except Exception as exc:
        _state["last_error"] = str(exc)
        logger.error("Mail Shield cycle: %s", exc)


def _loop() -> None:
    logger.info("NOVUS Mail Shield: bucle iniciado")
    while _running:
        _cycle()
        time.sleep(120)
    logger.info("NOVUS Mail Shield: bucle detenido")


def start_mail_shield_engine() -> Dict[str, Any]:
    global _running
    if _running:
        return {"status": "already_running", **get_engine_status()}
    _running = True
    _state["active"] = True
    threading.Thread(target=_loop, name="MailShieldEngine", daemon=True).start()
    logger.info("NOVUS Mail Shield Engine iniciado")
    return {"status": "started", **get_engine_status()}


def sync_now(user_id) -> Dict[str, Any]:
    from services.gmail_analyzer_service import sync_new_messages
    from services.mail_shield_service import ingest_analysis_record
    from services.microsoft365_oauth_service import sync_messages

    results = []
    g = sync_new_messages(user_id)
    results.append({"provider": "google_workspace", **g})
    m = sync_messages(user_id)
    results.append({"provider": "microsoft365", **m})
    return {"status": "ok", "results": results}
