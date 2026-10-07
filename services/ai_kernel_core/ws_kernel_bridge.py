"""Puente WebSocket Kernel — procesamiento sync; broadcast vía realtime_engine si disponible."""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from services.ai_kernel_core.action_payload import (
    execute_action_payload,
    infer_intent_from_text,
    parse_action_payload,
    validate_action_payload,
)
from utils.logger import logger


def process_kernel_ws_message(raw: str | Dict[str, Any]) -> Dict[str, Any]:
    """
    Procesa mensaje WS/JSON del dashboard.
    No bloquea indefinidamente — ejecuta motores canónicos y devuelve JSON validado.
    """
    try:
        if isinstance(raw, str):
            data = json.loads(raw)
        else:
            data = dict(raw or {})
    except json.JSONDecodeError as exc:
        return {
            "status": "ERROR",
            "message": f"JSON inválido: {exc}",
            "executes_actions": False,
            "verified": False,
            "invented": False,
        }

    action = data.get("action") or data.get("intent")
    user_input = data.get("message") or data.get("user_input") or ""
    context = data.get("context") or {}

    if isinstance(data.get("action_payload"), dict):
        v = validate_action_payload(data["action_payload"])
        if not v.get("valid"):
            return {
                "status": "VALIDATION_ERROR",
                "errors": v.get("errors"),
                "executes_actions": False,
                "verified": False,
                "invented": False,
            }
        payload = v["payload"]
    else:
        payload = infer_intent_from_text(user_input or str(action or ""))
        if data.get("target_mac"):
            payload.target_mac = data["target_mac"]
        if data.get("target_ip"):
            payload.target_ip = data["target_ip"]
        if data.get("target_path"):
            payload.target_path = data["target_path"]
        payload.admin_request = bool(data.get("admin_request"))

    out = execute_action_payload(payload, context)
    response = {
        "status": "COMPLETED",
        "message": f"IA Kernel procesando solicitud: {payload.intent}",
        "action": action or payload.intent,
        "processing": out.get("result", {}).get("type"),
        "response": out.get("result", {}).get("response"),
        "data": out.get("result", {}).get("data"),
        "action_payload": payload.to_dict(),
        "executes_actions": out.get("executes_actions", False),
        "executes_network_block": out.get("result", {}).get("executes_network_block", False),
        "verified": out.get("verified", False),
        "invented": False,
    }
    broadcast_kernel_alert(response)
    return response


def broadcast_kernel_alert(message: dict) -> None:
    """Best-effort broadcast a clientes realtime_engine conectados."""
    try:
        from realtime_engine import realtime_engine
        import asyncio

        if not getattr(realtime_engine, "active_connections", None):
            return
        if not realtime_engine.active_connections:
            return
        envelope = {"type": "kernel_alert", **message}
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(realtime_engine.broadcast(envelope))
        except RuntimeError:
            asyncio.run(realtime_engine.broadcast(envelope))
    except Exception as exc:
        logger.debug("broadcast_kernel_alert: %s", exc)
