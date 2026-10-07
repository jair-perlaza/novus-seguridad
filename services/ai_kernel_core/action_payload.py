"""Esquema estricto de decisión del Kernel IA — validación sin dependencia obligatoria de pydantic."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Literal, Optional

IntentType = Literal[
    "GREETING",
    "SCAN_REQUEST",
    "ISOLATE_DEVICE",
    "LEARN_OVERRIDE",
    "GENERAL_QUERY",
]

VALID_INTENTS = frozenset(
    {"GREETING", "SCAN_REQUEST", "ISOLATE_DEVICE", "LEARN_OVERRIDE", "GENERAL_QUERY"}
)


@dataclass
class ActionPayload:
    """Esquema de decisión estructurada para el backend Kernel."""

    intent: str
    confidence: float
    reasoning: str
    target_mac: Optional[str] = None
    target_ip: Optional[str] = None
    target_path: Optional[str] = None
    admin_request: bool = False
    executes_actions: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def validate(self) -> List[str]:
        errors: List[str] = []
        if self.intent not in VALID_INTENTS:
            errors.append(f"intent inválido: {self.intent}")
        if not isinstance(self.confidence, (int, float)) or not (0.0 <= float(self.confidence) <= 1.0):
            errors.append("confidence debe estar entre 0.0 y 1.0")
        if not (self.reasoning or "").strip():
            errors.append("reasoning requerido")
        if self.intent == "SCAN_REQUEST" and not self.target_path:
            errors.append("target_path requerido para SCAN_REQUEST")
        if self.intent == "ISOLATE_DEVICE" and not self.target_mac:
            errors.append("target_mac requerido para ISOLATE_DEVICE")
        if self.intent == "LEARN_OVERRIDE" and not self.target_mac:
            errors.append("target_mac requerido para LEARN_OVERRIDE")
        return errors


def parse_action_payload(data: Dict[str, Any]) -> ActionPayload:
    """Parsea dict JSON → ActionPayload."""
    return ActionPayload(
        intent=str(data.get("intent") or "GENERAL_QUERY"),
        confidence=float(data.get("confidence") if data.get("confidence") is not None else 0.5),
        reasoning=str(data.get("reasoning") or ""),
        target_mac=data.get("target_mac"),
        target_ip=data.get("target_ip"),
        target_path=data.get("target_path"),
        admin_request=bool(data.get("admin_request")),
        executes_actions=bool(data.get("executes_actions")),
    )


def validate_action_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    """Valida payload; devuelve {valid, errors, payload}."""
    try:
        payload = parse_action_payload(data)
    except (TypeError, ValueError) as exc:
        return {"valid": False, "errors": [str(exc)], "payload": None}
    errors = payload.validate()
    return {"valid": not errors, "errors": errors, "payload": payload if not errors else None}


def infer_intent_from_text(user_input: str) -> ActionPayload:
    """Heurística local — no LLM; mapea texto a intent estructurado."""
    text = (user_input or "").lower().strip()
    if text in ("hola", "buenas", "hey", "que tal", "buenos dias", "buenas tardes", "buenas noches"):
        return ActionPayload(
            intent="GREETING",
            confidence=0.95,
            reasoning="Saludo informal detectado",
            executes_actions=False,
        )
    if any(t in text for t in ("escanea", "scan", "analiza carpeta", "revisa carpeta")):
        import re

        m = re.search(r'[\'"]?([a-zA-Z]:\\[^\'"]+|/[^\'"]+|\.[^\'"]*)[\'"]?', user_input or "")
        path = m.group(1) if m else "."
        return ActionPayload(
            intent="SCAN_REQUEST",
            confidence=0.85,
            reasoning="Solicitud de escaneo de ruta local",
            target_path=path,
            executes_actions=False,
        )
    if any(t in text for t in ("aisla", "bloquea", "isolate")):
        return ActionPayload(
            intent="ISOLATE_DEVICE",
            confidence=0.8,
            reasoning="Solicitud de aislamiento — requiere admin_request o recomendación only",
            executes_actions=False,
        )
    if "falso positivo" in text or "autorizar equipo" in text:
        return ActionPayload(
            intent="LEARN_OVERRIDE",
            confidence=0.9,
            reasoning="Retroalimentación admin para reducir falsos positivos",
            executes_actions=False,
        )
    return ActionPayload(
        intent="GENERAL_QUERY",
        confidence=0.6,
        reasoning="Consulta general — delegar a kernel_operator si requiere motores",
        executes_actions=False,
    )


def execute_action_payload(payload: ActionPayload, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Ejecuta intent vía request_router — executes_actions false salvo admin explícito."""
    from services.ai_kernel_core.request_router import process_user_request

    ctx = dict(context or {})
    if payload.target_mac:
        ctx["mac"] = payload.target_mac
    if payload.target_ip:
        ctx["ip"] = payload.target_ip
    if payload.target_path:
        ctx["target_path"] = payload.target_path
    ctx["admin_request"] = payload.admin_request

    intent_map = {
        "GREETING": "Hola",
        "SCAN_REQUEST": f"Escanea {payload.target_path or '.'}",
        "ISOLATE_DEVICE": "Aisla el equipo",
        "LEARN_OVERRIDE": "Marcar como falso positivo",
        "GENERAL_QUERY": payload.reasoning or "consulta",
    }
    user_msg = intent_map.get(payload.intent, payload.reasoning)
    result = process_user_request(user_msg, ctx)
    return {
        "action_payload": payload.to_dict(),
        "validation_errors": payload.validate(),
        "result": result,
        "executes_actions": bool(result.get("executes_actions")),
        "verified": result.get("verified", False),
        "invented": False,
    }
