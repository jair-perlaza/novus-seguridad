"""Kernel IA — contexto del motor de eventos (analyze-only)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from services.ai_kernel_event_engine.event_engine import analyze_security_event, get_ai_kernel_engine
from services.ai_kernel_event_engine.knowledge_adapter import get_knowledge_adapter
from services.ai_kernel_event_engine.system_context import NOVUSAISystemContext


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_kernel_event_engine_context() -> Dict[str, Any]:
    adapter = get_knowledge_adapter()
    return {
        "role": "analyze_only",
        "executes_actions": False,
        "collected_at_utc": _utc(),
        "event_types": list(NOVUSAISystemContext.EVENT_TYPES),
        "recommendations": list(NOVUSAISystemContext.RECOMMENDATIONS),
        "learning": adapter.snapshot(),
        "capabilities": {
            "analyzes": True,
            "explains": True,
            "proposes": True,
            "executes": False,
        },
    }


def answer_kernel_query(question: str) -> str:
    ctx = build_kernel_event_engine_context()
    parts = [
        "Kernel Event Engine (solo análisis — executes_actions=false).",
        f"Tipos de evento: {', '.join(ctx.get('event_types') or [])}.",
        f"Excepciones aprendidas: {(ctx.get('learning') or {}).get('exceptions_n', 0)}.",
        "Aislamiento y bloqueo IP requieren aprobación admin o Swarm.",
    ]
    q = (question or "").lower()
    if "aislar" in q or "isolate" in q:
        parts.append(
            "El Kernel RECOMIENDA aislamiento cuando calculated_risk>=70; "
            "no ejecuta netsh/iptables ni marca AIE sin acción humana."
        )
    if "aprend" in q or "feedback" in q:
        parts.append(
            "Retroalimentación admin (approve/unblock → modifier 0.5; isolate/block → modifier 1.5) "
            "persistida en data/ai_kernel_feedback/feedback.json."
        )
    return " ".join(parts)
