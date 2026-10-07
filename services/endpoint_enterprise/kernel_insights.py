"""
Kernel IA — contexto Endpoint Enterprise (solo análisis; no ejecuta).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_kernel_endpoint_context() -> Dict[str, Any]:
    ctx: Dict[str, Any] = {
        "role": "analyze_only",
        "executes_actions": False,
        "collected_at_utc": _utc(),
        "hypotheses": [],
        "limitations": [],
    }
    try:
        from services.endpoint_enterprise.orchestrator import get_endpoint_enterprise_status
        from services.endpoint_enterprise.rootkit_indicators import LIMITATIONS

        st = get_endpoint_enterprise_status()
        ctx["sensor"] = {
            "active": st.get("active"),
            "cycles": st.get("cycles"),
            "last_yara_hits": st.get("last_yara_hits"),
            "last_heuristic_n": st.get("last_heuristic_n"),
            "host_risk": st.get("last_host_risk"),
        }
        ctx["limitations"] = LIMITATIONS
        if st.get("last_host_risk") and int((st.get("last_host_risk") or {}).get("score") or 0) >= 60:
            ctx["hypotheses"].append(
                {
                    "id": "elevated_host_risk",
                    "text": "Risk score de host elevado; correlacionar YARA/heurística/memoria antes de kill_process.",
                    "confidence": "medium",
                }
            )
    except Exception as exc:
        ctx["error"] = str(exc)[:160]
    ctx["capabilities"] = {
        "analyzes": True,
        "explains": True,
        "proposes": True,
        "executes": False,
    }
    return ctx


def answer_kernel_query(question: str) -> str:
    ctx = build_kernel_endpoint_context()
    parts = [
        "Kernel (solo análisis — no ejecuta acciones sobre endpoint).",
        f"Sensor cycles={(ctx.get('sensor') or {}).get('cycles')} yara_hits={(ctx.get('sensor') or {}).get('last_yara_hits')}.",
        f"Host risk={(ctx.get('sensor') or {}).get('host_risk')}.",
    ]
    if "rootkit" in (question or "").lower():
        parts.append(
            "Rootkit kernel propio / SSDT: NO implementados (requieren driver Ring-0). "
            "Hay Rootkit Detection híbrido user-mode: cross-view, servicios, drivers, hooks, ETW + correlación."
        )
    if ctx.get("hypotheses"):
        parts.append(ctx["hypotheses"][0]["text"])
    return " ".join(parts)
