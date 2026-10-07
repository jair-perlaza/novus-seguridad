"""
Kernel IA — contexto BTDE (solo análisis; no ejecuta acciones).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from services.behavioral_threat_detection.limitations import LIMITATIONS


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_kernel_btde_context() -> Dict[str, Any]:
    ctx: Dict[str, Any] = {
        "role": "analyze_only",
        "executes_actions": False,
        "collected_at_utc": _utc(),
        "hypotheses": [],
        "limitations": LIMITATIONS,
        "capabilities": {
            "analyzes": True,
            "explains": True,
            "proposes": True,
            "executes": False,
        },
    }
    try:
        from services.behavioral_threat_detection.orchestrator import get_btde_orchestrator_status
        from services.behavioral_threat_detection.engine import get_btde_status

        st = get_btde_orchestrator_status()
        eng = get_btde_status()
        ctx["sensor"] = {
            "active": st.get("active"),
            "cycles": st.get("cycles"),
            "last_risk": st.get("last_risk") or eng.get("last_risk"),
            "last_correlation": eng.get("last_correlation"),
        }
        risk = (st.get("last_risk") or {}) if isinstance(st.get("last_risk"), dict) else {}
        if int(risk.get("score") or 0) >= 50:
            ctx["hypotheses"].append(
                {
                    "id": "elevated_behavioral_risk",
                    "text": (
                        f"Risk comportamental {risk.get('score')} ({risk.get('level')}). "
                        "Correlacionar con Endpoint/Red/APE antes de contención Swarm."
                    ),
                    "confidence": "medium",
                }
            )
        ctx["hypotheses"].append(
            {
                "id": "not_zero_day",
                "text": "BTDE no es detector zero-day dedicado ni clasificador ML; es correlación comportamental.",
                "confidence": "high",
            }
        )
    except Exception as exc:
        ctx["error"] = str(exc)[:160]
    return ctx


def answer_kernel_query(question: str) -> str:
    ctx = build_kernel_btde_context()
    parts = [
        "Kernel (solo análisis — no ejecuta). BTDE=Behavioral Threat Detection Engine.",
        f"Sensor active={(ctx.get('sensor') or {}).get('active')} cycles={(ctx.get('sensor') or {}).get('cycles')}.",
        f"Last risk={(ctx.get('sensor') or {}).get('last_risk')}.",
        "Zero-day dedicado / ML malware: NO IMPLEMENTADOS. BTDE usa comportamiento + correlación multi-motor.",
    ]
    q = (question or "").lower()
    if "zero" in q or "0-day" in q:
        parts.append("No afirmar detección de zero-days; solo anomalías comportamentales verificables.")
    if ctx.get("hypotheses"):
        parts.append(ctx["hypotheses"][0]["text"])
    return " ".join(parts)
