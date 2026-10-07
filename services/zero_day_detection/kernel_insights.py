#!/usr/bin/env python3
"""Kernel IA — contexto ZDDE (correlaciona/explica/propone; nunca inventa)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from services.zero_day_detection.limitations import CLASSIFICATION, LIMITATIONS


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_kernel_zdde_context() -> Dict[str, Any]:
    ctx: Dict[str, Any] = {
        "role": "correlate_prioritize_explain_propose",
        "executes_actions": False,
        "invents_threats": False,
        "collected_at_utc": _utc(),
        "hypotheses": [],
        "limitations": LIMITATIONS,
        "classifications": CLASSIFICATION,
        "capabilities": {
            "analyzes": True,
            "correlates": True,
            "prioritizes": True,
            "explains": True,
            "proposes": True,
            "executes": False,
            "invents": False,
        },
    }
    try:
        from services.zero_day_detection.engine import get_zdde_status
        from services.zero_day_detection.orchestrator import get_zdde_orchestrator_status

        st = get_zdde_orchestrator_status()
        eng = get_zdde_status()
        last = eng.get("last") or {}
        ctx["sensor"] = {
            "active": st.get("active"),
            "cycles": st.get("cycles"),
            "last_classification": st.get("last_classification") or last.get("classification"),
            "last_risk": st.get("last_risk") or last.get("risk"),
            "signal_motors": last.get("signal_motors"),
        }
        cls = str(ctx["sensor"].get("last_classification") or "EVIDENCIA_INSUFICIENTE")
        if cls == "EVIDENCIA_INSUFICIENTE":
            ctx["hypotheses"].append(
                {
                    "id": "insufficient_evidence",
                    "text": CLASSIFICATION["EVIDENCIA_INSUFICIENTE"],
                    "confidence": "high",
                    "invented": False,
                }
            )
        elif cls == "CANDIDATO_AMENAZA_DESCONOCIDA":
            ctx["hypotheses"].append(
                {
                    "id": "unknown_threat_candidate",
                    "text": (
                        "Candidato por correlación ≥3 motores de señal. "
                        "NO es confirmación CVE zero-day. Revisar propuestas no destructivas."
                    ),
                    "confidence": str(last.get("confidence_level") or "medium"),
                    "invented": False,
                }
            )
        else:
            ctx["hypotheses"].append(
                {
                    "id": "correlated_anomaly",
                    "text": CLASSIFICATION.get(cls, cls),
                    "confidence": "medium",
                    "invented": False,
                }
            )
        ctx["hypotheses"].append(
            {
                "id": "not_cve_oracle",
                "text": "ZDDE no afirma detectar todos los zero-day ni confirmar CVEs desconocidos.",
                "confidence": "high",
                "invented": False,
            }
        )
    except Exception as exc:
        ctx["error"] = str(exc)[:160]
    return ctx


def answer_kernel_query(question: str) -> str:
    ctx = build_kernel_zdde_context()
    sensor = ctx.get("sensor") or {}
    parts = [
        "Kernel (correlaciona/explica/propone — no inventa ni ejecuta destructivo). ZDDE=Zero-Day Detection Engine Enterprise.",
        f"Active={sensor.get('active')} cycles={sensor.get('cycles')}.",
        f"Classification={sensor.get('last_classification')} risk={sensor.get('last_risk')}.",
        "Si evidencia insuficiente → EVIDENCIA_INSUFICIENTE (nunca zero-day inventado).",
    ]
    q = (question or "").lower()
    if "zero" in q or "0-day" in q:
        parts.append("No afirmar detección universal de zero-days; solo candidatos por correlación multicapa verificable.")
    if ctx.get("hypotheses"):
        parts.append(ctx["hypotheses"][0]["text"])
    return " ".join(parts)
