#!/usr/bin/env python3
"""Kernel IA — solo analiza / correlaciona / explica / propone. Nunca ejecuta heal destructivo."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.health_engine.limitations import LIMITATIONS, POLICY


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_kernel_health_context(dashboard: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if dashboard is None:
        from services.health_engine.engine import get_health_dashboard

        dashboard = get_health_dashboard()
    summary = dashboard.get("summary") or {}
    issues = dashboard.get("issues") or []
    alerts = dashboard.get("alerts") or []
    hypotheses: List[Dict[str, Any]] = []
    if not issues:
        hypotheses.append(
            {
                "id": "stable",
                "text": "Sin fallos detectados en el último ciclo. Telemetría real; ausencia ≠ invención.",
                "confidence": "medium",
                "invented": False,
            }
        )
    else:
        codes = sorted({i.get("code") for i in issues if i.get("code")})
        hypotheses.append(
            {
                "id": "correlated_health_issues",
                "text": f"Issues correlacionados: {', '.join(codes[:12])}. Revisar self-heal seguro y Swarm risk.",
                "confidence": "high",
                "invented": False,
            }
        )
    if any(i.get("elevate_swarm_risk") for i in issues):
        hypotheses.append(
            {
                "id": "elevate_swarm",
                "text": "Múltiples componentes fallidos → elevar riesgo interno Swarm (propuesta, no ejecución destructiva).",
                "confidence": "high",
                "invented": False,
            }
        )

    proposals = []
    for i in issues[:10]:
        proposals.append(
            {
                "issue": i.get("code"),
                "component_id": i.get("component_id"),
                "propose": "safe_self_heal_if_allowed",
                "requires_approval_if_destructive": True,
                "executes": False,
            }
        )

    return {
        "role": "analyze_correlate_explain_propose",
        "executes_actions": False,
        "destructive_decisions": False,
        "collected_at_utc": _utc(),
        "capabilities": {
            "analyzes": True,
            "correlates": True,
            "explains": True,
            "proposes": True,
            "executes": False,
            "invents": False,
        },
        "policy": POLICY,
        "limitations": LIMITATIONS,
        "summary": {
            "overall_status": summary.get("overall_status"),
            "availability_pct": summary.get("availability_pct"),
            "services_active": summary.get("services_active"),
            "services_down": summary.get("services_down"),
            "alert_count": len(alerts),
            "issue_count": len(issues),
        },
        "hypotheses": hypotheses,
        "proposals": proposals,
    }


def answer_kernel_query(question: str, dashboard: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    ctx = build_kernel_health_context(dashboard)
    q = (question or "").strip().lower()
    if "riesgo" in q or "swarm" in q:
        text = (
            f"Estado={ctx['summary'].get('overall_status')}; "
            f"caídos={ctx['summary'].get('services_down')}; "
            f"propuestas={len(ctx['proposals'])}. Kernel no ejecuta."
        )
    elif "memoria" in q or "ram" in q or "cpu" in q:
        text = "Consulte host metrics del dashboard Health Center (valores reales o NO DISPONIBLE)."
    else:
        text = (
            f"Health Engine: availability={ctx['summary'].get('availability_pct')}%; "
            f"issues={ctx['summary'].get('issue_count')}. "
            "Kernel solo analiza/explica/propone."
        )
    return {
        "question": question,
        "answer": text,
        "executes": False,
        "invented": False,
        "context_summary": ctx["summary"],
        "hypotheses": ctx["hypotheses"],
    }
