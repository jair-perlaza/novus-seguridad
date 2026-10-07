#!/usr/bin/env python3
"""Attack chain / timeline builder — solo evidencia observada."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List

from services.csv_bas.limitations import DETECTED, ND, NI, NV, NA


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_attack_chain(
    scenario: Dict[str, Any],
    run_id: str,
    detections: List[Dict[str, Any]],
    integration: Dict[str, Any],
) -> Dict[str, Any]:
    detected = [d for d in detections if d.get("result") == DETECTED]
    missed = [d for d in detections if d.get("result") == ND]
    not_impl = [d for d in detections if d.get("result") == NI]
    not_ver = [d for d in detections if d.get("result") == NV]

    steps = [
        {"step": 1, "phase": "scenario_selected", "detail": scenario.get("id"), "ts": _utc()},
        {"step": 2, "phase": "signal_emitted", "detail": scenario.get("signal"), "ts": _utc()},
        {"step": 3, "phase": "controls_probed", "detail": f"engines={len(detections)}", "ts": _utc()},
        {"step": 4, "phase": "detections_collected", "detail": f"detected={len(detected)}", "ts": _utc()},
        {"step": 5, "phase": "integration", "detail": integration.get("summary") or NA, "ts": _utc()},
    ]

    timeline = []
    for s in steps:
        timeline.append({"time": s["ts"], "event": s["phase"], "detail": s["detail"]})
    for d in detections:
        timeline.append({
            "time": _utc(),
            "event": f"control_{d.get('result')}",
            "engine": d.get("engine"),
            "detail": d.get("evidence"),
        })

    recommendations = []
    for d in missed:
        recommendations.append({
            "engine": d.get("engine"),
            "action": "Fortalecer deteccion / correlacion del marcador CSV-BAS",
            "severity": "MEDIO",
        })
    for d in not_impl:
        recommendations.append({
            "engine": d.get("engine"),
            "action": "Exponer API publica de validacion o documentar ausencia",
            "severity": "BAJO",
        })
    for d in not_ver:
        recommendations.append({
            "engine": d.get("engine"),
            "action": "Habilitar verificador CSV-BAS (API de deteccion de marcadores)",
            "severity": "MEDIO",
        })

    return {
        "run_id": run_id,
        "scenario_id": scenario.get("id"),
        "attack_chain": steps,
        "attack_timeline": timeline,
        "detections": detected,
        "missed_detections": missed,
        "not_implemented": not_impl,
        "not_verified": not_ver,
        "evidence": {
            "signal": scenario.get("signal"),
            "mitre": scenario.get("mitre") or NA,
            "integration": integration,
        },
        "recommendations": recommendations or NA,
        "invented": False,
        "destructive": False,
    }
