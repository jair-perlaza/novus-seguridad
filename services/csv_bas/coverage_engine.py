#!/usr/bin/env python3
"""Coverage engine — conteos reales observados; sin porcentajes inventados."""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List

from services.csv_bas.limitations import CONTROL_ENGINES, DETECTED, ND, NI, NV, NA
from services.csv_bas.scenario_catalog import SCENARIOS
from services.csv_bas.store import load_results, save_coverage


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_coverage(results: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    results = results if results is not None else load_results(500)
    # Latest result per scenario
    latest: Dict[str, Dict[str, Any]] = {}
    for r in results:
        sid = r.get("scenario_id")
        if not sid:
            continue
        prev = latest.get(sid)
        if not prev or str(r.get("timestamp_utc") or "") >= str(prev.get("timestamp_utc") or ""):
            latest[sid] = r

    total_scenarios = len(SCENARIOS)
    by_engine: Dict[str, Dict[str, int]] = {}
    for eng in CONTROL_ENGINES:
        by_engine[eng] = {
            "detected": 0,
            "not_detected": 0,
            "not_implemented": 0,
            "not_verified": 0,
            "scenarios_evaluated": 0,
        }

    for sid, r in latest.items():
        for d in r.get("detections") or []:
            eng = d.get("engine")
            if eng not in by_engine:
                by_engine[eng] = {
                    "detected": 0, "not_detected": 0,
                    "not_implemented": 0, "not_verified": 0,
                    "scenarios_evaluated": 0,
                }
            by_engine[eng]["scenarios_evaluated"] += 1
            res = d.get("result")
            if res == DETECTED:
                by_engine[eng]["detected"] += 1
            elif res == ND:
                by_engine[eng]["not_detected"] += 1
            elif res == NI:
                by_engine[eng]["not_implemented"] += 1
            elif res == NV:
                by_engine[eng]["not_verified"] += 1

    # Human-readable fractions like "18/20" — only from observed counts
    fractions = {}
    for eng, c in by_engine.items():
        denom = c["scenarios_evaluated"]
        num = c["detected"]
        fractions[eng] = {
            "detected_over_evaluated": f"{num}/{denom}" if denom else f"0/0",
            "detected": num,
            "evaluated": denom,
            "not_detected": c["not_detected"],
            "not_implemented": c["not_implemented"],
            "not_verified": c["not_verified"],
            # Explicit: no invented percentage
            "percentage_invented": False,
            "coverage_percent": NA if denom == 0 else None,  # filled only if denom>0 below as observed
        }
        if denom > 0:
            # Observed ratio only — not marketing score
            fractions[eng]["coverage_percent"] = round(100.0 * num / denom, 2)

    payload = {
        "generated_at_utc": _utc(),
        "scenarios_in_catalog": total_scenarios,
        "scenarios_with_results": len(latest),
        "by_engine": fractions,
        "latest_scenario_ids": sorted(latest.keys()),
        "invented": False,
        "rng": False,
        "note": "Cobertura = detecciones observadas / escenarios evaluados. Sin inventar.",
    }
    save_coverage(payload)
    return payload
