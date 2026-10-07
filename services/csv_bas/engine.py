#!/usr/bin/env python3
"""Motor CSV/BAS — dashboard y consultas."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from services.csv_bas.limitations import LIMITATIONS, POLICY, NA, CONTROL_ENGINES
from services.csv_bas.scenario_catalog import list_scenarios, get_scenario
from services.csv_bas.scenario_runner import run_scenario, run_all
from services.csv_bas.coverage_engine import compute_coverage
from services.csv_bas.control_validator import check_engine_availability
from services.csv_bas.kernel_console import ask_kernel
from services.csv_bas.store import load_results, load_runs, load_seals, load_queries, log_query


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def engines_status() -> Dict[str, Any]:
    status = {}
    for eng in CONTROL_ENGINES:
        status[eng] = check_engine_availability(eng)
    return status


def get_dashboard() -> Dict[str, Any]:
    scenarios = list_scenarios()
    results = load_results(50)
    coverage = compute_coverage(results)
    eng = engines_status()
    log_query({"action": "dashboard"})
    latest = results[0] if results else None
    return {
        "generated_at_utc": _utc(),
        "invented": False,
        "destructive": False,
        "real_attacks": False,
        "scenarios": scenarios,
        "engines": eng,
        "engines_available": sum(1 for v in eng.values() if v.get("available")),
        "engines_total": len(CONTROL_ENGINES),
        "coverage": coverage,
        "recent_results": results[:10],
        "latest_run": latest or NA,
        "history": load_runs(20),
        "seals": load_seals(5),
        "queries": load_queries(10),
        "limitations": LIMITATIONS,
        "policy": POLICY,
    }


def stats() -> Dict[str, Any]:
    results = load_results(500)
    coverage = compute_coverage(results)
    return {
        "scenarios_catalog": list_scenarios().get("count"),
        "results": len(results),
        "scenarios_with_results": coverage.get("scenarios_with_results"),
        "engines_available": sum(1 for v in engines_status().values() if v.get("available")),
        "invented": False,
        "destructive": False,
    }


def search(q: str, limit: int = 50) -> Dict[str, Any]:
    log_query({"action": "search", "q": q})
    ql = (q or "").lower()
    hits: List[Dict[str, Any]] = []
    for s in list_scenarios().get("scenarios") or []:
        if ql in json.dumps(s, default=str).lower():
            hits.append({"kind": "scenario", "item": s})
    for r in load_results(500):
        if ql in json.dumps(r, default=str).lower():
            hits.append({"kind": "result", "item": {
                "run_id": r.get("run_id"),
                "scenario_id": r.get("scenario_id"),
                "finished_at_utc": r.get("finished_at_utc"),
            }})
    return {
        "ok": True,
        "q": q,
        "hits": hits[:limit],
        "count": min(len(hits), limit),
        "invented": False,
        "message": None if hits else NA,
    }


def history(limit: int = 50) -> Dict[str, Any]:
    return {
        "runs": load_runs(limit),
        "results": [
            {
                "run_id": r.get("run_id"),
                "scenario_id": r.get("scenario_id"),
                "finished_at_utc": r.get("finished_at_utc"),
                "detections_summary": {
                    "detected": sum(1 for d in (r.get("detections") or []) if d.get("result") == "DETECTED"),
                    "not_detected": sum(1 for d in (r.get("detections") or []) if d.get("result") == "NOT DETECTED"),
                    "not_implemented": sum(1 for d in (r.get("detections") or []) if d.get("result") == "NOT IMPLEMENTED"),
                    "not_verified": sum(1 for d in (r.get("detections") or []) if d.get("result") == "NOT VERIFIED"),
                },
            }
            for r in load_results(limit)
        ],
        "invented": False,
    }
