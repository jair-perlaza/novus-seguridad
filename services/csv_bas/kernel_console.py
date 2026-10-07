#!/usr/bin/env python3
"""Kernel IA console CSV/BAS — solo analisis; executes_actions=false."""
from __future__ import annotations
from typing import Any, Dict, List

from services.csv_bas.limitations import NA, DETECTED, ND, NI, NV
from services.csv_bas.store import load_results
from services.csv_bas.coverage_engine import compute_coverage


def explain_run(scenario: Dict[str, Any], run_id: str) -> Dict[str, Any]:
    return {
        "question": "explain_run",
        "answer": (
            f"Escenario de validacion {scenario.get('id')} run={run_id}. "
            f"No destructivo. MITRE={scenario.get('mitre')}. "
            f"Kernel no ejecuta acciones."
        ),
        "role": "analyst_only",
        "executes_actions": False,
        "invented": False,
    }


def ask_kernel(question: str) -> Dict[str, Any]:
    q = (question or "").lower()
    results = load_results(100)
    coverage = compute_coverage(results)
    evidence: Dict[str, Any] = {}
    parts: List[str] = []

    latest = results[0] if results else None

    if "fallaron" in q or "fallo" in q or "failed" in q or "controles" in q:
        missed = (latest or {}).get("missed_detections") or []
        not_ver = (latest or {}).get("not_verified") or []
        parts.append(f"Controles NOT DETECTED: {[d.get('engine') for d in missed] or NA}")
        parts.append(f"Controles NOT VERIFIED: {[d.get('engine') for d in not_ver] or NA}")
        evidence["missed"] = missed
        evidence["not_verified"] = not_ver

    if "no detect" in q or "no detectó" in q or "no detecto" in q or "motor" in q:
        engines_nd = []
        for r in results[:20]:
            for d in r.get("detections") or []:
                if d.get("result") == ND:
                    engines_nd.append({"scenario": r.get("scenario_id"), "engine": d.get("engine")})
        parts.append(f"Motores NOT DETECTED (muestra): {engines_nd[:15] or NA}")
        evidence["not_detected"] = engines_nd[:30] or NA

    if "playbook" in q or "sope" in q:
        pbs = []
        for r in results[:20]:
            sope = (r.get("integration") or {}).get("sope")
            if sope:
                pbs.append({"scenario": r.get("scenario_id"), "sope": sope})
        parts.append(f"Playbooks recomendados (sin ejecutar): {pbs[:10] or NA}")
        evidence["playbooks"] = pbs[:20] or NA

    if "fortalecer" in q or "necesita" in q:
        by = coverage.get("by_engine") or {}
        weak = sorted(
            [(e, c) for e, c in by.items() if (c.get("evaluated") or 0) > 0],
            key=lambda x: (x[1].get("detected") or 0) / max(1, x[1].get("evaluated") or 1),
        )[:5]
        parts.append(f"Controles con menor deteccion observada: {[(e, c.get('detected_over_evaluated')) for e,c in weak] or NA}")
        evidence["weak_controls"] = weak

    if "peor cobertura" in q or "peor" in q or "cobertura" in q:
        by = coverage.get("by_engine") or {}
        ranked = sorted(
            [(e, c) for e, c in by.items() if (c.get("evaluated") or 0) > 0],
            key=lambda x: (x[1].get("detected") or 0) / max(1, x[1].get("evaluated") or 1),
        )
        worst = ranked[0] if ranked else None
        parts.append(f"Peor cobertura observada: {worst[0] if worst else NA} => {(worst[1].get('detected_over_evaluated') if worst else NA)}")
        evidence["worst"] = worst[0] if worst else NA
        evidence["coverage"] = coverage.get("by_engine")

    if "correlacion" in q or "mayor" in q:
        best = None
        best_n = -1
        for r in results:
            n = sum(1 for d in (r.get("detections") or []) if d.get("result") == DETECTED)
            if n > best_n:
                best_n = n
                best = r
        parts.append(
            f"Escenario con mas detecciones observadas: "
            f"{(best or {}).get('scenario_id') if best else NA} detected={best_n if best else NA}"
        )
        evidence["best_correlation"] = {
            "scenario_id": (best or {}).get("scenario_id") if best else NA,
            "detected_count": best_n if best else NA,
        }

    if not parts:
        parts.append(
            f"Resultados LIVE={len(results)}. Escenarios con resultado={coverage.get('scenarios_with_results')}. "
            f"Catalogo={coverage.get('scenarios_in_catalog')}."
        )
        evidence["coverage_summary"] = {
            "with_results": coverage.get("scenarios_with_results"),
            "catalog": coverage.get("scenarios_in_catalog"),
        }

    return {
        "question": question,
        "answer": " ".join(str(p) for p in parts),
        "evidence": evidence,
        "role": "analyst_only",
        "executes_actions": False,
        "invented": False,
    }
