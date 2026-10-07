#!/usr/bin/env python3
"""Kernel IA console IAPA — solo analisis."""
from __future__ import annotations
from typing import Any, Dict
from services.iapa.limitations import NA
from services.iapa.risk import compute_path_scores
from services.iapa.path_finder import find_paths, pivot_nodes, critical_paths
from services.iapa.privilege import privilege_analysis
from services.iapa.graph_builder import build_attack_graph


def ask_kernel(question: str) -> Dict[str, Any]:
    q = (question or "").lower()
    evidence: Dict[str, Any] = {}
    parts = []

    if "corto" in q or "shortest" in q or "crítico" in q or "critico" in q:
        paths = find_paths(max_paths=20)
        shortest = paths.get("shortest")
        parts.append(f"Camino mas corto evidenciado: {shortest}")
        evidence["shortest"] = shortest

    if "usuario" in q and "riesgo" in q:
        priv = privilege_analysis()
        risks = priv.get("identity_risks")
        parts.append(f"Riesgos de identidad UEBA: {risks}")
        evidence["identity_risks"] = risks

    if "vulnerabilidad" in q or "cve" in q or "inicia" in q:
        graph = build_attack_graph()
        cves = [n for n in (graph.get("nodes") or []) if n.get("kind") in ("cve", "vulnerabilidad")]
        scored = compute_path_scores(max_paths=30)
        starters = {}
        for p in scored.get("scored_paths") or []:
            kinds = p.get("kinds") or []
            labels = p.get("labels") or []
            for i, k in enumerate(kinds):
                if k in ("cve", "vulnerabilidad") and i < len(labels):
                    starters[labels[i]] = starters.get(labels[i], 0) + 1
        top = sorted(starters.items(), key=lambda x: x[1], reverse=True)[:5]
        parts.append(f"CVE/vulns que inician mas rutas: {top if top else NA}. Nodos CVE en grafo={len(cves)}.")
        evidence["cve_starters"] = top if top else NA

    if "incidente" in q or "origin" in q or "originó" in q or "origino" in q:
        scored = compute_path_scores(max_paths=20)
        with_inc = [p for p in (scored.get("scored_paths") or []) if "incidente" in (p.get("kinds") or [])]
        parts.append(f"Rutas con incidente: {len(with_inc)}. Ejemplo={with_inc[0] if with_inc else NA}")
        evidence["incident_paths"] = len(with_inc)

    if "rompe" in q or "pivot" in q or "protege" in q:
        piv = pivot_nodes(top_n=10)
        parts.append(f"Pivot nodes (mayor ruptura de rutas): {piv.get('pivots')}")
        evidence["pivots"] = piv.get("pivots")

    if not parts:
        crit = critical_paths()
        parts.append(f"Critical paths count={crit.get('count')}. Shortest={find_paths(max_paths=5).get('shortest')}")
        evidence["critical"] = crit.get("count")

    return {
        "question": question,
        "answer": " ".join(str(p) for p in parts),
        "evidence": evidence,
        "role": "analyst_only",
        "executes_actions": False,
        "invented": False,
    }
