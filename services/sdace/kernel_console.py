#!/usr/bin/env python3
"""Kernel IA console SDACE — solo analisis."""
from __future__ import annotations
from typing import Any, Dict
from services.sdace.limitations import NA
from services.sdace.history import historical_analysis, analytics_summary
from services.sdace.graph import build_attack_graph, build_attack_timeline
from services.sdace.correlate import temporal_correlate, ioc_correlate


def ask_kernel(question: str) -> Dict[str, Any]:
    q = (question or "").strip().lower()
    hist = historical_analysis()
    analytics = analytics_summary()
    evidence: Dict[str, Any] = {}
    parts = []

    if "primer" in q and ("indicador" in q or "ocurr" in q or "primero" in q):
        parts.append(f"Primer indicador/evento observado: {hist.get('que_ocurrio_primero')}")
        evidence["first"] = hist.get("que_ocurrio_primero")

    if "origen" in q or "origin" in q:
        parts.append(f"Origen (primer motor/tipo en timeline): {hist.get('que_origino_el_incidente')}")
        evidence["origin"] = hist.get("que_origino_el_incidente")

    if "propag" in q:
        g = build_attack_graph()
        n_edges = len(g.get("edges") or [])
        parts.append(f"Incidente analizado={g.get('incident_id')}; aristas de propagacion evidenciadas={n_edges}.")
        evidence["graph_edges"] = n_edges
        evidence["incident_id"] = g.get("incident_id")

    if "relacion" in q or "más relacion" in q or "mas relacion" in q:
        tops = analytics.get("top_incidentes")
        parts.append(f"Incidentes con mas registros relacionados: {tops}")
        evidence["top_incidentes"] = tops

    if "patron" in q or "repite" in q:
        temp = temporal_correlate()
        parts.append(f"Pares temporales evidenciados={len(temp.get('pairs') or [])}; escalas={temp.get('by_scale')}")
        evidence["temporal"] = temp.get("by_scale")

    if "usuario" in q:
        parts.append(f"Usuarios top: {analytics.get('top_usuarios')}")
        evidence["users"] = analytics.get("top_usuarios")

    if "activo" in q or "atacad" in q:
        parts.append(f"Activos top: {analytics.get('top_activos')}")
        evidence["assets"] = analytics.get("top_activos")

    if "campa" in q:
        parts.append(f"Campanas: {analytics.get('top_campanas')}")
        evidence["campaigns"] = analytics.get("top_campanas")

    if not parts:
        parts.append(
            f"Resumen analitico: top_ioc={analytics.get('top_ioc')}; "
            f"top_cve={analytics.get('top_cve')}; primeros_eventos={hist.get('que_ocurrio_primero')}"
        )
        evidence["analytics"] = {
            "top_ioc": analytics.get("top_ioc"),
            "top_cve": analytics.get("top_cve"),
        }

    # Replace empty lists with NA messaging honesty
    answer = " ".join(str(p) for p in parts)
    if "None" in answer:
        answer = answer.replace("None", NA)

    return {
        "question": question,
        "answer": answer,
        "evidence": evidence,
        "role": "analyst_only",
        "executes_actions": False,
        "invented": False,
        "confidence": "basada en correlaciones evidenciadas del SDL",
    }
