#!/usr/bin/env python3
"""Motor SDACE — analytics dashboard (solo lectura sobre SDL/motores)."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from services.sdace.limitations import NA, LIMITATIONS, POLICY
from services.sdace.readers import sdl_stats, peek_engines
from services.sdace.correlate import (
    temporal_correlate, identity_correlate, ioc_correlate, cve_correlate, mitre_correlate,
)
from services.sdace.graph import build_attack_graph, build_attack_timeline
from services.sdace.history import historical_analysis, analytics_summary
from services.sdace.kernel_console import ask_kernel
from services.sdace.seal import seal_correlation
from services.sdace.swarm_share import swarm_analytic_summary
from services.sdace.store import log_query, load_queries, load_seals


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_dashboard() -> Dict[str, Any]:
    analytics = analytics_summary()
    graph = build_attack_graph()
    timeline = build_attack_timeline(incident_id=graph.get("incident_id") if graph.get("incident_id") != NA else None)
    temporal = temporal_correlate()
    # Seal important correlation snapshot (local sdace store only)
    seal = seal_correlation("dashboard_snapshot", {
        "temporal_pairs": len(temporal.get("pairs") or []),
        "graph_nodes": len(graph.get("nodes") or []),
        "graph_edges": len(graph.get("edges") or []),
        "timeline_events": timeline.get("count", 0),
    })
    log_query({"action": "dashboard", "ok": True})
    return {
        "generated_at_utc": _utc(),
        "invented": False,
        "sdl_stats": sdl_stats(),
        "engines_peek": {k: {"available": v.get("available"), "status": v.get("status")} for k, v in peek_engines().items()},
        "attack_graph": graph,
        "timeline": timeline,
        "analytics": analytics,
        "temporal": {"by_scale": temporal.get("by_scale"), "pairs_count": len(temporal.get("pairs") or [])},
        "queries": load_queries(15),
        "seals": load_seals(5),
        "last_seal": seal,
        "limitations": LIMITATIONS,
        "policy": POLICY,
    }


def consult(topic: str, **kwargs) -> Dict[str, Any]:
    topic = (topic or "").lower()
    log_query({"action": "consult", "topic": topic, "kwargs": {k: kwargs.get(k) for k in list(kwargs)[:8]}})
    if topic in ("temporal", "time"):
        return temporal_correlate(**{k: kwargs[k] for k in kwargs if k in ("limit", "max_pairs")})
    if topic in ("identity", "identidad"):
        return identity_correlate(limit=int(kwargs.get("limit", 400)))
    if topic == "ioc":
        return ioc_correlate(limit=int(kwargs.get("limit", 400)))
    if topic == "cve":
        return cve_correlate(limit=int(kwargs.get("limit", 400)))
    if topic == "mitre":
        return mitre_correlate(limit=int(kwargs.get("limit", 400)))
    if topic in ("history", "historico"):
        return historical_analysis(incident_id=kwargs.get("incident_id"))
    if topic == "swarm":
        return swarm_analytic_summary()
    if topic == "analytics":
        return analytics_summary()
    return {"ok": False, "message": NA, "invented": False}


def relations(incident_id: Optional[str] = None) -> Dict[str, Any]:
    g = build_attack_graph(incident_id=incident_id)
    seal_correlation("relations", {"incident_id": g.get("incident_id"), "edges": len(g.get("edges") or [])})
    return g


def attack_path(incident_id: Optional[str] = None) -> Dict[str, Any]:
    """Camino derivado del grafo: ordena nodos por layer_order cuando hay aristas."""
    g = build_attack_graph(incident_id=incident_id)
    nodes = {n["id"]: n for n in (g.get("nodes") or [])}
    edges = g.get("edges") or []
    if not edges:
        return {"ok": True, "path": [], "message": NA, "invented": False, "graph": g}
    # Build adjacency and pick a simple path from earliest layer present
    order = {k: i for i, k in enumerate(g.get("layer_order") or [])}
    ranked = sorted(nodes.values(), key=lambda n: order.get(n.get("kind"), 99))
    path = [{"id": n["id"], "kind": n["kind"], "value": n["value"]} for n in ranked]
    return {"ok": True, "path": path, "edges": edges, "invented": False, "incident_id": g.get("incident_id")}
