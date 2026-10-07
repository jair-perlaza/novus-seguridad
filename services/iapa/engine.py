#!/usr/bin/env python3
"""Motor IAPA — dashboard y consultas (solo lectura)."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from services.iapa.limitations import NA, NI, LIMITATIONS, POLICY, PATH_WEIGHTS
from services.iapa.graph_builder import build_attack_graph
from services.iapa.path_finder import find_paths, critical_paths, pivot_nodes
from services.iapa.privilege import privilege_analysis
from services.iapa.lateral import lateral_movement_evidence
from services.iapa.risk import compute_path_scores, seal_analysis
from services.iapa.kernel_console import ask_kernel
from services.iapa.swarm_share import swarm_anonymous_summary
from services.iapa.store import log_query, load_queries, load_seals
from services.iapa.readers import peek_sources, sdl_search


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_dashboard() -> Dict[str, Any]:
    graph = build_attack_graph()
    scored = compute_path_scores(max_paths=25)
    crit = critical_paths(graph=graph)
    pivots = pivot_nodes(graph=graph)
    priv = privilege_analysis()
    lateral = lateral_movement_evidence()
    hva = [n for n in (graph.get("nodes") or []) if n.get("high_value")]
    seal = seal_analysis("dashboard", {
        "nodes": graph.get("node_count"),
        "edges": graph.get("edge_count"),
        "paths": scored.get("count"),
    })
    log_query({"action": "dashboard"})
    # SOPE playbook suggestion for breaking routes — recommend only, no execute
    sope_reco = NA
    try:
        from services.sope.playbook_catalog import PLAYBOOKS
        # If lateral or critical paths exist, suggest related playbook ids that exist in catalog
        if crit.get("count"):
            for pid in ("lateral_movement", "credential_theft", "critical_threat", "compromised_device"):
                if pid in PLAYBOOKS:
                    sope_reco = {"playbook_id": pid, "nombre": PLAYBOOKS[pid].get("nombre"), "mode": "recommend_only"}
                    break
    except Exception:
        sope_reco = NA

    return {
        "generated_at_utc": _utc(),
        "invented": False,
        "sources_status": graph.get("sources_status"),
        "missing_capabilities": graph.get("missing_capabilities"),
        "attack_graph": {"node_count": graph.get("node_count"), "edge_count": graph.get("edge_count"),
                        "nodes": graph.get("nodes"), "edges": graph.get("edges")},
        "critical_paths": crit,
        "scored_paths": scored.get("scored_paths"),
        "pivot_nodes": pivots,
        "high_value_assets": hva or NA,
        "privilege_analysis": priv,
        "lateral_movement": lateral,
        "sope_recommendation": sope_reco,
        "top_risks": (scored.get("scored_paths") or [])[:5] or NA,
        "seal": seal,
        "seals": load_seals(5),
        "queries": load_queries(10),
        "path_weights": PATH_WEIGHTS,
        "limitations": LIMITATIONS,
        "policy": POLICY,
    }


def stats() -> Dict[str, Any]:
    g = build_attack_graph()
    return {
        "nodes": g.get("node_count"),
        "edges": g.get("edge_count"),
        "sources_ok": sum(1 for v in (g.get("sources_status") or {}).values() if v.get("available")),
        "invented": False,
    }


def search(q: str, limit: int = 50) -> Dict[str, Any]:
    log_query({"action": "search", "q": q})
    g = build_attack_graph()
    ql = (q or "").lower()
    hits = [n for n in (g.get("nodes") or []) if ql in str(n.get("value") or "").lower() or ql in str(n.get("kind") or "").lower()]
    # also SDL
    sdl = sdl_search(q=q, limit=limit)
    return {
        "ok": True,
        "graph_hits": hits[:limit],
        "sdl": {"total": sdl.get("total"), "count": sdl.get("count"), "records": (sdl.get("records") or [])[:limit]},
        "invented": False,
        "message": None if hits or sdl.get("total") else NA,
    }
