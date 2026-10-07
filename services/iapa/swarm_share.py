#!/usr/bin/env python3
"""Resumen anonimo para Swarm Mesh."""
from __future__ import annotations
from typing import Any, Dict
from services.iapa.limitations import NA
from services.iapa.risk import compute_path_scores
from services.iapa.path_finder import pivot_nodes


def swarm_anonymous_summary() -> Dict[str, Any]:
    scored = compute_path_scores(max_paths=15)
    piv = pivot_nodes(top_n=5)
    scores = [p.get("scores", {}).get("attack_path_score") for p in (scored.get("scored_paths") or [])]
    scores = [s for s in scores if isinstance(s, (int, float))]
    return {
        "ok": True,
        "privacy": "no_pii",
        "invented": False,
        "aggregates": {
            "paths_scored": len(scores),
            "avg_path_score": (sum(scores) / len(scores)) if scores else NA,
            "max_path_score": max(scores) if scores else NA,
            "pivot_count": len(piv.get("pivots") or []),
            "note": "Sin usuarios, IPs, hashes ni labels identificables.",
        },
    }
