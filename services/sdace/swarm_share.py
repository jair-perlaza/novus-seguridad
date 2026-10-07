#!/usr/bin/env python3
"""Resumen analitico para Swarm — sin datos privados."""
from __future__ import annotations
from typing import Any, Dict
from services.sdace.limitations import NA
from services.sdace.history import analytics_summary
from services.sdace.correlate import temporal_correlate


def swarm_analytic_summary() -> Dict[str, Any]:
    a = analytics_summary()
    t = temporal_correlate(limit=100, max_pairs=20)
    # Strip any potentially identifying values — only aggregate counts
    def _count_only(top):
        if top == NA or top is None:
            return NA
        if isinstance(top, list):
            return {"distinct": len(top), "note": "values_redacted"}
        return NA

    return {
        "ok": True,
        "privacy": "no_private_data",
        "invented": False,
        "aggregates": {
            "top_ioc_distinct": _count_only(a.get("top_ioc")),
            "top_cve_distinct": _count_only(a.get("top_cve")),
            "top_incident_distinct": _count_only(a.get("top_incidentes")),
            "temporal_pairs": len(t.get("pairs") or []),
            "temporal_scales": t.get("by_scale") or NA,
            "sdl_sampled": a.get("sdl_total_sampled"),
        },
        "note": "Solo conteos/agregados. Sin usuarios, IPs, hashes ni payloads.",
    }
