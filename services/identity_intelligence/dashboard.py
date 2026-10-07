#!/usr/bin/env python3
"""Dashboard data + orquestacion del ciclo UEBA (sin mutar motores externos)."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from services.identity_intelligence.limitations import NA, LIMITATIONS, POLICY, RISK_WEIGHTS
from services.identity_intelligence.identity_engine import collect_observations, list_identities, get_identity
from services.identity_intelligence.behavior_baseline import rebuild_baselines, get_baseline
from services.identity_intelligence.risk_engine import compute_risk_score, rank_identities_by_risk, detect_anomalies_for_identity
from services.identity_intelligence.identity_graph import build_identity_graph
from services.identity_intelligence.timeline import build_identity_timeline
from services.identity_intelligence.store import load_anomalies, load_seals, load_baselines


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_cycle() -> Dict[str, Any]:
    """Observar -> baseline -> riesgos (local). No modifica SDL/motores."""
    obs = collect_observations()
    base = rebuild_baselines()
    ranked = rank_identities_by_risk(limit=15)
    # Congelar procesos vivos tras scoring (baseline de siguiente ciclo)
    try:
        import psutil
        from services.identity_intelligence.store import save_process_freeze
        names = []
        for p in psutil.process_iter(["name"]):
            try:
                n = (p.info.get("name") or "").lower()
                if n:
                    names.append(n)
            except Exception:
                continue
        if names:
            save_process_freeze(names)
    except Exception:
        pass
    return {
        "ok": True,
        "observations": obs,
        "baselines": base,
        "ranked": ranked,
        "invented": False,
        "timestamp_utc": _utc(),
    }


def get_dashboard() -> Dict[str, Any]:
    identities = list_identities()
    by_type = {}
    for i in identities:
        t = i.get("type") or "unknown"
        by_type[t] = by_type.get(t, 0) + 1
    baselines = load_baselines()
    ranked = rank_identities_by_risk(limit=10)
    top = (ranked.get("ranked") or [None])[0]
    graph = build_identity_graph(top.get("identity_uuid") if top else None)
    timeline = build_identity_timeline(top.get("identity_uuid") if top else None, limit=80)
    return {
        "generated_at_utc": _utc(),
        "invented": False,
        "identity_count": len(identities),
        "by_type": by_type,
        "baseline_count": len(baselines.get("baselines") or {}),
        "sufficient_baselines": sum(1 for b in (baselines.get("baselines") or {}).values() if b.get("sufficient")),
        "traffic_baseline": baselines.get("traffic_baseline") or NA,
        "top_risk": ranked.get("ranked") or NA,
        "recent_anomalies": load_anomalies(30),
        "graph": graph,
        "timeline": timeline,
        "seals": load_seals(5),
        "risk_weights": RISK_WEIGHTS,
        "limitations": LIMITATIONS,
        "policy": POLICY,
    }


def ask_kernel(question: str) -> Dict[str, Any]:
    q = (question or "").lower()
    ranked = rank_identities_by_risk(limit=20)
    top = (ranked.get("ranked") or [])
    evidence: Dict[str, Any] = {}
    parts = []

    if "mayor riesgo" in q or "más riesgo" in q or "mas riesgo" in q:
        if top:
            parts.append(f"Mayor riesgo: {top[0].get('label')} score={top[0].get('score')} confianza={top[0].get('confidence')}.")
            evidence["top"] = top[0]
        else:
            parts.append(f"Sin identidades con baseline suficiente. {NA}")

    if "desviaci" in q or "cambio" in q or "cambi" in q:
        if top:
            parts.append(f"Mayor desviacion observada (por factores): {top[0].get('label')} factores={top[0].get('factor_count')}.")
            evidence["deviation"] = top[0]
        else:
            parts.append(NA)

    if "equipo" in q and ("comparte" in q or "relacion" in q):
        focus = top[0]["identity_uuid"] if top else None
        g = build_identity_graph(focus)
        equipos = [n for n in (g.get("nodes") or []) if n.get("kind") in ("equipo", "device")]
        parts.append(f"Equipos/nodos relacionados: {equipos[:10] if equipos else NA}")
        evidence["equipos"] = equipos[:10] if equipos else NA

    if "incidente" in q:
        focus = top[0]["identity_uuid"] if top else None
        g = build_identity_graph(focus)
        incs = [n for n in (g.get("nodes") or []) if n.get("kind") == "incidente"]
        parts.append(f"Incidentes relacionados: {incs if incs else NA}")
        evidence["incidentes"] = incs if incs else NA

    if "primer" in q or "indicador" in q:
        focus = top[0]["identity_uuid"] if top else None
        tl = build_identity_timeline(focus)
        parts.append(f"Primer indicador: {tl.get('first_indicator')}")
        evidence["first"] = tl.get("first_indicator")

    if not parts:
        parts.append(f"Top riesgo: {top[:5] if top else NA}")
        evidence["ranked"] = top[:5] if top else NA

    return {
        "question": question,
        "answer": " ".join(str(p) for p in parts),
        "evidence": evidence,
        "role": "analyst_only",
        "executes_actions": False,
        "invented": False,
    }


def swarm_anonymous_summary() -> Dict[str, Any]:
    ranked = rank_identities_by_risk(limit=50)
    scores = [r.get("score") for r in (ranked.get("ranked") or []) if isinstance(r.get("score"), (int, float))]
    return {
        "ok": True,
        "privacy": "no_pii",
        "invented": False,
        "aggregates": {
            "identities_scored": len(scores),
            "avg_score": (sum(scores) / len(scores)) if scores else NA,
            "max_score": max(scores) if scores else NA,
            "note": "Sin emails, IPs, nombres ni payloads.",
        },
    }
