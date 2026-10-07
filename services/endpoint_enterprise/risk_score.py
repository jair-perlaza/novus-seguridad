"""
T6 — Risk Score justificado por factores medibles (sin aleatoriedad).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def compute_process_risk(
    *,
    pid: Optional[int] = None,
    name: Optional[str] = None,
    heuristic_findings: Optional[List[dict]] = None,
    yara_hits: Optional[List[dict]] = None,
    memory_findings: Optional[List[dict]] = None,
    network_conn_count: int = 0,
    signed: Optional[bool] = None,
    from_temp: bool = False,
    ape_unusual: bool = False,
    swarm_priority: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Score 0-100 con factores explícitos.
    """
    factors: Dict[str, Any] = {}
    score = 0

    sev_w = {"info": 2, "low": 8, "medium": 18, "high": 28, "critical": 40}
    for f in heuristic_findings or []:
        w = sev_w.get(str(f.get("severity") or "low").lower(), 8)
        score += w
        factors.setdefault("heuristics", []).append({"type": f.get("finding_type"), "weight": w})

    for h in yara_hits or []:
        w = sev_w.get(str(h.get("severity") or "medium").lower(), 18)
        # YARA hits are stronger signal
        w = min(45, w + 5)
        score += w
        factors.setdefault("yara", []).append({"rule": h.get("rule"), "weight": w})

    for m in memory_findings or []:
        w = sev_w.get(str(m.get("severity") or "medium").lower(), 18)
        score += w
        factors.setdefault("memory", []).append({"type": m.get("finding_type"), "weight": w})

    if network_conn_count >= 20:
        score += 10
        factors["network_fanout"] = {"connections": network_conn_count, "weight": 10}
    elif network_conn_count >= 5:
        score += 4
        factors["network_fanout"] = {"connections": network_conn_count, "weight": 4}

    if from_temp:
        score += 12
        factors["origin_temp"] = {"weight": 12}

    if signed is False:
        score += 8
        factors["unsigned_binary"] = {"weight": 8}
    elif signed is True:
        score = max(0, score - 5)
        factors["signed_binary_discount"] = {"weight": -5}

    if ape_unusual:
        score += 10
        factors["ape_unusual_process"] = {"weight": 10}

    if swarm_priority is not None and swarm_priority >= 70:
        score += 8
        factors["swarm_priority_boost"] = {"priority": swarm_priority, "weight": 8}

    score = max(0, min(100, int(score)))
    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 35:
        level = "medium"
    elif score >= 15:
        level = "low"
    else:
        level = "info"

    return {
        "pid": pid,
        "name": name,
        "score": score,
        "level": level,
        "factors": factors,
        "basis": "suma ponderada de hallazgos verificados — sin RNG",
        "verified": True,
    }


def aggregate_host_risk(process_scores: List[Dict[str, Any]], *, extra_findings: int = 0) -> Dict[str, Any]:
    if not process_scores and extra_findings <= 0:
        return {"score": 0, "level": "info", "top": [], "basis": "sin hallazgos"}
    top = sorted(process_scores, key=lambda x: int(x.get("score") or 0), reverse=True)[:10]
    peak = int(top[0]["score"]) if top else 0
    boost = min(15, extra_findings * 3)
    score = min(100, peak + boost)
    level = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low" if score >= 15 else "info"
    return {"score": score, "level": level, "top": top, "extra_findings": extra_findings, "boost": boost}
