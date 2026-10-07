#!/usr/bin/env python3
"""Risk scoring IAPA — explicable, sin RNG."""
from __future__ import annotations
import hashlib
import json
from typing import Any, Dict, List, Optional

from services.iapa.limitations import NA, PATH_WEIGHTS
from services.iapa.store import save_seal
from services.iapa.path_finder import find_paths, critical_paths, pivot_nodes
from services.iapa.graph_builder import build_attack_graph
from services.iapa.lateral import lateral_movement_evidence
from services.iapa.privilege import privilege_analysis


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def seal_analysis(kind: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    core = {"kind": kind, "payload": payload, "invented": False}
    digest = hashlib.sha256(_canonical(core).encode()).hexdigest()
    sig, kid = NA, NA
    try:
        from services.forensic_evidence_keys import load_signing_keypair
        pk, kid = load_signing_keypair()
        sig = pk.sign(digest.encode()).hex()
    except Exception:
        pass
    entry = {
        "kind": kind,
        "sha256": digest,
        "ed25519_sig": sig,
        "key_id": kid,
        "chain_of_custody": {"phase": "iapa_analysis", "ref": digest},
        "invented": False,
    }
    save_seal(entry)
    return entry


def score_path(path: Dict[str, Any], lateral: Dict[str, Any], priv: Dict[str, Any]) -> Dict[str, Any]:
    factors = []
    score = 0
    kinds = set(path.get("kinds") or [])
    length = path.get("length") or 99

    if length <= 3:
        w = PATH_WEIGHTS["path_length_short"]
        score += w
        factors.append({"factor": "path_length_short", "weight": w, "explanation": f"Ruta corta length={length}."})

    if path.get("target_high_value"):
        w = PATH_WEIGHTS["reaches_critical_asset"]
        score += w
        factors.append({"factor": "reaches_critical_asset", "weight": w, "explanation": "Destino marcado high_value por evidencia ASM/criticity."})

    if "cve" in kinds or "vulnerabilidad" in kinds:
        w = PATH_WEIGHTS["has_cve_or_vuln"]
        score += w
        factors.append({"factor": "has_cve_or_vuln", "weight": w, "explanation": "La ruta incluye CVE/vulnerabilidad observada."})

    if "ioc" in kinds:
        w = PATH_WEIGHTS["has_ioc"]
        score += w
        factors.append({"factor": "has_ioc", "weight": w, "explanation": "La ruta incluye IOC observado."})

    if "incidente" in kinds:
        w = PATH_WEIGHTS["has_incident"]
        score += w
        factors.append({"factor": "has_incident", "weight": w, "explanation": "La ruta incluye incidente IMCM/SDL."})

    # privileged identity on path
    priv_labels = set()
    for a in (priv.get("admins") or []) if isinstance(priv.get("admins"), list) else []:
        priv_labels.add((a.get("label") or "").lower())
    for s in (priv.get("service_accounts") or []) if isinstance(priv.get("service_accounts"), list) else []:
        priv_labels.add((s.get("label") or "").lower())
    path_labels = [str(x).lower() for x in (path.get("labels") or [])]
    if any(any(pl in lbl or lbl in pl for pl in priv_labels if pl) for lbl in path_labels):
        w = PATH_WEIGHTS["has_privileged_identity"]
        score += w
        factors.append({"factor": "has_privileged_identity", "weight": w, "explanation": "Nodo de ruta coincide con identidad privilegiada observada."})

    lat = lateral.get("lateral") or {}
    if any((lat.get(k) or {}).get("count", 0) > 0 for k in ("rdp", "smb", "psexec", "winrm", "powershell", "wmi")):
        # only if path mentions related kinds/processes
        blob = " ".join(path_labels + list(kinds))
        if any(x in blob for x in ("rdp", "3389", "powershell", "smb", "445", "psexec", "wmi", "winrm")):
            w = PATH_WEIGHTS["has_lateral_evidence"]
            score += w
            factors.append({"factor": "has_lateral_evidence", "weight": w, "explanation": "Evidencia lateral existente y reflejada en la ruta."})

    if length >= 1 and len(kinds) >= 3:
        w = PATH_WEIGHTS["multi_engine_evidence"]
        score += w
        factors.append({"factor": "multi_engine_evidence", "weight": w, "explanation": f"Ruta cruza {len(kinds)} tipos de nodo evidenciados."})

    score = min(100, score)
    # Attack probability: score/100 explicable, not random
    attack_probability = round(score / 100.0, 3)
    # Business impact: high if reaches critical else medium/low by score bands
    if path.get("target_high_value") and score >= 50:
        business_impact = "ALTO"
    elif score >= 40:
        business_impact = "MEDIO"
    elif score > 0:
        business_impact = "BAJO"
    else:
        business_impact = NA
    confidence = "high" if len(factors) >= 3 else ("medium" if factors else "low")

    return {
        "attack_path_score": score,
        "attack_probability": attack_probability,
        "business_impact": business_impact,
        "confidence_score": confidence,
        "factors": factors,
        "weights_document": PATH_WEIGHTS,
        "rng": False,
        "invented": False,
    }


def compute_path_scores(max_paths: int = 20) -> Dict[str, Any]:
    graph = build_attack_graph()
    paths = find_paths(graph=graph, max_paths=max_paths)
    lateral = lateral_movement_evidence()
    priv = privilege_analysis()
    scored = []
    for p in paths.get("paths") or []:
        s = score_path(p, lateral, priv)
        scored.append({**p, "scores": s})
    scored.sort(key=lambda x: x.get("scores", {}).get("attack_path_score", 0), reverse=True)
    seal = seal_analysis("path_scores", {
        "count": len(scored),
        "top_score": scored[0]["scores"]["attack_path_score"] if scored else NA,
    })
    return {
        "ok": True,
        "scored_paths": scored,
        "count": len(scored),
        "seal": seal,
        "message": None if scored else NA,
        "invented": False,
        "graph_meta": {"nodes": graph.get("node_count"), "edges": graph.get("edge_count")},
    }
