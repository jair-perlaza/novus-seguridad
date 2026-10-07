#!/usr/bin/env python3
"""
Correlación multicapa ZDDE + Risk Score explicable (sin RNG).
Ningún indicador aislado → CANDIDATO_AMENAZA_DESCONOCIDA.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from services.zero_day_detection.limitations import CLASSIFICATION


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Pesos fijos por factor de capa (reproducibles)
LAYER_WEIGHTS = {
    "btde_enough": 28,
    "btde_high_risk": 18,
    "btde_findings": 10,
    "swarm_correlations": 12,
    "mesh_shared_intel": 16,
    "mesh_multi_peer_ioc": 10,
    "endpoint_lolbin_shell": 14,
    "endpoint_unusual_net": 10,
    "endpoint_persistence_dense": 8,
    "network_alerts": 12,
    "ape_online": 6,
    "cryptovault_ok": 4,
    "forensic_ready": 6,
    "defense_center_active": 6,
}


def _score_factors(layers: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
    factors: List[Dict[str, Any]] = []
    score = 0
    btde = layers.get("btde") or {}
    swarm = layers.get("swarm") or {}
    mesh = layers.get("mesh") or {}
    endpoint = layers.get("endpoint") or {}
    network = layers.get("network") or {}
    ape = layers.get("ape") or {}
    crypto = layers.get("cryptovault") or {}
    forensic = layers.get("forensic") or {}
    dc = layers.get("defense_center") or {}

    def add(key: str, cond: bool, detail: str) -> None:
        nonlocal score
        if not cond:
            return
        w = int(LAYER_WEIGHTS.get(key, 5))
        score += w
        factors.append({"factor": key, "weight": w, "detail": detail, "verified": True})

    add("btde_enough", bool(btde.get("enough_evidence")), f"BTDE enough_evidence reason={btde.get('correlation_reason')}")
    risk_lvl = str(((btde.get("risk") or {}).get("level") or "")).lower()
    add("btde_high_risk", risk_lvl in ("high", "critical"), f"BTDE risk_level={risk_lvl}")
    add("btde_findings", int(btde.get("findings_n") or 0) >= 3, f"BTDE findings_n={btde.get('findings_n')}")
    add("swarm_correlations", int(swarm.get("recent_correlations_n") or 0) >= 1, "Swarm recent correlations")
    add("mesh_shared_intel", bool(mesh.get("has_shared_intel")), f"mesh ioc={mesh.get('ioc_counts')}")
    ioc = mesh.get("ioc_counts") or {}
    peers_hint = sum(1 for k in ("ips", "domains", "hashes") if int(ioc.get(k) or 0) > 0) >= 2
    add("mesh_multi_peer_ioc", peers_hint, "≥2 familias IOC en mesh")
    add(
        "endpoint_lolbin_shell",
        int(endpoint.get("suspicious_tool_procs_n") or 0) >= 2,
        f"lolbin/shell procs={endpoint.get('suspicious_tool_procs_n')}",
    )
    add(
        "endpoint_unusual_net",
        int(endpoint.get("unusual_remote_port_conns_n") or 0) >= 3,
        f"unusual_remote_port_conns={endpoint.get('unusual_remote_port_conns_n')}",
    )
    add(
        "endpoint_persistence_dense",
        int(endpoint.get("persistence_run_entries_n") or 0) >= 8,
        f"Run persistence entries={endpoint.get('persistence_run_entries_n')}",
    )
    add("network_alerts", int(network.get("alerts_n") or 0) >= 1, f"NDR alerts_n={network.get('alerts_n')}")
    add("ape_online", bool(ape.get("ok")), "APE engine_status ok")
    add("cryptovault_ok", bool(crypto.get("ok")), "CryptoVault round-trip")
    add("forensic_ready", bool(forensic.get("ok")), "Forensic summary ok")
    add("defense_center_active", int(dc.get("active_n") or 0) >= 1, f"engines active={dc.get('active_n')}")

    score = min(100, score)
    return score, factors


def _active_signal_layers(layers: Dict[str, Any], factors: List[Dict[str, Any]]) -> List[str]:
    """Capas con señal de amenaza (no solo salud)."""
    signal_keys = {
        "btde_enough",
        "btde_high_risk",
        "btde_findings",
        "swarm_correlations",
        "mesh_shared_intel",
        "mesh_multi_peer_ioc",
        "endpoint_lolbin_shell",
        "endpoint_unusual_net",
        "endpoint_persistence_dense",
        "network_alerts",
    }
    motor_map = {
        "btde_enough": "btde",
        "btde_high_risk": "btde",
        "btde_findings": "btde",
        "swarm_correlations": "swarm",
        "mesh_shared_intel": "mesh",
        "mesh_multi_peer_ioc": "mesh",
        "endpoint_lolbin_shell": "endpoint",
        "endpoint_unusual_net": "endpoint",
        "endpoint_persistence_dense": "endpoint",
        "network_alerts": "network",
    }
    motors = []
    for f in factors:
        if f.get("factor") in signal_keys:
            m = motor_map.get(f["factor"])
            if m and m not in motors:
                motors.append(m)
    return motors


def correlate_layers(bundle: Dict[str, Any]) -> Dict[str, Any]:
    layers = bundle.get("layers") or {}
    score, factors = _score_factors(layers)
    signal_motors = _active_signal_layers(layers, factors)
    participating = list(bundle.get("participating") or [])

    level = (
        "critical"
        if score >= 80
        else "high"
        if score >= 60
        else "medium"
        if score >= 35
        else "low"
        if score >= 15
        else "info"
    )

    # Política estricta: candidato desconocido solo con ≥3 motores de SEÑAL + score alto
    classification = "EVIDENCIA_INSUFICIENTE"
    reason = "insufficient_multi_layer_signal"
    if len(signal_motors) >= 3 and score >= 55 and (layers.get("btde") or {}).get("enough_evidence"):
        classification = "CANDIDATO_AMENAZA_DESCONOCIDA"
        reason = "multi_layer_behavioral_correlation_ge3_motors"
    elif len(signal_motors) >= 2 and score >= 35:
        classification = "ANOMALIA_CORRELACIONADA"
        reason = "multi_layer_anomaly_ge2_motors"
    elif len(signal_motors) == 1:
        classification = "EVIDENCIA_INSUFICIENTE"
        reason = "single_layer_insufficient_no_zero_day_claim"
    else:
        classification = "EVIDENCIA_INSUFICIENTE"
        reason = "no_actionable_signal_layers"

    confidence = (
        "high"
        if classification == "CANDIDATO_AMENAZA_DESCONOCIDA" and score >= 70
        else "medium"
        if classification != "EVIDENCIA_INSUFICIENTE"
        else "low"
    )

    risk = {
        "score": score,
        "level": level,
        "factors": factors,
        "basis": "suma de pesos fijos por factor de capa verificado — sin RNG",
        "verified": True,
        "reproducible": True,
    }

    explanation = {
        "classification": classification,
        "classification_meaning": CLASSIFICATION.get(classification),
        "correlation_reason": reason,
        "confidence_level": confidence,
        "motors_participating": participating,
        "signal_motors": signal_motors,
        "signal_motors_n": len(signal_motors),
        "factors_observed": factors,
        "risk": risk,
        "zero_day_cve_confirmed": False,
        "signature_based": False,
        "static_rules_primary": False,
        "invented": False,
        "kernel_role": {
            "analyzes": True,
            "correlates": True,
            "prioritizes": True,
            "explains": True,
            "proposes": True,
            "invents_threats": False,
            "executes_destructive": False,
        },
        "reasoning_chain": [
            "1. Recolección de capas (BTDE, Swarm/Mesh, Endpoint, Red, APE, CryptoVault, Forense, Centro Defensa).",
            "2. Extracción de factores verificables con pesos fijos.",
            f"3. Motores con señal={signal_motors} (n={len(signal_motors)}).",
            f"4. Risk Score={score} ({level}) — {risk['basis']}.",
            f"5. Clasificación={classification} — {CLASSIFICATION.get(classification)}",
            "6. Si evidencia insuficiente: NO se afirma zero-day.",
        ],
        "timestamp_utc": _utc(),
    }

    proposals = []
    if classification == "CANDIDATO_AMENAZA_DESCONOCIDA":
        proposals = [
            {"action": "elevate_alert", "requires_approval": False},
            {"action": "notify_defense_center", "requires_approval": False},
            {"action": "preserve_evidence", "requires_approval": False},
            {"action": "increase_monitoring", "requires_approval": False},
            {"action": "isolate_host", "requires_approval": True},
            {"action": "kill_process", "requires_approval": True},
        ]
    elif classification == "ANOMALIA_CORRELACIONADA":
        proposals = [
            {"action": "notify_defense_center", "requires_approval": False},
            {"action": "increase_monitoring", "requires_approval": False},
            {"action": "preserve_evidence", "requires_approval": False},
        ]

    return {
        "enough_for_unknown_threat_candidate": classification == "CANDIDATO_AMENAZA_DESCONOCIDA",
        "classification": classification,
        "correlation_reason": reason,
        "confidence_level": confidence,
        "risk": risk,
        "explanation": explanation,
        "proposals": proposals,
        "signal_motors": signal_motors,
        "participating": participating,
        "timestamp_utc": _utc(),
        "policy": {
            "no_alert_on_single_weak_layer": True,
            "no_zero_day_claim_without_ge3_signal_motors": True,
            "no_destructive_auto": True,
            "no_rng": True,
        },
    }
