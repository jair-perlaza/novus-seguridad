"""
T3/T6/T9 — Correlación multi-indicador + Risk Score + explicación (sin RNG).
Ningún indicador débil solo genera alerta.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

WEIGHTS = {
    "execution_from_temp": 28,
    "anomalous_powershell": 30,
    "anomalous_cmd": 18,
    "lolbin_network_fetch": 28,
    "mass_process_creation": 26,
    "new_persistence_runkey": 32,
    "privilege_context_anomaly": 30,
    "new_running_service": 18,
    "never_seen_processes": 12,
    "unusual_connections_burst": 16,
    "high_connection_fanout": 12,
    "cpu_spike": 8,
    "memory_pressure": 8,
    "abrupt_cpu_change": 10,
    "new_service_created": 16,
    "suspicious_persistence_task": 20,
    "office_suspicious_child": 22,
    "process_masquerading": 28,
}

WEAK_ALONE = {
    "cpu_spike",
    "memory_pressure",
    "abrupt_cpu_change",
    "never_seen_processes",
    "high_connection_fanout",
    "office_suspicious_child",
}


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_risk(findings: List[Dict[str, Any]], *, correlated: bool) -> Dict[str, Any]:
    score = 0
    factors = []
    for f in findings:
        ft = f.get("finding_type") or ""
        base = WEIGHTS.get(ft, 8)
        conf = str(f.get("confidence") or "medium").lower()
        conf_m = {"high": 1.2, "medium": 1.0, "low": 0.65}.get(conf, 1.0)
        sev = str(f.get("severity") or "low").lower()
        sev_m = {"critical": 1.3, "high": 1.15, "medium": 1.0, "low": 0.7, "info": 0.4}.get(sev, 1.0)
        w = int(base * conf_m * sev_m)
        score += w
        factors.append({"type": ft, "weight": w, "severity": sev, "confidence": conf})
    if correlated:
        score = int(min(100, score * 1.1 + min(15, (len(findings) - 1) * 4)))
    else:
        score = int(min(100, score * 0.85))
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
    return {
        "score": score,
        "level": level,
        "factors": factors,
        "basis": "pesos fijos por tipo x confianza x severidad + boost correlacion — sin RNG",
        "correlated": correlated,
        "verified": True,
    }


def build_explanation(
    findings: List[Dict[str, Any]],
    *,
    risk: Dict[str, Any],
    motors: List[str],
    enough: bool,
    reason: str,
) -> Dict[str, Any]:
    chain = [
        "1. Telemetría host (procesos/conexiones/servicios/recursos/persistencia).",
        "2. Anomalías comportamentales sin firmas AV.",
        f"3. Correlación: {reason}.",
        f"4. Risk Score={risk.get('score')} ({risk.get('level')}) — {risk.get('basis')}.",
        "5. Publicación a Swarm/Forense solo si enough_evidence.",
    ]
    return {
        "indicators_used": [
            {
                "type": f.get("finding_type"),
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "method": f.get("detection_method") or f.get("source"),
            }
            for f in findings
        ],
        "motors_participating": motors,
        "confidence_level": (
            "high"
            if enough and int(risk.get("score") or 0) >= 60
            else "medium"
            if enough
            else "low"
        ),
        "reasoning_chain": chain,
        "enough_evidence": enough,
        "correlation_reason": reason,
        "invented": False,
        "timestamp_utc": _utc(),
    }


def correlate_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    actionable = [
        f
        for f in findings
        if str(f.get("severity") or "").lower() not in ("info",)
        and not (
            f.get("finding_type") in WEAK_ALONE
            and str(f.get("severity") or "").lower() == "low"
            and str(f.get("confidence") or "").lower() == "low"
        )
    ]
    types = {f.get("finding_type") for f in actionable}
    strong = [f for f in actionable if f.get("finding_type") not in WEAK_ALONE or str(f.get("severity")).lower() in ("high", "critical")]
    strong_types = {f.get("finding_type") for f in strong}

    enough = False
    reason = "insufficient_evidence_no_alert"

    if len(strong) >= 2 and len(strong_types) >= 2:
        enough = True
        reason = "multi_indicator_correlation"
    elif any(
        str(f.get("severity")).lower() in ("high", "critical") and str(f.get("confidence")).lower() == "high"
        for f in strong
    ):
        enough = True
        reason = "single_high_confidence_strong"
    elif "anomalous_powershell" in strong_types and (
        "execution_from_temp" in types or "lolbin_network_fetch" in types or "new_persistence_runkey" in types
    ):
        enough = True
        reason = "powershell_plus_lateral_indicator"
    elif "office_suspicious_child" in types and (
        "anomalous_powershell" in types or "lolbin_network_fetch" in types or "process_masquerading" in types
    ):
        enough = True
        reason = "office_shell_plus_secondary_indicator"

    risk = compute_risk(actionable if enough else strong or actionable, correlated=enough)
    motors = [
        "behavioral_threat_detection",
        "swarm_defense",
        "adaptive_profile_engine",
        "kernel_ia",
        "forensic",
        "defense_center",
        "endpoint_enterprise",
    ]
    explanation = build_explanation(
        actionable if enough else findings[:8],
        risk=risk,
        motors=motors,
        enough=enough,
        reason=reason,
    )

    alerts = []
    if enough:
        for f in actionable:
            if f.get("finding_type") in WEAK_ALONE and str(f.get("severity")).lower() not in ("high", "critical"):
                continue
            if str(f.get("severity")).lower() in ("low", "info"):
                continue
            ff = dict(f)
            ff["risk"] = risk
            alerts.append(ff)

    return {
        "enough_evidence": enough,
        "correlation_reason": reason,
        "indicators_n": len(actionable),
        "strong_n": len(strong),
        "types": sorted(t for t in types if t),
        "alerts": alerts,
        "risk": risk,
        "explanation": explanation,
        "findings": findings,
        "timestamp_utc": _utc(),
        "policy": "no_alert_on_single_weak_indicator",
    }
