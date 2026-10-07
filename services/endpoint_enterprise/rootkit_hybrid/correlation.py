"""
T8–T9 — Correlación multi-indicador + Risk Score (sin RNG).
No alerta por un único indicador débil.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


WEIGHTS = {
    "hidden_process_candidate": 28,
    "hidden_service_candidate": 30,
    "service_registry_not_in_scm": 18,
    "process_view_skew": 6,
    "driver_signature_anomaly": 14,
    "inline_hook_indicator": 32,
    "iat_or_forward_anomaly": 30,
    "etw_telemetry": 2,
}


def compute_indicator_risk(finding: Dict[str, Any], *, correlated_n: int = 1) -> Dict[str, Any]:
    ftype = finding.get("finding_type") or ""
    base = WEIGHTS.get(ftype, 8)
    conf = str(finding.get("confidence") or "medium").lower()
    conf_m = {"high": 1.2, "medium": 1.0, "low": 0.7}.get(conf, 1.0)
    corr_boost = min(25, max(0, (correlated_n - 1) * 8))
    score = int(min(100, base * conf_m + corr_boost))
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
        "factors": {
            "finding_type": ftype,
            "base_weight": base,
            "confidence_mult": conf_m,
            "correlation_boost": corr_boost,
            "correlated_indicators": correlated_n,
        },
        "basis": "pesos fijos por tipo + confianza + correlación — sin RNG",
        "verified": True,
    }


def correlate_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Agrupa indicadores. Solo emite alertas correlacionadas si:
    - ≥2 hallazgos medium+ de tipos fuertes distintos, o
    - 1 hallazgo high/critical con confidence high, o
    - hook + (process|service) mismatch
    service_registry_not_in_scm solo no basta para alertar (ruido residual).
    """
    weak_alone = {"etw_telemetry", "process_view_skew", "service_registry_not_in_scm"}
    actionable = [
        f
        for f in findings
        if f.get("finding_type") not in ("etw_telemetry",)
        and str(f.get("severity") or "").lower() not in ("info",)
    ]
    strong = [f for f in actionable if f.get("finding_type") not in weak_alone]
    types = {f.get("finding_type") for f in actionable}
    strong_types = {f.get("finding_type") for f in strong}
    high = [f for f in actionable if str(f.get("severity")).lower() in ("high", "critical")]

    alerts: List[Dict[str, Any]] = []
    enough = False
    reason = ""

    if len(strong) >= 2 and len(strong_types) >= 2:
        enough = True
        reason = "multi_indicator_correlation"
    elif any(
        str(f.get("severity")).lower() in ("high", "critical") and str(f.get("confidence")).lower() == "high"
        for f in strong
    ):
        enough = True
        reason = "single_high_confidence"
    elif "inline_hook_indicator" in types and (
        "hidden_process_candidate" in types or "hidden_service_candidate" in types
    ):
        enough = True
        reason = "hook_plus_concealment"
    elif len(strong) >= 1 and "hidden_service_candidate" in strong_types:
        enough = True
        reason = "hidden_service_confirmed"

    n = len(strong) if enough else len(actionable)
    for f in actionable:
        risk = compute_indicator_risk(f, correlated_n=n if enough else 1)
        f = dict(f)
        f["risk"] = risk
        if not enough:
            continue
        ft = f.get("finding_type")
        sev = str(f.get("severity") or "").lower()
        # Publicar alertas individuales solo para indicadores fuertes / high
        if ft in weak_alone and sev not in ("high", "critical"):
            continue
        if sev in ("low", "info"):
            continue
        alerts.append(f)

    # Always attach risk to all findings for forensics
    enriched = []
    for f in findings:
        ff = dict(f)
        if "risk" not in ff:
            ff["risk"] = compute_indicator_risk(ff, correlated_n=n if enough else 1)
        enriched.append(ff)

    return {
        "enough_evidence": enough,
        "correlation_reason": reason or "insufficient_evidence_no_alert",
        "indicators_n": len(actionable),
        "strong_indicators_n": len(strong),
        "types": sorted(types),
        "alerts": alerts,
        "findings_enriched": enriched,
        "timestamp_utc": _utc(),
        "policy": "no_alert_on_single_weak_indicator",
    }
