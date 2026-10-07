#!/usr/bin/env python3
"""
Zero-Day Detection Engine Enterprise (ZDDE).
Correlación multicapa de amenaza desconocida — no antivirus, no firmas, no RNG.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from utils.logger import logger

from services.zero_day_detection.correlator import correlate_layers
from services.zero_day_detection.layers import gather_all_layers
from services.zero_day_detection.limitations import CLASSIFICATION, LIMITATIONS
from services.zero_day_detection.publish import notify_proposals, publish_zdde, seal_zdde

_lock = threading.Lock()
_last: Dict[str, Any] = {}
_stats: Dict[str, Any] = {
    "cycles": 0,
    "events_analyzed": 0,
    "correlations": 0,
    "candidates": 0,
    "insufficient": 0,
    "anomalies": 0,
}


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_zdde_cycle(
    *,
    heavy: bool = False,
    publish: bool = True,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    t0 = datetime.now(timezone.utc)
    result: Dict[str, Any] = {
        "ok": False,
        "engine": "zero_day_detection_engine",
        "version": "1.0.0-zdde-enterprise",
        "signature_based": False,
        "static_rules_primary": False,
        "zero_day_cve_oracle": False,
        "antivirus": False,
        "limitations": LIMITATIONS,
        "classifications": CLASSIFICATION,
        "timestamp_utc": _utc(),
        "tenant_id": tenant_id,
    }
    try:
        bundle = gather_all_layers(heavy=heavy, tenant_id=tenant_id)
        corr = correlate_layers(bundle)
        classification = corr.get("classification") or "EVIDENCIA_INSUFICIENTE"
        risk = corr.get("risk") or {}
        duration_ms = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)

        published = 0
        sealed = 0
        notify = {"notifications": []}
        if publish:
            fid = f"ZDDE-{classification}-{int(t0.timestamp())}"
            evidence = {
                "classification": classification,
                "correlation_reason": corr.get("correlation_reason"),
                "confidence_level": corr.get("confidence_level"),
                "signal_motors": corr.get("signal_motors"),
                "participating": corr.get("participating"),
                "risk": risk,
                "explanation": corr.get("explanation"),
                "proposals": corr.get("proposals"),
                "layers_summary": {
                    k: {
                        "ok": (v or {}).get("ok"),
                        "motor": (v or {}).get("motor"),
                        **{
                            sk: (v or {}).get(sk)
                            for sk in (
                                "enough_evidence",
                                "findings_n",
                                "has_shared_intel",
                                "suspicious_tool_procs_n",
                                "alerts_n",
                                "recent_correlations_n",
                            )
                            if sk in (v or {})
                        },
                    }
                    for k, v in (bundle.get("layers") or {}).items()
                },
                "verified": True,
                "zero_day_cve_confirmed": False,
            }
            action = (
                "zdde_unknown_threat_candidate"
                if classification == "CANDIDATO_AMENAZA_DESCONOCIDA"
                else "zdde_correlated_anomaly"
                if classification == "ANOMALIA_CORRELACIONADA"
                else "zdde_insufficient_evidence"
            )
            # Publicar siempre el ciclo (evidencia insuficiente también queda registrada honestamente)
            pub = publish_zdde(
                action=action,
                evidence=evidence,
                threat_type="unknown_threat_correlation"
                if classification == "CANDIDATO_AMENAZA_DESCONOCIDA"
                else "behavioral_correlation",
                confidence=str(corr.get("confidence_level") or "low"),
                finding_id=fid,
                risk_level=str(risk.get("level") or "info"),
            )
            if pub.get("status") != "error":
                published += 1
            if seal_zdde(
                finding_id=fid,
                action=action,
                evidence=evidence,
                risk_level=str(risk.get("level") or "info"),
            ):
                sealed += 1
            notify = notify_proposals(corr.get("proposals") or [], classification)

        events_n = sum(
            int((bundle.get("layers") or {}).get(k, {}).get("findings_n") or 0)
            + int((bundle.get("layers") or {}).get(k, {}).get("alerts_n") or 0)
            + int((bundle.get("layers") or {}).get(k, {}).get("suspicious_tool_procs_n") or 0)
            + int((bundle.get("layers") or {}).get(k, {}).get("recent_correlations_n") or 0)
            for k in ("btde", "network", "endpoint", "swarm")
        )

        result.update(
            {
                "ok": True,
                "bundle": {
                    "participating": bundle.get("participating"),
                    "participating_n": bundle.get("participating_n"),
                    "gathered_at": bundle.get("gathered_at"),
                    "layers": bundle.get("layers"),
                },
                "correlation": corr,
                "classification": classification,
                "risk": risk,
                "confidence_level": corr.get("confidence_level"),
                "explanation": corr.get("explanation"),
                "proposals": corr.get("proposals"),
                "notify": notify,
                "published": published,
                "sealed": sealed,
                "events_analyzed": events_n,
                "duration_ms": duration_ms,
                "analysis_time_ms": duration_ms,
            }
        )

        with _lock:
            _stats["cycles"] = int(_stats.get("cycles") or 0) + 1
            _stats["events_analyzed"] = int(_stats.get("events_analyzed") or 0) + events_n
            _stats["correlations"] = int(_stats.get("correlations") or 0) + 1
            if classification == "CANDIDATO_AMENAZA_DESCONOCIDA":
                _stats["candidates"] = int(_stats.get("candidates") or 0) + 1
            elif classification == "ANOMALIA_CORRELACIONADA":
                _stats["anomalies"] = int(_stats.get("anomalies") or 0) + 1
            else:
                _stats["insufficient"] = int(_stats.get("insufficient") or 0) + 1
            _last.clear()
            _last.update(
                {
                    "timestamp_utc": result["timestamp_utc"],
                    "classification": classification,
                    "risk": risk,
                    "confidence_level": corr.get("confidence_level"),
                    "signal_motors": corr.get("signal_motors"),
                    "participating": corr.get("participating"),
                    "duration_ms": duration_ms,
                    "correlation_reason": corr.get("correlation_reason"),
                    "enough_for_unknown_threat_candidate": corr.get("enough_for_unknown_threat_candidate"),
                    "zero_day_cve_confirmed": False,
                }
            )
    except Exception as exc:
        logger.warning("zdde cycle: %s", exc)
        result["error"] = str(exc)[:240]
        result["classification"] = "EVIDENCIA_INSUFICIENTE"
    return result


def get_zdde_status() -> Dict[str, Any]:
    with _lock:
        last = dict(_last)
        stats = dict(_stats)
    return {
        "ok": True,
        "engine": "zero_day_detection_engine",
        "active": True,
        "signature_based": False,
        "static_rules_primary": False,
        "zero_day_cve_oracle": False,
        "last": last or None,
        "stats": stats,
        "limitations": LIMITATIONS,
        "classifications": CLASSIFICATION,
        "timestamp_utc": _utc(),
    }


def get_zdde_dashboard() -> Dict[str, Any]:
    """Payload dashboard: omitir campos vacíos."""
    st = get_zdde_status()
    last = st.get("last") or {}
    out: Dict[str, Any] = {
        "engine": "ZDDE",
        "state": "activo",
        "signature_based": False,
        "zero_day_cve_oracle": False,
        "stats": st.get("stats"),
        "timestamp_utc": st.get("timestamp_utc"),
    }
    if last.get("classification"):
        out["classification"] = last["classification"]
    if last.get("risk"):
        out["risk"] = last["risk"]
    if last.get("confidence_level"):
        out["confidence_level"] = last["confidence_level"]
    if last.get("signal_motors"):
        out["motors_participants"] = last["signal_motors"]
    if last.get("participating"):
        out["layers_online"] = last["participating"]
    if last.get("correlation_reason"):
        out["explanation"] = last["correlation_reason"]
    if last.get("duration_ms") is not None:
        out["analysis_time_ms"] = last["duration_ms"]
    if last.get("timestamp_utc"):
        out["last_analysis_utc"] = last["timestamp_utc"]
    # No mostrar claim de zero-day CVE
    out["claims"] = {
        "detects_all_zero_days": False,
        "cve_zero_day_confirmed": False,
        "insufficient_evidence_honored": True,
    }
    return out
