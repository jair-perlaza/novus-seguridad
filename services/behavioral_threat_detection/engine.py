"""
Motor BTDE — ciclo de telemetría → anomalías → correlación → publicación.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from utils.logger import logger

from services.behavioral_threat_detection.limitations import LIMITATIONS
from services.behavioral_threat_detection.sensors import collect_full_snapshot
from services.behavioral_threat_detection.baseline import (
    get_prev_snapshot,
    is_warm,
    load_baseline,
    update_from_snapshot,
)
from services.behavioral_threat_detection.anomalies import collect_anomaly_findings
from services.behavioral_threat_detection.correlator import correlate_findings
from services.behavioral_threat_detection.publish import publish_btde, seal_btde, host_profile_email

_lock = threading.Lock()
_last: Dict[str, Any] = {}
_loaded = False


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_btde_cycle(*, heavy: bool = False, publish: bool = True) -> Dict[str, Any]:
    global _loaded
    t0 = datetime.now(timezone.utc)
    if not _loaded:
        load_baseline()
        _loaded = True

    result: Dict[str, Any] = {
        "ok": False,
        "zero_day_detector": False,
        "ml_classifier": False,
        "signature_based": False,
        "limitations": LIMITATIONS,
        "timestamp_utc": _utc(),
        "version": "1.0.0-btde-fase1",
    }

    try:
        prev = get_prev_snapshot()
        snap = collect_full_snapshot(heavy=heavy)
        from services.tenant_scope_service import get_platform_tenant_id

        learn_meta = update_from_snapshot(snap, tenant_id=get_platform_tenant_id())
        warm = is_warm(get_platform_tenant_id())

        findings = collect_anomaly_findings(
            snap,
            prev=prev,
            learn_meta=learn_meta,
            warm=warm,
            include_heuristics=True,
        )
        corr = correlate_findings(findings)

        published = 0
        sealed = 0
        if publish and corr.get("enough_evidence"):
            corr_id = f"BTDE-CORR-{int(t0.timestamp())}"
            corr_ev = {
                "enough_evidence": True,
                "reason": corr.get("correlation_reason"),
                "types": corr.get("types"),
                "alerts_n": len(corr.get("alerts") or []),
                "risk": corr.get("risk"),
                "explanation": corr.get("explanation"),
                "zero_day_detector": False,
                "ml_classifier": False,
                "verified": True,
            }
            publish_btde(
                action="btde_correlated_alert",
                evidence=corr_ev,
                threat_type="behavioral_threat",
                confidence="medium",
                finding_id=corr_id,
                risk_level=str((corr.get("risk") or {}).get("level") or "medium"),
                feed_ape=False,
            )
            if seal_btde(
                finding_id=corr_id,
                action="btde_correlated_alert",
                evidence=corr_ev,
                risk_level=str((corr.get("risk") or {}).get("level") or "medium"),
            ):
                sealed += 1
            published += 1
            for alert in (corr.get("alerts") or [])[:5]:
                fid = f"BTDE-{alert.get('finding_type')}-{abs(hash(str(alert.get('evidence')))) % 10**10}"
                publish_btde(
                    action=f"btde_{alert.get('finding_type')}",
                    evidence={**alert, "explanation": corr.get("explanation"), "risk": corr.get("risk")},
                    threat_type="behavioral_anomaly",
                    confidence=str(alert.get("confidence") or "medium"),
                    finding_id=fid,
                    risk_level=str((corr.get("risk") or {}).get("level") or alert.get("severity") or "medium"),
                    feed_ape=False,
                )
                if seal_btde(
                    finding_id=fid,
                    action=f"btde_{alert.get('finding_type')}",
                    evidence=alert,
                    risk_level=str((corr.get("risk") or {}).get("level") or "medium"),
                ):
                    sealed += 1
                published += 1
        elif publish:
            scan_id = f"BTDE-SCAN-{int(t0.timestamp())}"
            scan_ev = {
                "enough_evidence": False,
                "reason": corr.get("correlation_reason"),
                "findings_n": len(findings),
                "types": corr.get("types"),
                "risk": corr.get("risk"),
                "explanation": corr.get("explanation"),
                "warm": warm,
                "learn_meta": {
                    "baseline_proc_n": learn_meta.get("baseline_proc_n"),
                    "baseline_svc_n": learn_meta.get("baseline_svc_n"),
                    "warm_cycles": learn_meta.get("warm_cycles"),
                },
                "zero_day_detector": False,
                "verified": True,
            }
            publish_btde(
                action="btde_scan_complete",
                evidence=scan_ev,
                threat_type="behavioral_telemetry",
                confidence="high",
                finding_id=scan_id,
                risk_level="info",
                feed_ape=False,
            )
            if seal_btde(
                finding_id=scan_id,
                action="btde_scan_complete",
                evidence=scan_ev,
                risk_level="info",
            ):
                sealed += 1
            published += 1

        # APE learnable tick (baseline counts — no amenazas)
        if publish:
            try:
                from services.adaptive_profile_engine import observe_async

                observe_async(
                    host_profile_email(),
                    event_type="btde_tick",
                    evidence={
                        "learnable": True,
                        "process_count": (snap.get("processes") or {}).get("count"),
                        "connection_count": (snap.get("connections") or {}).get("count"),
                        "services_running": ((snap.get("services") or {}).get("counts") or {}).get("running"),
                        "resources": snap.get("resources"),
                        "enough_evidence": corr.get("enough_evidence"),
                    },
                    risk_level="info",
                    evaluate=False,
                )
            except Exception as exc:
                logger.debug("btde ape: %s", exc)

        elapsed = round((datetime.now(timezone.utc) - t0).total_seconds() * 1000, 1)
        result.update(
            {
                "ok": True,
                "telemetry": {
                    "processes_n": (snap.get("processes") or {}).get("count"),
                    "connections_n": (snap.get("connections") or {}).get("count"),
                    "services_running": ((snap.get("services") or {}).get("counts") or {}).get("running"),
                    "users_n": (snap.get("sessions") or {}).get("users_n"),
                    "resources": snap.get("resources"),
                    "persistence_n": (snap.get("persistence") or {}).get("count"),
                },
                "baseline": {
                    "warm": warm,
                    "warm_cycles": learn_meta.get("warm_cycles"),
                    "proc_n": learn_meta.get("baseline_proc_n"),
                    "svc_n": learn_meta.get("baseline_svc_n"),
                },
                "findings_n": len(findings),
                "correlation": {
                    "enough_evidence": corr.get("enough_evidence"),
                    "reason": corr.get("correlation_reason"),
                    "types": corr.get("types"),
                    "alerts_n": len(corr.get("alerts") or []),
                    "risk": corr.get("risk"),
                },
                "explanation": corr.get("explanation"),
                "published": published,
                "forensic_sealed": sealed,
                "duration_ms": elapsed,
            }
        )
    except Exception as exc:
        result["error"] = str(exc)[:300]
        logger.warning("btde cycle: %s", exc)

    with _lock:
        _last.clear()
        _last.update(result)
    return result


def get_btde_status() -> Dict[str, Any]:
    with _lock:
        snap = dict(_last) if _last else {}
    return {
        "ok": True,
        "zero_day_detector": False,
        "ml_classifier": False,
        "last_scan_at": snap.get("timestamp_utc"),
        "last_ok": snap.get("ok"),
        "last_correlation": snap.get("correlation"),
        "last_published": snap.get("published"),
        "last_risk": (snap.get("correlation") or {}).get("risk"),
        "limitations_n": len(LIMITATIONS),
        "version": "1.0.0-btde-fase1",
    }
