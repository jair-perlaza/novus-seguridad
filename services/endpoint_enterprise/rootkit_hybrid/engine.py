"""
Motor Rootkit Detection Híbrido — orquesta cross-view, drivers, hooks, ETW, correlación.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from utils.logger import logger

from services.endpoint_enterprise.rootkit_hybrid.limitations import LIMITATIONS
from services.endpoint_enterprise.rootkit_hybrid.cross_view import run_cross_view
from services.endpoint_enterprise.rootkit_hybrid.drivers import inventory_drivers, compare_driver_sets
from services.endpoint_enterprise.rootkit_hybrid.hooks import (
    scan_inline_hooks_current_process,
    scan_iat_anomalies_sample,
)
from services.endpoint_enterprise.rootkit_hybrid.ssdt import check_ssdt_capability
from services.endpoint_enterprise.rootkit_hybrid.etw_collector import (
    collect_etw_like_events,
    etw_events_as_findings,
)
from services.endpoint_enterprise.rootkit_hybrid.correlation import correlate_findings

_lock = threading.Lock()
_last: Dict[str, Any] = {}


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _seal_forensic(
    *,
    finding_id: str,
    action: str,
    evidence: Dict[str, Any],
    risk_level: str,
) -> Optional[Dict[str, Any]]:
    """T10 — sello forense SHA-256 + Ed25519 + cadena (sin valores inventados)."""
    try:
        import socket

        from services.forensic_evidence_integrity_service import seal_evidence

        return seal_evidence(
            source_id=finding_id,
            source_type="rootkit_hybrid",
            motor="endpoint_enterprise.rootkit_hybrid",
            evidence_type=action,
            payload={
                "action": action,
                "risk_level": risk_level,
                "evidence": evidence,
                "ssdt_implemented": False,
                "kernel_rootkit_engine": False,
                "recorded_at_utc": _utc(),
            },
            equipment=socket.gethostname(),
            user_email=None,
        )
    except Exception as exc:
        logger.debug("rkh forensic seal: %s", exc)
        return None


def run_hybrid_rootkit_scan(*, include_etw: bool = True, publish: bool = True) -> Dict[str, Any]:
    """
    Escaneo híbrido incremental. SSDT nunca se marca implementado.
    Publica a Swarm solo alertas correlacionadas (enough_evidence).
    """
    t0 = datetime.now(timezone.utc)
    result: Dict[str, Any] = {
        "ok": False,
        "kernel_rootkit_engine": False,
        "ssdt_implemented": False,
        "limitations": LIMITATIONS,
        "timestamp_utc": _utc(),
        "version": "1.0.0-rootkit-hybrid-fase1",
    }

    try:
        cross = run_cross_view()
        drv = inventory_drivers()
        drv_findings = compare_driver_sets(drv)
        hooks = scan_inline_hooks_current_process()
        iat = scan_iat_anomalies_sample()
        ssdt = check_ssdt_capability()
        etw = collect_etw_like_events(limit=30) if include_etw else {"ok": False, "events": [], "skipped": True}

        findings = []
        findings.extend(cross.get("findings") or [])
        findings.extend(drv_findings)
        findings.extend(hooks.get("findings") or [])
        findings.extend(iat.get("findings") or [])
        findings.extend(etw_events_as_findings(etw))

        corr = correlate_findings(findings)
        published = 0
        sealed = 0
        if publish and corr.get("enough_evidence"):
            from services.endpoint_enterprise.publish import publish_finding

            # Resumen correlacionado (siempre 1) + alertas fuertes (máx 5)
            corr_id = f"RKH-CORR-{int(t0.timestamp())}"
            corr_ev = {
                "enough_evidence": True,
                "reason": corr.get("correlation_reason"),
                "types": corr.get("types"),
                "alerts_n": len(corr.get("alerts") or []),
                "strong_indicators_n": corr.get("strong_indicators_n"),
                "ssdt_implemented": False,
                "kernel_rootkit_engine": False,
                "verified": True,
            }
            publish_finding(
                action="rootkit_hybrid_correlated_alert",
                evidence=corr_ev,
                threat_type="rootkit_correlation",
                confidence="medium",
                finding_id=corr_id,
                risk_level="high" if len(corr.get("alerts") or []) >= 2 else "medium",
                feed_ape=False,
            )
            if _seal_forensic(
                finding_id=corr_id,
                action="rootkit_hybrid_correlated_alert",
                evidence=corr_ev,
                risk_level="high" if len(corr.get("alerts") or []) >= 2 else "medium",
            ):
                sealed += 1
            published += 1
            for alert in (corr.get("alerts") or [])[:5]:
                risk = alert.get("risk") or {}
                fid = f"RKH-{alert.get('finding_type')}-{abs(hash(str(alert.get('evidence')))) % 10**10}"
                ev = {
                    **alert,
                    "correlation": {
                        "reason": corr.get("correlation_reason"),
                        "indicators_n": corr.get("indicators_n"),
                        "types": corr.get("types"),
                    },
                }
                publish_finding(
                    action=f"rootkit_hybrid_{alert.get('finding_type')}",
                    evidence=ev,
                    threat_type="rootkit_indicator",
                    confidence=str(alert.get("confidence") or "medium"),
                    finding_id=fid,
                    risk_level=str(risk.get("level") or alert.get("severity") or "medium"),
                    feed_ape=False,
                )
                if _seal_forensic(
                    finding_id=fid,
                    action=f"rootkit_hybrid_{alert.get('finding_type')}",
                    evidence=ev,
                    risk_level=str(risk.get("level") or alert.get("severity") or "medium"),
                ):
                    sealed += 1
                published += 1
        elif publish:
            # Tick forense de escaneo limpio / insuficiente evidencia (sin alerta)
            try:
                from services.endpoint_enterprise.publish import publish_finding

                scan_id = f"RKH-SCAN-{int(t0.timestamp())}"
                scan_ev = {
                    "enough_evidence": False,
                    "reason": corr.get("correlation_reason"),
                    "findings_n": len(findings),
                    "types": corr.get("types"),
                    "ssdt_implemented": False,
                    "kernel_rootkit_engine": False,
                    "verified": True,
                }
                publish_finding(
                    action="rootkit_hybrid_scan_complete",
                    evidence=scan_ev,
                    threat_type="rootkit_hybrid_telemetry",
                    confidence="high",
                    finding_id=scan_id,
                    risk_level="info",
                    feed_ape=False,
                )
                if _seal_forensic(
                    finding_id=scan_id,
                    action="rootkit_hybrid_scan_complete",
                    evidence=scan_ev,
                    risk_level="info",
                ):
                    sealed += 1
                published += 1
            except Exception as exc:
                logger.debug("rkh scan_complete publish: %s", exc)

        # APE learnable tick (non-threat baseline of view counts)
        if publish:
            try:
                from services.adaptive_profile_engine import observe_async
                from services.endpoint_enterprise.publish import host_profile_email

                observe_async(
                    host_profile_email(),
                    event_type="rootkit_hybrid_tick",
                    evidence={
                        "learnable": True,
                        "process_view_counts": (cross.get("processes") or {}).get("counts"),
                        "services_counts": cross.get("services"),
                        "hooks_checked": hooks.get("checked_n"),
                        "etw_events_n": etw.get("events_n"),
                        "enough_evidence": corr.get("enough_evidence"),
                    },
                    risk_level="info",
                    evaluate=False,
                )
            except Exception as exc:
                logger.debug("rkh ape: %s", exc)

        elapsed_ms = round((datetime.now(timezone.utc) - t0).total_seconds() * 1000, 1)
        result.update(
            {
                "ok": True,
                "cross_view": {
                    "processes": cross.get("processes"),
                    "services": cross.get("services"),
                    "sessions": cross.get("sessions"),
                    "findings_n": len(cross.get("findings") or []),
                },
                "drivers": {
                    "ok": drv.get("ok"),
                    "count": drv.get("count"),
                    "by_state": drv.get("by_state"),
                    "signature_probe_n": len(drv.get("signature_probe") or []),
                    "limitation": drv.get("limitation"),
                },
                "hooks": {
                    "ok": hooks.get("ok"),
                    "checked_n": hooks.get("checked_n"),
                    "findings_n": len(hooks.get("findings") or []),
                    "iat_findings_n": len(iat.get("findings") or []),
                    "scope": hooks.get("scope"),
                },
                "ssdt": ssdt,
                "etw": {
                    "ok": etw.get("ok"),
                    "events_n": etw.get("events_n"),
                    "channels_ok": etw.get("channels_ok"),
                    "limitation": etw.get("limitation"),
                },
                "correlation": {
                    "enough_evidence": corr.get("enough_evidence"),
                    "reason": corr.get("correlation_reason"),
                    "indicators_n": corr.get("indicators_n"),
                    "types": corr.get("types"),
                    "alerts_n": len(corr.get("alerts") or []),
                },
                "findings_n": len(findings),
                "published": published,
                "forensic_sealed": sealed,
                "duration_ms": elapsed_ms,
            }
        )
    except Exception as exc:
        result["error"] = str(exc)[:300]
        logger.warning("hybrid rootkit scan: %s", exc)

    with _lock:
        _last.clear()
        _last.update(result)
    return result


def get_rootkit_hybrid_status() -> Dict[str, Any]:
    with _lock:
        snap = dict(_last) if _last else {}
    return {
        "ok": True,
        "kernel_rootkit_engine": False,
        "ssdt_implemented": False,
        "last_scan_at": snap.get("timestamp_utc"),
        "last_ok": snap.get("ok"),
        "last_correlation": snap.get("correlation"),
        "last_published": snap.get("published"),
        "limitations_n": len(LIMITATIONS),
        "version": "1.0.0-rootkit-hybrid-fase1",
    }
