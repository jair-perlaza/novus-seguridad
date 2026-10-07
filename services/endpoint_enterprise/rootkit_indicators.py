"""
Indicadores de rootkit — delega al motor híbrido user-mode.
Rootkit kernel propio / SSDT = NO IMPLEMENTADO.
"""
from __future__ import annotations

from typing import Any, Dict

from services.endpoint_enterprise.rootkit_hybrid.limitations import LIMITATIONS
from services.endpoint_enterprise.rootkit_hybrid.engine import run_hybrid_rootkit_scan


def run_rootkit_indicator_checks(*, publish: bool = False) -> Dict[str, Any]:
    """
    Compatibilidad con Endpoint Enterprise orchestrator.
    publish=False en ciclos ligeros; el scan híbrido pesado publica solo correlacionado.
    """
    scan = run_hybrid_rootkit_scan(include_etw=True, publish=publish)
    findings = []
    # Flatten for legacy consumers
    cross_n = (scan.get("cross_view") or {}).get("findings_n") or 0
    corr = scan.get("correlation") or {}
    if corr.get("alerts_n"):
        findings.append(
            {
                "finding_type": "rootkit_hybrid_correlated",
                "severity": "high" if corr.get("alerts_n", 0) >= 2 else "medium",
                "confidence": "medium",
                "evidence": corr,
                "verified": True,
            }
        )
    return {
        "ok": bool(scan.get("ok")),
        "kernel_rootkit_engine": False,
        "ssdt_implemented": False,
        "limitations": LIMITATIONS,
        "findings": findings,
        "hybrid": {
            "cross_view_findings": cross_n,
            "hooks_checked": (scan.get("hooks") or {}).get("checked_n"),
            "drivers_count": (scan.get("drivers") or {}).get("count"),
            "etw_events": (scan.get("etw") or {}).get("events_n"),
            "correlation": corr,
            "published": scan.get("published"),
        },
        "psutil_pid_count": ((scan.get("cross_view") or {}).get("processes") or {}).get("counts", {}).get("psutil"),
        "wmi_pid_count": ((scan.get("cross_view") or {}).get("processes") or {}).get("counts", {}).get("wmi"),
        "drivers_enumerated": (scan.get("drivers") or {}).get("count"),
        "timestamp_utc": scan.get("timestamp_utc"),
        "method": "rootkit_hybrid_fase1",
        "note": (
            "Híbrido user-mode (cross-view, servicios, drivers, hooks, ETW). "
            "Rootkit kernel propio / SSDT = NO IMPLEMENTADO."
        ),
    }
