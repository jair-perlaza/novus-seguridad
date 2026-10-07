"""
T5 — Anomalías basadas en datos reales (inventario, NDR, endpoint, APE).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def detect_anomalies_from_cycle(
    *,
    inventory_changes: List[dict],
    dns_changes: List[dict],
    dhcp_result: Optional[dict],
    endpoint_changes: List[dict],
    new_devices: Optional[List[dict]] = None,
    ndr_alerts: Optional[List[dict]] = None,
) -> List[Dict[str, Any]]:
    """Une señales reales en anomalías tipadas (sin reglas inventadas de IOC ficticios)."""
    anomalies: List[Dict[str, Any]] = []

    for ch in inventory_changes or []:
        ctype = ch.get("change_type")
        if ctype in ("gateway_change", "dhcp_change", "ip_change", "mac_change"):
            anomalies.append(
                {
                    "anomaly_type": ctype,
                    "category": "network_infra",
                    "severity": "high" if ctype != "dns_change" else "medium",
                    "evidence": ch,
                    "detected_at_utc": _utc(),
                    "verified": True,
                }
            )

    for alert in (dhcp_result or {}).get("alerts") or []:
        anomalies.append(
            {
                "anomaly_type": "rogue_dhcp",
                "category": "network_infra",
                "severity": alert.get("severity") or "high",
                "evidence": alert,
                "detected_at_utc": _utc(),
                "verified": True,
            }
        )

    for ch in endpoint_changes or []:
        ctype = ch.get("change_type")
        if ctype in ("possible_dll_injection", "new_or_stopped_service", "listening_port_change", "scheduled_task_change"):
            anomalies.append(
                {
                    "anomaly_type": ctype,
                    "category": "endpoint",
                    "severity": ch.get("severity") or ("high" if "dll" in ctype else "medium"),
                    "evidence": ch,
                    "detected_at_utc": _utc(),
                    "verified": True,
                }
            )

    for d in new_devices or []:
        anomalies.append(
            {
                "anomaly_type": "new_device",
                "category": "network_device",
                "severity": "medium",
                "evidence": d,
                "detected_at_utc": _utc(),
                "verified": True,
            }
        )

    for a in ndr_alerts or []:
        level = str(a.get("level") or "").lower()
        if level in ("riesgo", "critico", "alerta", "high", "critical"):
            anomalies.append(
                {
                    "anomaly_type": a.get("code") or a.get("title") or "ndr_alert",
                    "category": "ndr",
                    "severity": "high" if level in ("critico", "critical", "riesgo") else "medium",
                    "evidence": a,
                    "detected_at_utc": _utc(),
                    "verified": True,
                }
            )

    # DNS flood as potential scan / C2 beaconing pattern (many new resolutions)
    for ch in dns_changes or []:
        if ch.get("change_type") == "dns_resolution_new" and len(ch.get("added") or []) >= 15:
            anomalies.append(
                {
                    "anomaly_type": "dns_resolution_burst",
                    "category": "dns",
                    "severity": "medium",
                    "evidence": {"count": len(ch.get("added") or []), "sample": (ch.get("added") or [])[:10]},
                    "detected_at_utc": _utc(),
                    "verified": True,
                }
            )

    return anomalies
