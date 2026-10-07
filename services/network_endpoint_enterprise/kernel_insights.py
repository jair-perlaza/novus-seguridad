"""
Kernel IA — contexto de lectura: tendencias, patrones, hipótesis. Nunca ejecuta acciones.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_kernel_net_endpoint_context() -> Dict[str, Any]:
    """Análisis/explicación para Kernel — solo lectura."""
    ctx: Dict[str, Any] = {
        "role": "analyze_only",
        "executes_actions": False,
        "collected_at_utc": _utc(),
        "hypotheses": [],
        "patterns": [],
        "trends": [],
    }
    try:
        from services.network_endpoint_enterprise.local_inventory import load_previous_inventory

        inv = load_previous_inventory() or {}
        ctx["host"] = {
            "hostname": inv.get("hostname"),
            "local_ip": inv.get("local_ip"),
            "gateway": inv.get("gateway"),
            "dns_servers": inv.get("dns_servers"),
            "dhcp_servers": (inv.get("dhcp") or {}).get("dhcp_servers"),
        }
    except Exception as exc:
        ctx["host_error"] = str(exc)[:120]

    try:
        from services.network_security_history_service import build_kernel_network_insights

        insights = build_kernel_network_insights()
        ctx["network_history_insights"] = insights
        if insights.get("insights"):
            ctx["trends"].extend(list(insights.get("insights") or [])[:8])
    except Exception as exc:
        ctx["history_error"] = str(exc)[:120]

    try:
        from services.network_endpoint_enterprise.orchestrator import get_enterprise_status

        st = get_enterprise_status()
        ctx["sensor_status"] = {
            "active": st.get("active"),
            "cycles": st.get("cycles"),
            "last_anomalies": st.get("last_anomalies_n"),
            "last_published": st.get("last_published_n"),
        }
        if st.get("last_anomaly_types"):
            ctx["patterns"].append({"type": "recent_anomalies", "values": st.get("last_anomaly_types")})
    except Exception:
        pass

    # Hypotheses (explicativas, no acciones)
    host = ctx.get("host") or {}
    if host.get("gateway") and host.get("dhcp_servers"):
        dhcp = host.get("dhcp_servers") or []
        if host.get("gateway") not in dhcp and dhcp:
            ctx["hypotheses"].append(
                {
                    "id": "dhcp_vs_gateway_mismatch",
                    "text": "El servidor DHCP observado no coincide con el gateway; posible infraestructura separada o DHCP inesperado.",
                    "confidence": "medium",
                }
            )
    if (ctx.get("sensor_status") or {}).get("last_anomalies"):
        ctx["hypotheses"].append(
            {
                "id": "recent_sensor_anomalies",
                "text": "El sensor Enterprise registró anomalías recientes; correlacionar con Swarm/NDR antes de contener.",
                "confidence": "low",
            }
        )

    ctx["capabilities"] = {
        "analyzes": True,
        "correlates": True,
        "explains": True,
        "proposes": True,
        "executes": False,
    }
    return ctx


def answer_kernel_query(question: str) -> str:
    ctx = build_kernel_net_endpoint_context()
    q = (question or "").lower()
    parts = [
        "Kernel (solo análisis — no ejecuta acciones).",
        f"Host IP={((ctx.get('host') or {}).get('local_ip'))} GW={((ctx.get('host') or {}).get('gateway'))}.",
    ]
    if "anomal" in q or "amenaz" in q:
        parts.append(f"Anomalías recientes: {(ctx.get('sensor_status') or {}).get('last_anomalies')}.")
    if ctx.get("hypotheses"):
        parts.append("Hipótesis: " + "; ".join(h.get("text", "")[:120] for h in ctx["hypotheses"][:2]))
    if "tendenc" in q or "patron" in q or "patrón" in q:
        parts.append(f"Tendencias historial: {len(ctx.get('trends') or [])} insights.")
    return " ".join(parts)
