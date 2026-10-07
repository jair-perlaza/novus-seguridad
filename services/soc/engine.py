#!/usr/bin/env python3
"""
SOC Enterprise Engine — convergencia de motores reales.
NO inventa datos. Vistas: overview, tactical, executive, analyst, forensic, health, swarm.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.soc.limitations import NA
from services.soc.collectors import collect_all
from services.soc.store import save_derived_snapshot
from services.soc.hunting import hunt
from services.soc.kernel_console import ask_kernel


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _d(block: Dict[str, Any], *keys, default=NA):
    if not block or not block.get("available"):
        return default
    data = block.get("data")
    if data is None:
        return default
    cur = data
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur if cur is not None else default


def _engine_status_row(block: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source": block.get("source"),
        "available": bool(block.get("available")),
        "status": "ok" if block.get("available") else NA,
    }


def get_overview(*, tenant_id: str) -> Dict[str, Any]:
    from services.performance_cache import get_or_compute
    from core.config import Config

    tid = str(tenant_id or "").strip()
    return get_or_compute(
        f"soc_overview:{tid}",
        Config.SOC_OVERVIEW_CACHE_TTL,
        lambda: _get_overview_uncached(tenant_id=tid),
    )


def _get_overview_uncached(*, tenant_id: str) -> Dict[str, Any]:
    engines = collect_all(tenant_id=tenant_id)
    imcm = engines["imcm"]
    asm = engines["asm"]
    viem = engines["viem"]

    imcm_stats = _d(imcm, "stats", default={})
    imcm_dash = _d(imcm, "dashboard", default={})
    if not isinstance(imcm_stats, dict):
        imcm_stats = {}
    if not isinstance(imcm_dash, dict):
        imcm_dash = {}

    by_sev = imcm_dash.get("by_severity") if isinstance(imcm_dash.get("by_severity"), dict) else {}
    by_state = imcm_dash.get("by_state") if isinstance(imcm_dash.get("by_state"), dict) else {}

    critical = by_sev.get("CRITICO", 0) or by_sev.get("CRITICAL", 0) or 0
    active = (by_state.get("nuevo", 0) or 0) + (by_state.get("investigando", 0) or 0) + (by_state.get("confirmado", 0) or 0)
    closed = by_state.get("cerrado", 0) if by_state else (imcm_stats.get("cerrado") if isinstance(imcm_stats, dict) else NA)

    # Risk: only from real exposure/severity — no invented formula that fabricates numbers
    risk_global = NA
    asm_exp = _d(asm, "dashboard", "exposure", default=None)
    if isinstance(asm_exp, dict) and "exposure_score" in asm_exp:
        risk_global = asm_exp.get("exposure_score")
    elif critical and isinstance(critical, int) and critical > 0:
        risk_global = f"CRITICO ({critical} incidentes criticos en IMCM)"
    elif active and isinstance(active, int) and active > 0:
        risk_global = f"ALTO ({active} incidentes activos en IMCM)"
    elif imcm.get("available") and (imcm_stats.get("total") or 0) == 0:
        risk_global = "SIN INCIDENTES REGISTRADOS"

    asm_stats = _d(asm, "stats", default={})
    assets_protected = asm_stats.get("total_assets") if isinstance(asm_stats, dict) else NA
    if assets_protected is NA or assets_protected is None:
        assets_protected = asm_stats.get("software_count") if isinstance(asm_stats, dict) else NA

    viem_stats = _d(viem, "stats", default={})
    compromised = NA
    if isinstance(viem_stats, dict):
        compromised = viem_stats.get("critical") or viem_stats.get("total")
        if compromised is None:
            compromised = NA

    overview = {
        "generated_at_utc": _utc(),
        "tenant_id": tenant_id,
        "source": "services.soc.engine.get_overview",
        "source_type": "aggregated_collectors",
        "observed_at": _utc(),
        "invented": False,
        "risk_global": risk_global,
        "incidentes_activos": active if imcm.get("available") else NA,
        "incidentes_criticos": critical if imcm.get("available") else NA,
        "casos_abiertos": active if imcm.get("available") else NA,
        "casos_cerrados": closed if imcm.get("available") else NA,
        "activos_protegidos": assets_protected if asm.get("available") else NA,
        "activos_comprometidos": compromised if viem.get("available") else NA,
        "engines": {
            "swarm_defense": _engine_status_row(engines["swarm_defense"]),
            "swarm_mesh": _engine_status_row(engines["swarm_mesh"]),
            "kernel_ia": _engine_status_row(engines["kernel_ia"]),
            "health_engine": _engine_status_row(engines["health_engine"]),
            "cryptovault": _engine_status_row(engines["cryptovault"]),
            "sope": _engine_status_row(engines["sope"]),
            "imcm": _engine_status_row(engines["imcm"]),
            "threat_intelligence": _engine_status_row(engines["tie"]),
            "viem": _engine_status_row(engines["viem"]),
            "asm": _engine_status_row(engines["asm"]),
            "zero_day_detection": _engine_status_row(engines["zero_day_detection"]),
            "compliance": _engine_status_row(engines["compliance"]),
            "centro_defensa": _engine_status_row(engines["centro_defensa"]),
            "forense": _engine_status_row(engines["forense"]),
        },
    }
    # Derived cache only
    save_derived_snapshot(
        {
            "risk_global": overview["risk_global"],
            "incidentes_activos": overview["incidentes_activos"],
            "incidentes_criticos": overview["incidentes_criticos"],
            "engines_available": {k: v.get("available") for k, v in overview["engines"].items()},
        },
        tenant_id=tenant_id,
    )
    return overview


def get_tactical_map(*, tenant_id: str) -> Dict[str, Any]:
    """Mapa tactico desde ASM + Swarm + Red. Sin relaciones inventadas."""
    engines = collect_all(tenant_id=tenant_id)
    asm = engines["asm"]
    swarm = engines["swarm_defense"]
    mesh = engines["swarm_mesh"]

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    if asm.get("available"):
        dash = asm.get("data", {}).get("dashboard") or {}
        inv_host = dash.get("local_host") or dash.get("host") or {}
        if inv_host:
            nodes.append({
                "id": inv_host.get("asset_id") or inv_host.get("hostname") or "local",
                "type": inv_host.get("classification") or "host",
                "hostname": inv_host.get("hostname", NA),
                "ip": inv_host.get("ip", NA),
                "mac": inv_host.get("mac", NA),
                "source": "asm",
            })
        # Try inventory for network nodes + dependencies
        try:
            from services.asm.store import load_inventory
            inv = load_inventory() or {}
            for n in (inv.get("network_nodes") or []):
                nodes.append({
                    "id": n.get("ip") or n.get("mac") or str(n)[:40],
                    "type": n.get("classification") or "network",
                    "ip": n.get("ip", NA),
                    "mac": n.get("mac", NA),
                    "vendor": n.get("vendor", NA),
                    "source": "asm",
                })
            deps = inv.get("dependencies") or []
            local_id = nodes[0]["id"] if nodes else None
            for d in deps:
                if not isinstance(d, dict):
                    continue
                target = d.get("target") or d.get("ip") or d.get("name")
                if local_id and target:
                    edges.append({
                        "from": local_id,
                        "to": target,
                        "relation": d.get("type") or d.get("relation") or "dependency",
                        "source": "asm",
                    })
        except Exception:
            pass
    else:
        return {
            "available": False,
            "message": NA,
            "nodes": [],
            "edges": [],
            "swarm": _engine_status_row(swarm),
            "mesh": _engine_status_row(mesh),
            "invented": False,
            "generated_at_utc": _utc(),
        }

    return {
        "available": True,
        "nodes": nodes,
        "edges": edges,
        "note": "Solo nodos y dependencias observadas por ASM. Sin relaciones inventadas.",
        "swarm": _engine_status_row(swarm),
        "mesh": _engine_status_row(mesh),
        "invented": False,
        "generated_at_utc": _utc(),
    }


def get_executive_kpis(*, tenant_id: str) -> Dict[str, Any]:
    """KPIs reales para CEO/CISO/CSO/CTO/COO/Consejo."""
    engines = collect_all(tenant_id=tenant_id)
    imcm = engines["imcm"]
    viem = engines["viem"]
    health = engines["health_engine"]
    compliance = engines["compliance"]
    asm = engines["asm"]

    imcm_stats = _d(imcm, "stats", default={})
    imcm_dash = _d(imcm, "dashboard", default={})
    if not isinstance(imcm_stats, dict):
        imcm_stats = {}
    if not isinstance(imcm_dash, dict):
        imcm_dash = {}

    by_sev = imcm_dash.get("by_severity") if isinstance(imcm_dash.get("by_severity"), dict) else {}
    by_state = imcm_dash.get("by_state") if isinstance(imcm_dash.get("by_state"), dict) else {}

    # MTTD / MTTR: only if timeline timestamps exist — else NA
    mttd = NA
    mttr = NA
    try:
        from services.imcm.store import load_timeline, load_history

        timeline = load_timeline(tenant_id=tenant_id, limit=200)
        history = load_history(tenant_id=tenant_id, limit=200)
        # Cannot invent times; only report counts of real events
        if timeline:
            mttd = f"eventos_timeline={len(timeline)} (calculo MTTD requiere pares detect/respuesta — parcial)"
        if history:
            closed_events = [h for h in history if h.get("new_state") == "cerrado" or h.get("action") == "state_change"]
            mttr = f"cambios_estado={len(closed_events)}" if closed_events else NA
    except Exception:
        pass

    overview = get_overview(tenant_id=tenant_id)
    viem_stats = _d(viem, "stats", default={})
    health_data = health.get("data") if health.get("available") else None

    weekly = NA
    monthly = NA
    # Trends only if we have dated incidents
    try:
        from services.imcm.store import load_incidents

        incs = load_incidents(tenant_id=tenant_id, limit=500)
        if incs:
            weekly = {"incidentes_registrados_en_store": len(incs), "note": "conteo real en store; sin proyeccion inventada"}
            monthly = weekly
        else:
            weekly = NA
            monthly = NA
    except Exception:
        pass

    return {
        "audience": ["CEO", "CISO", "CSO", "CTO", "COO", "Consejo Directivo"],
        "generated_at_utc": _utc(),
        "invented": False,
        "kpis": {
            "riesgo_global": overview.get("risk_global", NA),
            "tiempo_medio_deteccion": mttd,
            "tiempo_medio_respuesta": mttr,
            "incidentes_abiertos": overview.get("incidentes_activos", NA),
            "incidentes_cerrados": overview.get("casos_cerrados", NA),
            "vulnerabilidades_criticas": (
                viem_stats.get("critical") if isinstance(viem_stats, dict) and viem_stats.get("critical") is not None else NA
            ),
            "estado_cumplimiento": (
                _d(compliance, "latest", default=NA) if compliance.get("available") else NA
            ),
            "salud_general": (
                (health_data.get("status") if isinstance(health_data, dict) else health_data)
                if health.get("available") else NA
            ),
            "tendencia_semanal": weekly,
            "tendencia_mensual": monthly,
            "by_severity": by_sev if by_sev else NA,
            "by_state": by_state if by_state else NA,
            "asm_available": asm.get("available"),
        },
    }


def get_analyst_view(*, tenant_id: str) -> Dict[str, Any]:
    """Cola sincronizada con IMCM + motores."""
    engines = collect_all(tenant_id=tenant_id)
    imcm = engines["imcm"]
    queue = []
    if imcm.get("available"):
        dash = imcm.get("data", {}).get("dashboard") or {}
        queue = dash.get("recent_incidents") or []
        try:
            from services.imcm import search_incidents
            queue = search_incidents(limit=50, tenant_id=tenant_id)
        except Exception:
            pass

    return {
        "generated_at_utc": _utc(),
        "invented": False,
        "queue": queue if queue else [],
        "queue_message": None if queue else NA,
        "engines": {
            "imcm": _engine_status_row(engines["imcm"]),
            "sope": _engine_status_row(engines["sope"]),
            "viem": _engine_status_row(engines["viem"]),
            "asm": _engine_status_row(engines["asm"]),
            "tie": _engine_status_row(engines["tie"]),
            "kernel_ia": _engine_status_row(engines["kernel_ia"]),
            "forense": _engine_status_row(engines["forense"]),
        },
        "playbooks": _d(engines["sope"], "dashboard", default=NA),
        "timeline": (_d(engines["imcm"], "dashboard", "timeline", default=[]) if imcm.get("available") else NA),
    }


def get_forensic_view(incident_id: Optional[str] = None, *, tenant_id: str) -> Dict[str, Any]:
    engines = collect_all(tenant_id=tenant_id)
    forense = engines["forense"]
    payload: Dict[str, Any] = {
        "generated_at_utc": _utc(),
        "invented": False,
        "system": forense.get("data") if forense.get("available") else NA,
        "incident_forensic": NA,
    }
    if incident_id:
        try:
            from services.imcm import get_incident
            inc = get_incident(incident_id, tenant_id=tenant_id)
            if inc and inc.get("forensic"):
                payload["incident_forensic"] = inc.get("forensic")
                payload["timeline"] = inc.get("timeline") or inc.get("full_timeline") or NA
                payload["incident_id"] = incident_id
            else:
                payload["incident_forensic"] = NA
                payload["message"] = f"Incidente {incident_id} sin cadena forense o no encontrado"
        except Exception as exc:
            payload["error"] = str(exc)[:200]
            payload["incident_forensic"] = NA
    return payload


def get_health_view(*, tenant_id: str) -> Dict[str, Any]:
    block = collect_all(tenant_id=tenant_id)["health_engine"]
    if not block.get("available"):
        return {"available": False, "message": NA, "invented": False, "generated_at_utc": _utc()}
    data = block.get("data") or {}
    return {
        "available": True,
        "status": data.get("status"),
        "dashboard": data.get("dashboard"),
        "invented": False,
        "generated_at_utc": _utc(),
        "note": "Telemetria exclusiva de Health Engine",
    }


def get_swarm_mesh_view(*, tenant_id: str) -> Dict[str, Any]:
    engines = collect_all(tenant_id=tenant_id)
    swarm = engines["swarm_defense"]
    mesh = engines["swarm_mesh"]
    nodes = []
    if mesh.get("available"):
        data = mesh.get("data") or {}
        # Only real fields from mesh_status
        if isinstance(data, dict):
            peers = data.get("peers") or data.get("nodes") or data.get("trust") or []
            if isinstance(peers, list):
                nodes = peers
            elif isinstance(peers, dict):
                nodes = [{"id": k, **(v if isinstance(v, dict) else {"value": v})} for k, v in peers.items()]
    return {
        "generated_at_utc": _utc(),
        "invented": False,
        "swarm_defense": swarm.get("data") if swarm.get("available") else NA,
        "swarm_mesh": mesh.get("data") if mesh.get("available") else NA,
        "nodes": nodes if nodes else [],
        "nodes_message": None if nodes else NA,
        "note": "Solo nodos reales reportados por Swarm Mesh",
    }


def stats(*, tenant_id: str) -> Dict[str, Any]:
    ov = get_overview(tenant_id=tenant_id)
    return {
        "engines_ok": sum(1 for e in ov["engines"].values() if e.get("available")),
        "engines_total": len(ov["engines"]),
        "incidentes_activos": ov.get("incidentes_activos"),
        "incidentes_criticos": ov.get("incidentes_criticos"),
        "invented": False,
    }
