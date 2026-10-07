"""
Colectores de evidencia real para Knowledge Packs.
Solo leen servicios/APIs/DB existentes. Si falla o no hay dato → gap explícito.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


def _safe_call(label: str, fn) -> Tuple[bool, Optional[Any], Optional[str]]:
    try:
        data = fn()
        if data is None:
            return False, None, f"{label}: sin datos disponibles"
        return True, data, None
    except Exception as exc:
        return False, None, f"{label}: {exc}"


def collect_security_summary(_query: str = "", _ctx: Optional[dict] = None):
    facts: List[Dict[str, Any]] = []
    gaps: List[str] = []
    sources: List[str] = []

    try:
        from services.platform_metrics_service import get_unified_security_payload

        data = get_unified_security_payload()
        if data:
            sources.append("platform_metrics_service.get_unified_security_payload")
            facts.append({"type": "security_summary", "data": data})
        else:
            gaps.append("get_unified_security_payload devolvió vacío")
    except Exception as exc:
        gaps.append(f"platform_metrics_service: {exc}")
        try:
            from services.platform_metrics_service import get_platform_counters

            data = get_platform_counters()
            if data:
                sources.append("platform_metrics_service.get_platform_counters")
                facts.append({"type": "platform_counters", "data": data})
        except Exception as exc2:
            gaps.append(f"get_platform_counters: {exc2}")

    if not facts:
        gaps.append("No hay resumen de seguridad canónico disponible en este momento")

    return bool(facts), facts, gaps, sources


def collect_vulnerabilities(_query: str = "", _ctx: Optional[dict] = None):
    facts, gaps, sources = [], [], []
    try:
        from services.ai_capability_registry import capability_registry

        data, module = capability_registry._run_capability(
            "security.vulnerabilities", None, True
        )
        sources.append("capability:security.vulnerabilities")
        if data:
            facts.append({"type": "vulnerabilities", "module": module, "data": data})
        else:
            gaps.append("Motor de vulnerabilidades respondió sin hallazgos o sin datos")
    except Exception as exc:
        gaps.append(f"security.vulnerabilities: {exc}")
    return bool(facts), facts, gaps, sources


def collect_threats(_query: str = "", _ctx: Optional[dict] = None):
    facts, gaps, sources = [], [], []
    try:
        from services.ai_capability_registry import capability_registry

        data, module = capability_registry._run_capability("security.threats", None, True)
        sources.append("capability:security.threats")
        if data:
            facts.append({"type": "threats", "module": module, "data": data})
        else:
            gaps.append("Motor de amenazas sin datos verificables en esta consulta")
    except Exception as exc:
        gaps.append(f"security.threats: {exc}")
    return bool(facts), facts, gaps, sources


def collect_network(_query: str = "", _ctx: Optional[dict] = None):
    facts, gaps, sources = [], [], []
    for cap in ("network.scanner", "network.events", "network.ndr"):
        try:
            from services.ai_capability_registry import capability_registry

            if cap not in capability_registry.CAPABILITY_CATALOG and cap != "network.ndr":
                # network.ndr puede no estar en catalog — intentar servicio
                pass
            if cap == "network.ndr":
                try:
                    from services.network_ndr_service import build_ndr_payload

                    data = build_ndr_payload(force_refresh=False)
                    if data:
                        sources.append("network_ndr_service.build_ndr_payload")
                        # Truncate heavy payload
                        facts.append(
                            {
                                "type": "ndr",
                                "data": {
                                    "keys": list(data.keys()) if isinstance(data, dict) else [],
                                    "meta": (data.get("meta") if isinstance(data, dict) else None),
                                    "device_count": len(data.get("devices") or data.get("nodes") or [])
                                    if isinstance(data, dict)
                                    else None,
                                    "truncated": True,
                                },
                            }
                        )
                    else:
                        gaps.append("NDR: payload vacío")
                except Exception as exc:
                    gaps.append(f"network.ndr: {exc}")
                continue
            data, module = capability_registry._run_capability(cap, None, True)
            sources.append(f"capability:{cap}")
            if data:
                facts.append({"type": cap, "module": module, "data": data})
            else:
                gaps.append(f"{cap}: sin datos")
        except Exception as exc:
            gaps.append(f"{cap}: {exc}")
    return bool(facts), facts, gaps, sources


def collect_compliance(_query: str = "", _ctx: Optional[dict] = None):
    facts, gaps, sources = [], [], []
    try:
        from services.compliance_catalog import FRAMEWORK_MAP

        sources.append("compliance_catalog.FRAMEWORK_MAP")
        facts.append(
            {
                "type": "compliance_frameworks",
                "count": len(FRAMEWORK_MAP),
                "frameworks": [
                    {"id": f.get("id"), "name": f.get("label") or f.get("name")}
                    for f in FRAMEWORK_MAP
                ],
            }
        )
    except Exception as exc:
        gaps.append(f"compliance_catalog: {exc}")
    try:
        from services.compliance_center_service import build_profile

        profile = build_profile(sector_id="general", country="CO")
        sources.append("compliance_center_service.build_profile")
        facts.append({"type": "compliance_profile", "data": profile})
    except Exception as exc:
        gaps.append(f"compliance_center_service: {exc}")
    return bool(facts), facts, gaps, sources


def collect_forensic(_query: str = "", _ctx: Optional[dict] = None):
    facts, gaps, sources = [], [], []
    try:
        from services.defense_evidence_registry import list_recent_events

        events = list_recent_events(limit=20)
        sources.append("defense_evidence_registry")
        facts.append({"type": "defense_events", "count": len(events or []), "events": events})
    except Exception as exc:
        gaps.append(f"defense_evidence_registry: {exc}")
    try:
        from services.forensic_pcap_capture_service import list_captures

        caps = list_captures(10)
        sources.append("forensic_pcap_capture_service")
        facts.append({"type": "pcap_captures", "count": len(caps or []), "captures": caps})
    except Exception as exc:
        gaps.append(f"forensic_pcap: {exc}")
    return bool(facts), facts, gaps, sources


def collect_endpoint(_query: str = "", _ctx: Optional[dict] = None):
    facts, gaps, sources = [], [], []
    for cap in ("endpoints.live", "process.scanner", "system.metrics", "advanced_detector.processes"):
        try:
            from services.ai_capability_registry import capability_registry

            data, module = capability_registry._run_capability(cap, None, True)
            sources.append(f"capability:{cap}")
            if data:
                facts.append({"type": cap, "module": module, "data": data})
            else:
                gaps.append(f"{cap}: sin datos")
        except Exception as exc:
            gaps.append(f"{cap}: {exc}")
    return bool(facts), facts, gaps, sources


def collect_mail_web(_query: str = "", _ctx: Optional[dict] = None):
    facts, gaps, sources = [], [], []
    try:
        from services.mail_shield_service import get_stats

        data = get_stats()
        sources.append("mail_shield_service.get_stats")
        facts.append({"type": "mail_shield", "data": data})
    except Exception as exc:
        gaps.append(f"mail_shield: {exc}")
    try:
        from services.web_shield_service import get_stats as web_stats

        data = web_stats()
        sources.append("web_shield_service.get_stats")
        facts.append({"type": "web_shield", "data": data})
    except Exception as exc:
        gaps.append(f"web_shield: {exc}")
    return bool(facts), facts, gaps, sources


def collect_reports(_query: str = "", _ctx: Optional[dict] = None):
    facts, gaps, sources = [], [], []
    try:
        from services.ai_capability_registry import capability_registry

        data, module = capability_registry._run_capability("reports.manager", None, True)
        sources.append("capability:reports.manager")
        if data:
            facts.append({"type": "reports", "module": module, "data": data})
        else:
            gaps.append("Gestor de reportes sin datos en esta consulta")
    except Exception as exc:
        gaps.append(f"reports.manager: {exc}")
    return bool(facts), facts, gaps, sources


def collect_kernel_memory(_query: str = "", _ctx: Optional[dict] = None):
    facts, gaps, sources = [], [], []
    try:
        from services.kernel_memory import kernel_memory

        # Solo metadatos agregados — sin inventar contenido
        path_hint = getattr(kernel_memory, "MEMORY_DIR", "data/kernel_memory")
        sources.append("kernel_memory")
        facts.append(
            {
                "type": "kernel_memory_meta",
                "storage": str(path_hint),
                "note": "Aprendizaje local verificable por usuario; sin modelos externos",
            }
        )
    except Exception as exc:
        gaps.append(f"kernel_memory: {exc}")
    return bool(facts), facts, gaps, sources


def collect_none(_query: str = "", _ctx: Optional[dict] = None):
    """Pack teórico sin fuente NOVUS local — transparencia total."""
    return (
        False,
        [],
        [
            "Este Knowledge Pack está registrado para crecimiento modular, "
            "pero NOVUS no tiene aún un corpus local verificable para este dominio. "
            "No se inventan definiciones ni datos."
        ],
        [],
    )


COLLECTORS = {
    "security_summary": collect_security_summary,
    "vulnerabilities": collect_vulnerabilities,
    "threats": collect_threats,
    "network": collect_network,
    "compliance": collect_compliance,
    "forensic": collect_forensic,
    "endpoint": collect_endpoint,
    "mail_web": collect_mail_web,
    "reports": collect_reports,
    "kernel_memory": collect_kernel_memory,
    "none": collect_none,
}
