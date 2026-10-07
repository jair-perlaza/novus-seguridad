#!/usr/bin/env python3
"""Analisis historico y respuestas basadas solo en datos reales."""
from __future__ import annotations
from collections import Counter
from typing import Any, Dict, List, Optional

from services.sdace.limitations import NA
from services.sdace.readers import sdl_search, parse_ts
from services.sdace.correlate import _val, temporal_correlate, ioc_correlate, cve_correlate, identity_correlate
from services.sdace.graph import build_attack_timeline, build_attack_graph


def historical_analysis(incident_id: Optional[str] = None) -> Dict[str, Any]:
    tl = build_attack_timeline(incident_id=incident_id)
    events = tl.get("events") or []
    idn = identity_correlate()
    ioc = ioc_correlate()
    cve = cve_correlate()
    temp = temporal_correlate()

    first = tl.get("first_event") if events else NA
    related = temp.get("pairs") or []

    assets = []
    if isinstance(idn.get("tops"), dict):
        assets = idn["tops"].get("activos") or []

    users = []
    if isinstance(idn.get("tops"), dict):
        users = idn["tops"].get("usuarios") or []

    campaigns = []
    for k, n in (ioc.get("top_iocs") or []):
        if str(k).startswith("campaign:"):
            campaigns.append((k, n))

    return {
        "ok": True,
        "invented": False,
        "que_ocurrio_primero": first if first != NA else NA,
        "que_origino_el_incidente": tl.get("origin_hypothesis") or NA,
        "eventos_relacionados": related[:20] if related else NA,
        "activos_participantes": assets[:10] if assets else NA,
        "usuarios_repetidos": [u for u, c in users if c > 1][:10] if users else NA,
        "campanas_reaparecen": campaigns[:10] if campaigns else NA,
        "ioc_reutilizados": ioc.get("reused") or NA,
        "cve_frecuencia": cve.get("top_cves") or NA,
        "timeline_count": tl.get("count", 0),
        "incident_id": tl.get("incident_id"),
    }


def analytics_summary() -> Dict[str, Any]:
    """Tops y estadisticas derivadas — conteos reales, no numeros estaticos."""
    idn = identity_correlate()
    ioc = ioc_correlate()
    cve = cve_correlate()
    mitre = __import__("services.sdace.correlate", fromlist=["mitre_correlate"]).mitre_correlate()
    incs = sdl_search(record_type="incident", limit=200)
    records = incs.get("records") or []
    sev = Counter()
    for r in records:
        s = _val(r, "severity")
        if s:
            sev[s] += 1

    tops_activos = (idn.get("tops") or {}).get("activos") or []
    tops_users = (idn.get("tops") or {}).get("usuarios") or []

    # top incidents by related record count
    inc_counts = Counter()
    allr = sdl_search(limit=500).get("records") or []
    for r in allr:
        iid = _val(r, "incident_id")
        if iid:
            inc_counts[iid] += 1

    return {
        "ok": True,
        "invented": False,
        "top_ioc": ioc.get("top_iocs") or NA,
        "top_cve": cve.get("top_cves") or NA,
        "top_activos": tops_activos or NA,
        "top_usuarios": tops_users or NA,
        "top_incidentes": inc_counts.most_common(10) or NA,
        "top_campanas": [x for x in (ioc.get("top_iocs") or []) if str(x[0]).startswith("campaign:")] or NA,
        "top_mitre": (mitre.get("techniques") or mitre.get("tactics") or NA),
        "incidentes_por_severidad": dict(sev) if sev else NA,
        "sdl_total_sampled": len(allr),
    }
