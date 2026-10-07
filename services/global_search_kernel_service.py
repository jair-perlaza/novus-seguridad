"""
Kernel IA del buscador global: intención, corrección, sinónimos, ranking y sugerencias.
Solo datos reales indexados por global_search_index.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from services.global_search_learning_store import (
    click_boost,
    frequent_queries,
    query_boost,
    record_search,
    record_timing_ms,
    user_sector,
)
from services.global_search_index import global_search as _index_search, get_index_stats
from utils.logger import logger

# Corrección ortográfica determinística (telemetría local, sin inventar resultados)
_SPELL_FIX = {
    "vulnerabilida": "vulnerabilidad",
    "vulnerabilidades": "vulnerabilidad",
    "vulnrrabilidad": "vulnerabilidad",
    "amenas": "amenaza",
    "amenazaas": "amenaza",
    "repote": "reporte",
    "reportes": "reporte",
    "informe": "reporte",
    "incidente": "incidente",
    "incidentes": "incidente",
    "proceso": "proceso",
    "procesos": "proceso",
    "dispositivo": "dispositivo",
    "dispositivos": "dispositivo",
    "configuracion": "configuración",
    "automatizacion": "automación",
    "inteligencia": "inteligencia",
    "playbook": "playbook",
    "playbooks": "playbook",
    "escaneo": "escaneo",
    "escaneos": "escaneo",
    "logistica": "logística",
    "fintech": "fintech",
    "movil": "móvil",
}

_SYNONYMS: Dict[str, List[str]] = {
    "amenaza": ["threat", "xdr", "ataque", "malware", "biohazard"],
    "vulnerabilidad": ["vuln", "cve", "bug", "hallazgo", "puerto"],
    "reporte": ["informe", "report", "pdf", "sec", "rpt"],
    "incidente": ["alerta", "inc", "mitigación"],
    "dispositivo": ["nodo", "host", "endpoint", "equipo", "ip"],
    "red": ["network", "topology", "arp", "radar"],
    "log": ["siem", "auditoría", "evento"],
    "playbook": ["automatización", "regla", "automation"],
    "defensa": ["manual", "centro de defensa", "escaneo", "mdr"],
    "ioc": ["indicador", "inteligencia", "caso", "threat intel"],
    "usuario": ["user", "email", "acceso"],
    "escaneo": ["scan", "deep scan", "host_scan"],
}

_INTENT_PATTERNS: List[Tuple[str, str, List[str]]] = [
    (r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "buscar_ip", ["Dispositivos en Network", "Incidentes relacionados"]),
    (r"\b(cve-|cve)\d", "buscar_cve", ["Vulnerabilidades"]),
    (r"(vuln|vulnerab|puerto|port)", "buscar_vulnerabilidades", ["Módulo Vulnerabilidades"]),
    (r"\b(amenaza|threat|xdr|malware)\b", "buscar_amenazas", ["XDR / Amenazas"]),
    (r"\b(reporte|informe|rpt-|sec-)\b", "buscar_reportes", ["Centro de Reportes"]),
    (r"\b(incidente|inc-|alerta)\b", "buscar_incidentes", ["Incidentes"]),
    (r"\b(playbook|automat)\b", "buscar_playbooks", ["Automatización"]),
    (r"\b(defensa|escaneo|scan|mdr)\b", "buscar_defensa", ["Centro de Defensa"]),
    (r"\b(log|siem|auditor)\b", "buscar_logs", ["SIEM"]),
    (r"\b(ioc|intel|caso)\b", "buscar_ioc", ["Centro de Inteligencia"]),
    (r"\b(red|network|topolog)\b", "buscar_red", ["Network / Topology"]),
]


def _correct_spelling(query: str) -> str:
    q = query.strip()
    low = q.lower()
    if low in _SPELL_FIX:
        return _SPELL_FIX[low]
    tokens = low.split()
    fixed = []
    for t in tokens:
        fixed.append(_SPELL_FIX.get(t, t))
    return " ".join(fixed) if fixed != tokens else q


def _expand_synonyms(query: str) -> List[str]:
    low = query.lower().strip()
    terms: Set[str] = {low}
    for key, syns in _SYNONYMS.items():
        if key in low or any(s in low for s in syns):
            terms.add(key)
            terms.update(syns)
    for token in low.split():
        if token in _SYNONYMS:
            terms.update(_SYNONYMS[token])
    return list(terms)[:12]


def interpret_query(query: str, email: Optional[str] = None) -> Dict[str, Any]:
    corrected = _correct_spelling(query)
    expanded = _expand_synonyms(corrected)
    intent = "busqueda_general"
    hints: List[str] = []
    for pattern, name, hint_list in _INTENT_PATTERNS:
        if re.search(pattern, corrected, re.I):
            intent = name
            hints = hint_list
            break

    sector = user_sector(email)
    related: List[str] = []
    for fq in frequent_queries(email, limit=5):
        if fq != corrected.lower() and fq not in related:
            related.append(fq)
    for term in expanded[:3]:
        if term not in related and term != corrected.lower():
            related.append(term)

    return {
        "intent": intent,
        "original_query": query,
        "corrected_query": corrected,
        "expanded_terms": expanded,
        "interpretation": _intent_label(intent),
        "related_queries": related[:6],
        "sector_context": sector or None,
        "hints": hints[:4],
    }


def _intent_label(intent: str) -> str:
    labels = {
        "buscar_ip": "Localizar dispositivo o actividad asociada a una dirección IP",
        "buscar_cve": "Consultar vulnerabilidades correlacionadas",
        "buscar_vulnerabilidades": "Hallazgos de exposición y puertos",
        "buscar_amenazas": "Amenazas y procesos en XDR",
        "buscar_reportes": "Informes de seguridad archivados",
        "buscar_incidentes": "Incidentes y alertas operativas",
        "buscar_playbooks": "Reglas y automatización",
        "buscar_defensa": "Mecanismos del Centro de Defensa",
        "buscar_logs": "Eventos SIEM y auditoría",
        "buscar_ioc": "Casos e indicadores de inteligencia",
        "buscar_red": "Topología y nodos de red",
        "busqueda_general": "Exploración en catálogo y telemetría NOVUS",
    }
    return labels.get(intent, labels["busqueda_general"])


def _exactness_score(query: str, item: dict) -> int:
    q = query.lower().strip()
    name = (item.get("name") or "").lower()
    iid = (item.get("id") or "").lower()
    if not q:
        return 0
    if name == q or iid == q:
        return 1000
    if name.startswith(q) or iid.startswith(q):
        return 900
    if q in name or q in iid:
        return 800
    return 0


def _semantic_score(item: dict) -> int:
    return int(item.get("score") or item.get("fuzzy_score") or 0)


def rank_results(
    original_query: str,
    corrected_query: str,
    items: List[dict],
    email: Optional[str] = None,
    kernel: Optional[dict] = None,
) -> List[dict]:
    kernel = kernel or {}
    intent = kernel.get("intent") or ""
    intent_boost_types = {
        "buscar_vulnerabilidades": {"Vulnerabilidad", "Puerto"},
        "buscar_amenazas": {"Incidente", "Amenaza", "Shield"},
        "buscar_reportes": {"Reporte"},
        "buscar_incidentes": {"Incidente", "Alerta"},
        "buscar_playbooks": {"Playbook", "Regla"},
        "buscar_defensa": {"Mecanismo de defensa", "Escaneo"},
        "buscar_logs": {"Log"},
        "buscar_ioc": {"IOC", "Caso de inteligencia"},
        "buscar_red": {"Dispositivo", "Módulo"},
        "buscar_ip": {"Dispositivo", "Incidente", "Vulnerabilidad"},
    }.get(intent, set())

    ranked = []
    for item in items:
        exact = _exactness_score(corrected_query, item)
        if exact == 0:
            exact = _exactness_score(original_query, item)
        semantic = _semantic_score(item)
        freq = click_boost(email, item.get("id", "")) * 15 + query_boost(email, corrected_query) * 2
        kernel_b = 40 if item.get("type") in intent_boost_types else 0
        if kernel.get("sector_context") and "Sector" in (item.get("type") or ""):
            kernel_b += 10
        total = exact * 10 + semantic * 8 + freq + kernel_b
        out = dict(item)
        out["rank"] = {
            "exact": exact,
            "semantic": semantic,
            "frequency": freq,
            "kernel": kernel_b,
            "total": total,
        }
        ranked.append(out)

    ranked.sort(key=lambda x: (-x["rank"]["total"], x.get("name") or ""))
    return ranked


def _merge_candidates(queries: List[str], limit: int, *, tenant_id: str) -> List[dict]:
    seen = set()
    merged: List[dict] = []
    for q in queries:
        if not q:
            continue
        for item in _index_search(q, limit=limit, tenant_id=tenant_id):
            key = item.get("id") or item.get("url")
            if not key or key in seen:
                continue
            seen.add(key)
            entry = dict(item)
            if "score" not in entry:
                entry["score"] = 70
            merged.append(entry)
    return merged


def run_global_search(
    query: str,
    *,
    limit: int = 25,
    user_email: Optional[str] = None,
    sector: Optional[str] = None,
    tenant_id: str,
) -> Dict[str, Any]:
    start = time.perf_counter()
    raw_q = (query or "").strip()
    tid = str(tenant_id or "").strip()
    if not tid:
        return {
            "status": "error",
            "message": "tenant_not_configured",
            "query": raw_q,
            "results": [],
            "count": 0,
            "kernel": {},
            "timing_ms": 0,
        }
    if not raw_q:
        return {
            "status": "success",
            "query": "",
            "results": [],
            "count": 0,
            "kernel": {},
            "timing_ms": 0,
        }

    kernel = interpret_query(raw_q, user_email)
    corrected = kernel["corrected_query"]
    search_terms = [corrected, raw_q] + [t for t in kernel["expanded_terms"] if t not in (corrected, raw_q)]
    candidates = _merge_candidates(search_terms, limit=max(limit, 40), tenant_id=tid)
    ranked = rank_results(raw_q, corrected, candidates, user_email, kernel)

    results = []
    for item in ranked[:limit]:
        clean = {k: v for k, v in item.items() if k not in ("search_text",)}
        results.append(clean)

    from services.v1_runtime_surface import filter_lab_search_results

    results = filter_lab_search_results(results)
    if not results and raw_q:
        return {
            "status": "success",
            "query": raw_q,
            "corrected_query": corrected if corrected != raw_q else None,
            "kernel": {
                "intent": kernel.get("intent"),
                "interpretation": kernel.get("interpretation") or "No se encontraron resultados.",
                "expanded_terms": kernel.get("expanded_terms", [])[:8],
                "related_queries": kernel.get("related_queries", []),
                "sector_context": kernel.get("sector_context"),
            },
            "suggestions": [],
            "results": [],
            "count": 0,
            "message": "No se encontraron resultados.",
            "timing_ms": round((time.perf_counter() - start) * 1000, 2),
            "index_stats": get_index_stats(tenant_id=tid),
        }

    record_search(user_email, raw_q, sector=sector)
    elapsed = (time.perf_counter() - start) * 1000
    record_timing_ms(elapsed)

    suggestions = []
    for rq in kernel.get("related_queries") or []:
        suggestions.append({
            "id": f"suggest-{rq}",
            "name": rq,
            "type": "Sugerencia",
            "url": f"/api/search?q={rq}",
            "description": kernel.get("interpretation", ""),
            "icon": "fa-lightbulb",
            "location": "Kernel IA",
        })

    return {
        "status": "success",
        "query": raw_q,
        "corrected_query": corrected if corrected != raw_q else None,
        "kernel": {
            "intent": kernel.get("intent"),
            "interpretation": kernel.get("interpretation"),
            "expanded_terms": kernel.get("expanded_terms", [])[:8],
            "related_queries": kernel.get("related_queries", []),
            "sector_context": kernel.get("sector_context"),
        },
        "suggestions": suggestions[:4],
        "results": results,
        "count": len(results),
        "timing_ms": round(elapsed, 2),
        "index_stats": get_index_stats(tenant_id=tid),
        "tenant_id": tid,
    }


def build_audit_report(*, tenant_id: str | None = None) -> Dict[str, Any]:
    from services.global_search_index import get_dynamic_index_counts
    from services.global_search_learning_store import audit_snapshot

    tid = str(tenant_id or "").strip() or None
    stats = get_index_stats(tenant_id=tid)
    dynamic = get_dynamic_index_counts(tenant_id=tid)
    learning = audit_snapshot()
    return {
        "static_index": stats,
        "dynamic_sources": dynamic,
        "learning": learning,
        "tenant_id": tid,
        "kernel_capabilities": [
            "Corrección ortográfica determinística",
            "Sinónimos operativos ES/EN",
            "Detección de intención (IP, CVE, módulos)",
            "Ranking: exactitud → semántica → frecuencia → relevancia sector/intent",
            "Sugerencias desde historial del usuario",
        ],
        "limitations": [
            "Sin embeddings externos: la semántica usa fuzzy + sinónimos + intención",
            "IOC/NDCI en búsqueda: solo tenant plataforma (host) — no TENANT_GLOBAL",
            "Archivos analizados: historial Centro de Defensa e informes MDR persistidos",
            "El Kernel IA en chat no sustituye esta indexación; comparte contexto de intención",
        ],
    }
