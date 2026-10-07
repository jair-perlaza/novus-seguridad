"""Memoria colectiva Swarm — patrones/tácticas/frecuencia (no solo firmas).

P0-1: memoria OPERATIVA tenant-scoped.
- Write: exige tenant_id inequívoco.
- Lookup: solo filas del mismo tenant_id; deny-by-default sin tenant.
- Legacy sin tenant_id: no se usa como contexto operativo (LEGACY_GLOBAL / TENANT_UNKNOWN).
"""
from __future__ import annotations

import json
import os
import threading
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_LOCK = threading.Lock()
_DIR = os.path.join("data", "swarm_defense")
_PATH = os.path.join(_DIR, "collective_memory.jsonl")

# Identity keys allowed for memory scope (never email-domain / hostname / IP / MAC).
_TENANT_KEYS = ("tenant_id", "company_id", "nit_pyme", "nit")


def _ensure() -> None:
    os.makedirs(_DIR, exist_ok=True)


def resolve_memory_tenant_id(
    origin_event: Optional[Dict[str, Any]] = None,
    *,
    tenant_id: Optional[str] = None,
) -> Optional[str]:
    """
    Canonical tenant for collective_memory operations.
    Prefer explicit tenant_id; accept company_id / nit aliases already used in NOVUS.
    Does NOT use email domain, hostname, IP, MAC, or user-agent.
    """
    if tenant_id is not None and str(tenant_id).strip():
        return str(tenant_id).strip()
    if not isinstance(origin_event, dict):
        return None
    for key in _TENANT_KEYS:
        val = origin_event.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    evidence = origin_event.get("evidence")
    if isinstance(evidence, dict):
        for key in _TENANT_KEYS:
            val = evidence.get(key)
            if val is not None and str(val).strip():
                return str(val).strip()
    return None


def _no_memory_context(reason: str = "missing_tenant_id") -> Dict[str, Any]:
    return {
        "seen_before": False,
        "frequency": 0,
        "matches": [],
        "category_frequency": {},
        "memory_context": "NO_MEMORY_CONTEXT",
        "reason": reason,
        "tenant_scoped": True,
    }


def remember_incident(
    *,
    correlation: Dict[str, Any],
    origin_event: Dict[str, Any],
    priority: Optional[Dict[str, Any]] = None,
    tenant_id: Optional[str] = None,
) -> str:
    """Persiste patrón colectivo verificable — solo con tenant inequívoco."""
    tid = resolve_memory_tenant_id(origin_event, tenant_id=tenant_id)
    if not tid:
        # Deny-by-default: no escribir en pool operativo sin scope.
        return ""
    _ensure()
    cls = correlation.get("classification") or {}
    conf = correlation.get("confidence") or {}
    inds = correlation.get("indicators") or {}
    entry = {
        "id": f"SWARM-MEM-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{os.urandom(3).hex()}",
        "ts": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tid,
        "tenant_scope": tid,
        "category": cls.get("category"),
        "tactics": [cls.get("category"), origin_event.get("threat_type"), origin_event.get("action")],
        "behaviors": {
            "origin_motor": origin_event.get("motor"),
            "supporting_modules": cls.get("supporting_modules"),
        },
        "relations": {
            "indicator_keys": {k: (v[:10] if isinstance(v, list) else v) for k, v in inds.items() if v},
            "finding_id": origin_event.get("finding_id"),
        },
        "frequency_hint": 1,
        "confidence": conf,
        "priority": priority,
        "patterns": {
            "indicator_types": cls.get("indicator_types_present"),
            "modules_count": conf.get("modules_with_evidence"),
        },
    }
    with _LOCK:
        with open(_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    # Alimentar Kernel memoria (solo hechos) — sin filtrar tenant aquí (audit host);
    # la influencia operativa vive en lookup_similar tenant-scoped.
    try:
        from services.kernel_memory import kernel_memory

        kernel_memory.log_operation(
            {
                "type": "swarm_collective_memory",
                "id": entry["id"],
                "tenant_id": tid,
                "category": entry.get("category"),
                "patterns": entry.get("patterns"),
                "tactics": entry.get("tactics"),
            }
        )
    except Exception:
        pass
    return entry["id"]


def lookup_similar(
    *,
    indicators: Dict[str, List[str]],
    category: Optional[str] = None,
    limit: int = 200,
    tenant_id: Optional[str] = None,
    origin_event: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Busca reincidencia por indicadores/categoría en memoria real del MISMO tenant.
    Sin tenant inequívoco → NO_MEMORY_CONTEXT (nunca búsqueda global).
    Filas legacy sin tenant_id se ignoran (no se atribuyen ni se usan).
    """
    tid = resolve_memory_tenant_id(origin_event, tenant_id=tenant_id)
    if not tid:
        return _no_memory_context("missing_tenant_id")

    if not os.path.isfile(_PATH):
        return {
            "seen_before": False,
            "frequency": 0,
            "matches": [],
            "category_frequency": {},
            "memory_context": "EMPTY",
            "tenant_id": tid,
            "tenant_scoped": True,
        }

    ips = set(indicators.get("ips") or [])
    domains = set(indicators.get("domains") or [])
    hashes = set(indicators.get("hashes") or [])
    matches = []
    cat_count = Counter()
    try:
        with open(_PATH, encoding="utf-8") as fh:
            lines = fh.readlines()[-limit:]
        for line in lines:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Isolation BEFORE influence: skip other tenants and legacy unscoped rows.
            row_tid = row.get("tenant_id") or row.get("tenant_scope")
            if row_tid is None or not str(row_tid).strip():
                continue  # LEGACY_GLOBAL / TENANT_UNKNOWN — not operational
            if str(row_tid).strip() != tid:
                continue

            rel = (row.get("relations") or {}).get("indicator_keys") or {}
            row_ips = set(rel.get("ips") or [])
            row_dom = set(rel.get("domains") or [])
            row_hash = set(rel.get("hashes") or [])
            hit = bool(ips & row_ips or domains & row_dom or hashes & row_hash)
            if category and row.get("category") == category:
                cat_count[category] += 1
                if not hit and category:
                    hit = True  # misma táctica/categoría — solo same-tenant
            if hit:
                matches.append(
                    {
                        "id": row.get("id"),
                        "ts": row.get("ts"),
                        "category": row.get("category"),
                        "tactics": row.get("tactics"),
                        "tenant_id": tid,
                    }
                )
    except OSError:
        return _no_memory_context("store_unreadable")

    freq = len(matches)
    if category:
        freq = max(freq, cat_count.get(category, 0))
    return {
        "seen_before": freq > 0,
        "frequency": freq,
        "matches": matches[-10:],
        "category_frequency": dict(cat_count),
        "memory_context": "TENANT_SCOPED",
        "tenant_id": tid,
        "tenant_scoped": True,
    }


def memory_stats() -> Dict[str, Any]:
    if not os.path.isfile(_PATH):
        return {"entries": 0, "categories": {}, "tenant_scoped_entries": 0, "legacy_unscoped_entries": 0}
    cats = Counter()
    n = 0
    scoped = 0
    legacy = 0
    with open(_PATH, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            n += 1
            try:
                row = json.loads(line)
                cats[row.get("category") or "unknown"] += 1
                if row.get("tenant_id") or row.get("tenant_scope"):
                    scoped += 1
                else:
                    legacy += 1
            except json.JSONDecodeError:
                continue
    return {
        "entries": n,
        "categories": dict(cats),
        "tenant_scoped_entries": scoped,
        "legacy_unscoped_entries": legacy,
    }
