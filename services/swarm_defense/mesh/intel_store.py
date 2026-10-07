#!/usr/bin/env python3
"""
Almacén local de intel recibida/enviada por el mesh (IOC, reputación, hashes).
Solo datos reales aceptados; sin telemetría inventada.

P0-2: IOC operativos para influencia ZDDE son tenant-scoped.
- Sin tenant verificable → NO se aplica a store de influencia (DENY).
- Legacy sin tenant → legacy_unscoped; ignorado para influencia ZDDE.
- HOST_GLOBAL no se inventa aquí; ZDDE sin tenant_id no consume mesh intel.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
STORE_DIR = os.path.join(ROOT, "data", "swarm_mesh", "intel")
_lock = threading.RLock()

_TENANT_KEYS = ("tenant_id", "company_id", "nit_pyme", "nit")
_BUCKETS = ("ips", "domains", "hashes", "urls", "behaviors")
_SCHEMA = "tenant_scoped_v1"


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure() -> None:
    os.makedirs(STORE_DIR, exist_ok=True)


def resolve_ioc_tenant_id(
    source: Optional[Dict[str, Any]] = None,
    *,
    tenant_id: Optional[str] = None,
) -> Optional[str]:
    """
    Identidad canónica para IOC Mesh → ZDDE.
    No usa email, dominio, hostname, IP, MAC ni user-agent.
    """
    if tenant_id is not None and str(tenant_id).strip():
        return str(tenant_id).strip()
    if not isinstance(source, dict):
        return None
    for key in _TENANT_KEYS:
        val = source.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    for nested_key in ("origin", "evidence", "meta"):
        nested = source.get(nested_key)
        if isinstance(nested, dict):
            for key in _TENANT_KEYS:
                val = nested.get(key)
                if val is not None and str(val).strip():
                    return str(val).strip()
    return None


def _empty_buckets() -> Dict[str, Dict[str, Any]]:
    return {b: {} for b in _BUCKETS}


def _normalize_store(raw: Any) -> Dict[str, Any]:
    """Preserve legacy unscoped rows; never reassign them to a tenant."""
    if isinstance(raw, dict) and raw.get("schema") == _SCHEMA:
        tenants = raw.get("tenants") if isinstance(raw.get("tenants"), dict) else {}
        legacy = raw.get("legacy_unscoped") if isinstance(raw.get("legacy_unscoped"), dict) else _empty_buckets()
        for b in _BUCKETS:
            legacy.setdefault(b, {})
            if not isinstance(legacy[b], dict):
                legacy[b] = {}
        clean_tenants: Dict[str, Any] = {}
        for tid, block in tenants.items():
            if not isinstance(block, dict):
                continue
            nb = _empty_buckets()
            for b in _BUCKETS:
                nb[b] = block.get(b) if isinstance(block.get(b), dict) else {}
            clean_tenants[str(tid)] = nb
        return {"schema": _SCHEMA, "tenants": clean_tenants, "legacy_unscoped": legacy}
    # Pre-P0-2 flat format → legacy_unscoped only
    legacy = _empty_buckets()
    if isinstance(raw, dict):
        for b in _BUCKETS:
            legacy[b] = raw.get(b) if isinstance(raw.get(b), dict) else {}
    return {"schema": _SCHEMA, "tenants": {}, "legacy_unscoped": legacy}


def _load_store(ioc_path: str) -> Dict[str, Any]:
    if not os.path.isfile(ioc_path):
        return {"schema": _SCHEMA, "tenants": {}, "legacy_unscoped": _empty_buckets()}
    try:
        with open(ioc_path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception:
        return {"schema": _SCHEMA, "tenants": {}, "legacy_unscoped": _empty_buckets()}
    return _normalize_store(raw)


def _save_store(ioc_path: str, store: Dict[str, Any]) -> None:
    with open(ioc_path, "w", encoding="utf-8") as fh:
        json.dump(store, fh, indent=2, ensure_ascii=False)


def _append(name: str, row: Dict[str, Any]) -> None:
    _ensure()
    path = os.path.join(STORE_DIR, name)
    with _lock:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def record_outbound(row: Dict[str, Any]) -> None:
    _append("outbound.jsonl", {**row, "direction": "out", "at": _utc()})


def record_inbound(row: Dict[str, Any]) -> None:
    _append("inbound.jsonl", {**row, "direction": "in", "at": _utc()})


def apply_indicators(
    indicators: Dict[str, Any],
    *,
    peer_id: str,
    msg_id: str,
    tenant_id: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Persiste IOC/IOA recibidos bajo tenant verificable.
    Sin tenant → DENY (no influence store update).
    """
    tid = resolve_ioc_tenant_id(payload, tenant_id=tenant_id)
    if not tid:
        return {
            "ok": False,
            "denied": True,
            "reason": "missing_tenant_id",
            "influence": "NO_INFLUENCE",
            "applied": {b: 0 for b in _BUCKETS},
        }

    _ensure()
    applied = {b: 0 for b in _BUCKETS}
    ioc_path = os.path.join(STORE_DIR, "shared_iocs.json")
    with _lock:
        store = _load_store(ioc_path)
        tenants = store.setdefault("tenants", {})
        block = tenants.setdefault(tid, _empty_buckets())
        for key in _BUCKETS:
            values = (indicators or {}).get(key) or []
            if isinstance(values, dict):
                values = list(values.keys())
            if not isinstance(values, list):
                continue
            entry_bucket = block.setdefault(key, {})
            for raw in values:
                val = str(raw).strip().lower()
                if not val or len(val) > 512:
                    continue
                prev = entry_bucket.get(val) or {"count": 0, "peers": [], "first_seen": _utc()}
                prev["count"] = int(prev.get("count") or 0) + 1
                peers = list(prev.get("peers") or [])
                if peer_id not in peers:
                    peers.append(peer_id)
                prev["peers"] = peers[-20:]
                prev["last_seen"] = _utc()
                prev["last_msg_id"] = msg_id
                prev["tenant_id"] = tid
                entry_bucket[val] = prev
                applied[key] = applied.get(key, 0) + 1
        tenants[tid] = block
        store["tenants"] = tenants
        _save_store(ioc_path, store)
    return {
        "ok": True,
        "denied": False,
        "tenant_id": tid,
        "influence": "TENANT_SCOPED",
        "applied": applied,
    }


def _count_buckets(block: Dict[str, Any]) -> Dict[str, int]:
    counts = {b: 0 for b in _BUCKETS}
    for b in _BUCKETS:
        bucket = block.get(b) if isinstance(block, dict) else None
        counts[b] = len(bucket) if isinstance(bucket, dict) else 0
    return counts


def stats(*, tenant_id: Optional[str] = None, for_zdde_influence: bool = False) -> Dict[str, Any]:
    """
    Inventario Mesh.
    - for_zdde_influence=True + tenant_id → solo IOC de ese tenant.
    - for_zdde_influence=True sin tenant → vacío / NO_TENANT_CONTEXT (deny-by-default).
    - for_zdde_influence=False → inventario (tenant + legacy) para status Mesh (no es ZDDE score).
    """
    _ensure()
    ioc_path = os.path.join(STORE_DIR, "shared_iocs.json")
    with _lock:
        store = _load_store(ioc_path)

    if for_zdde_influence:
        if not tenant_id or not str(tenant_id).strip():
            return {
                "ioc_counts": {b: 0 for b in _BUCKETS},
                "outbound_events": _line_count("outbound.jsonl"),
                "inbound_events": _line_count("inbound.jsonl"),
                "store_dir": STORE_DIR,
                "tenant_id": None,
                "influence": "NO_TENANT_CONTEXT",
                "denied": True,
                "has_shared_intel": False,
            }
        tid = str(tenant_id).strip()
        block = (store.get("tenants") or {}).get(tid) or _empty_buckets()
        counts = _count_buckets(block)
        return {
            "ioc_counts": counts,
            "outbound_events": _line_count("outbound.jsonl"),
            "inbound_events": _line_count("inbound.jsonl"),
            "store_dir": STORE_DIR,
            "tenant_id": tid,
            "influence": "TENANT_SCOPED",
            "denied": False,
            "has_shared_intel": any(int(v or 0) > 0 for v in counts.values()),
            "legacy_ignored": True,
        }

    # Observability inventory (not ZDDE influence)
    inventory = {b: 0 for b in _BUCKETS}
    for block in (store.get("tenants") or {}).values():
        c = _count_buckets(block if isinstance(block, dict) else {})
        for b in _BUCKETS:
            inventory[b] += c[b]
    legacy_counts = _count_buckets(store.get("legacy_unscoped") or {})
    total = {b: inventory[b] + legacy_counts[b] for b in _BUCKETS}
    return {
        "ioc_counts": total,
        "tenant_scoped_counts": inventory,
        "legacy_unscoped_counts": legacy_counts,
        "outbound_events": _line_count("outbound.jsonl"),
        "inbound_events": _line_count("inbound.jsonl"),
        "store_dir": STORE_DIR,
        "schema": _SCHEMA,
        "zdde_default_influence": "NO_TENANT_CONTEXT",
    }


def _line_count(name: str) -> int:
    path = os.path.join(STORE_DIR, name)
    if not os.path.isfile(path):
        return 0
    with open(path, encoding="utf-8") as fh:
        return sum(1 for _ in fh)


def recent(direction: str = "inbound", limit: int = 20) -> List[Dict[str, Any]]:
    name = "inbound.jsonl" if direction == "inbound" else "outbound.jsonl"
    path = os.path.join(STORE_DIR, name)
    if not os.path.isfile(path):
        return []
    rows: List[Dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows[-limit:]


def tenant_ioc_visible(*, viewer_tenant_id: Optional[str], value: str, bucket: str = "ips") -> Dict[str, Any]:
    """Lookup helper for isolation tests — never cross-tenant."""
    tid = resolve_ioc_tenant_id(tenant_id=viewer_tenant_id)
    if not tid:
        return {"ok": False, "denied": True, "reason": "missing_tenant_id", "visible": False}
    if bucket not in _BUCKETS:
        return {"ok": False, "denied": True, "reason": "bad_bucket", "visible": False}
    ioc_path = os.path.join(STORE_DIR, "shared_iocs.json")
    with _lock:
        store = _load_store(ioc_path)
        block = (store.get("tenants") or {}).get(tid) or {}
        entry = (block.get(bucket) or {}).get(str(value).strip().lower())
        # Ensure not visible via legacy
        legacy_hit = ((store.get("legacy_unscoped") or {}).get(bucket) or {}).get(str(value).strip().lower())
    return {
        "ok": True,
        "denied": False,
        "tenant_id": tid,
        "visible": bool(entry),
        "legacy_present_but_ignored": bool(legacy_hit),
        "entry_tenant_id": (entry or {}).get("tenant_id") if entry else None,
    }
