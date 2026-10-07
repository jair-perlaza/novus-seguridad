#!/usr/bin/env python3
"""Attack graph y timeline — solo aristas con evidencia real."""
from __future__ import annotations
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from services.sdace.limitations import NA
from services.sdace.readers import sdl_search, parse_ts
from services.sdace.correlate import _val


# Canonical layer order for presentation (nodes only added if evidence exists)
LAYER_ORDER = [
    "user", "asset", "process", "ioc", "threat_intelligence", "btde",
    "sope", "incident", "forense", "admin", "containment",
]


def _node_id(kind: str, value: str) -> str:
    return f"{kind}:{value}"


def build_attack_graph(incident_id: Optional[str] = None, limit: int = 400) -> Dict[str, Any]:
    """
    Grafo a partir de co-ocurrencias y mismos incident_id/ioc/asset.
    No dibuja nodos/aristas sin evidencia.
    """
    if incident_id:
        res = sdl_search(incident_id=incident_id, limit=limit)
    else:
        res = sdl_search(record_type="incident", limit=min(limit, 50))
        # expand related records for top incidents
        incs = res.get("records") or []
        if incs:
            iid = _val(incs[0], "incident_id") or incs[0].get("incident_id")
            if not iid and incs[0].get("record_type") == "incident":
                # payload may hold id
                try:
                    import json
                    p = json.loads(incs[0].get("payload_json") or "{}")
                    iid = p.get("id")
                except Exception:
                    iid = None
            if iid:
                incident_id = iid
                res = sdl_search(incident_id=incident_id, limit=limit)
            else:
                res = sdl_search(limit=limit)
        else:
            res = sdl_search(limit=limit)

    rows = res.get("records") or []
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    edge_set: Set[Tuple[str, str, str]] = set()

    def add_node(kind: str, value: str, meta: Optional[Dict] = None):
        if not value or value == NA:
            return None
        nid = _node_id(kind, value)
        if nid not in nodes:
            nodes[nid] = {"id": nid, "kind": kind, "value": value, "meta": meta or {}}
        return nid

    def add_edge(a: Optional[str], b: Optional[str], relation: str, evidence: str):
        if not a or not b or a == b:
            return
        key = (a, b, relation)
        if key in edge_set:
            return
        edge_set.add(key)
        edges.append({"from": a, "to": b, "relation": relation, "evidence": evidence})

    for r in rows:
        engine = (r.get("engine") or "").lower()
        rtype = (r.get("record_type") or "").lower()
        user_n = add_node("user", _val(r, "user_ref") or "")
        asset_n = add_node("asset", _val(r, "asset", "device", "endpoint_ref") or "")
        ioc_n = add_node("ioc", _val(r, "ioc") or "")
        inc_n = add_node("incident", _val(r, "incident_id") or "")
        sope_n = add_node("sope", _val(r, "playbook_id") or "")
        # engine-as-layer nodes only when that engine produced the record
        eng_n = None
        if "threat_intelligence" in engine or engine == "tie":
            eng_n = add_node("threat_intelligence", engine or "tie")
        elif engine in ("btde",):
            eng_n = add_node("btde", "btde")
        elif engine == "sope":
            eng_n = add_node("sope", _val(r, "playbook_id") or "sope")
        elif engine in ("forense",) or rtype in ("forensic_event", "custody", "evidence"):
            eng_n = add_node("forense", "forense")
        elif engine == "imcm" or rtype == "incident":
            eng_n = add_node("incident", _val(r, "incident_id") or r.get("uuid") or "incident")

        # Real co-occurrence edges on same record
        if user_n and asset_n:
            add_edge(user_n, asset_n, "associated_with", "same_record")
        if asset_n and ioc_n:
            add_edge(asset_n, ioc_n, "observed_ioc", "same_record")
        if ioc_n and eng_n and nodes[eng_n]["kind"] == "threat_intelligence":
            add_edge(ioc_n, eng_n, "enriched_by", "same_record")
        if sope_n and inc_n:
            add_edge(sope_n, inc_n, "playbook_for", "same_record")
        if eng_n and inc_n and nodes[eng_n]["kind"] != "incident":
            add_edge(eng_n, inc_n, "contributed_to", "same_record")
        if eng_n and nodes[eng_n]["kind"] == "forense" and inc_n:
            add_edge(inc_n, eng_n, "forensic_sealed", "same_record")

        # containment/admin only if status fields show real state change evidence
        status = (_val(r, "status") or "").lower()
        if status in ("contenido", "contained", "cerrado", "closed") and inc_n:
            cont = add_node("containment", status)
            add_edge(inc_n, cont, "state", "status_field")

    # process node: only if payload mentions process fields — do not invent
    process_available = False

    return {
        "ok": True,
        "incident_id": incident_id or NA,
        "nodes": list(nodes.values()),
        "edges": edges,
        "layer_order": LAYER_ORDER,
        "process": NA if not process_available else "present",
        "admin": NA,
        "message": None if nodes else NA,
        "invented": False,
        "note": "Solo nodos/aristas con evidencia en registros SDL.",
    }


def build_attack_timeline(incident_id: Optional[str] = None, limit: int = 300) -> Dict[str, Any]:
    if incident_id:
        res = sdl_search(incident_id=incident_id, limit=limit)
    else:
        # pick first incident with related events if any
        incs = sdl_search(record_type="incident", limit=20).get("records") or []
        incident_id = None
        for inc in incs:
            iid = _val(inc, "incident_id")
            if not iid:
                try:
                    import json
                    iid = json.loads(inc.get("payload_json") or "{}").get("id")
                except Exception:
                    iid = None
            if iid:
                incident_id = iid
                break
        res = sdl_search(incident_id=incident_id, limit=limit) if incident_id else sdl_search(limit=limit)

    rows = res.get("records") or []
    events = []
    for r in rows:
        dt = parse_ts(r.get("timestamp_utc"))
        events.append({
            "timestamp_utc": r.get("timestamp_utc"),
            "_sort": dt.timestamp() if dt else 0,
            "engine": r.get("engine"),
            "record_type": r.get("record_type"),
            "uuid": r.get("uuid"),
            "ioc": _val(r, "ioc") or NA,
            "asset": _val(r, "asset") or NA,
            "playbook_id": _val(r, "playbook_id") or NA,
            "status": _val(r, "status") or NA,
            "incident_id": _val(r, "incident_id") or incident_id or NA,
        })
    events.sort(key=lambda e: e["_sort"])
    for e in events:
        e.pop("_sort", None)

    first = events[0] if events else None
    origin = NA
    if first:
        origin = f"{first.get('engine')}:{first.get('record_type')}"

    return {
        "ok": True,
        "incident_id": incident_id or NA,
        "events": events,
        "count": len(events),
        "first_event": first or NA,
        "origin_hypothesis": origin if first else NA,
        "message": None if events else NA,
        "invented": False,
        "note": "Timeline estrictamente cronologica sobre registros existentes.",
    }
