#!/usr/bin/env python3
"""Identity Graph — solo relaciones observadas."""
from __future__ import annotations
from typing import Any, Dict, List, Optional, Set, Tuple

from services.identity_intelligence.limitations import NA
from services.identity_intelligence.store import load_identities, load_observations


def build_identity_graph(identity_uuid: Optional[str] = None) -> Dict[str, Any]:
    identities = load_identities().get("identities") or {}
    obs = load_observations(1000)
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    edge_set: Set[Tuple[str, str, str]] = set()

    def add_node(nid: str, kind: str, label: str, meta=None):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "kind": kind, "label": label, "meta": meta or {}}
        return nid

    def add_edge(a, b, rel, evidence):
        if not a or not b or a == b:
            return
        key = (a, b, rel)
        if key in edge_set:
            return
        edge_set.add(key)
        edges.append({"from": a, "to": b, "relation": rel, "evidence": evidence})

    # Seed identity nodes
    focus = [identity_uuid] if identity_uuid and identity_uuid in identities else list(identities.keys())
    for iid in focus:
        rec = identities.get(iid)
        if not rec:
            continue
        add_node(f"identity:{iid}", rec.get("type") or "identity", rec.get("label") or iid, {"uuid": iid})

    # Observed links
    for o in obs:
        iid = o.get("identity_uuid")
        if identity_uuid and iid != identity_uuid:
            # still allow incident/ioc global enrich for focused user via matching
            if o.get("kind") not in ("incident_link",) or iid != identity_uuid:
                if identity_uuid and iid != identity_uuid:
                    continue
        if not iid or iid not in identities:
            if identity_uuid:
                continue
        id_node = add_node(f"identity:{iid}", identities.get(iid, {}).get("type") or "identity",
                           identities.get(iid, {}).get("label") or iid, {"uuid": iid})

        if o.get("kind") == "authentication":
            if o.get("ip"):
                n = add_node(f"network:{o['ip']}", "red", str(o["ip"]))
                add_edge(id_node, n, "authenticated_from", "login_session")
            if o.get("device_type"):
                n = add_node(f"device:{o['device_type']}", "equipo", str(o["device_type"]))
                add_edge(id_node, n, "used_device", "login_session")
            n = add_node(f"event:auth:{o.get('session_id') or o.get('login_at')}", "evento", "authentication")
            add_edge(id_node, n, "has_event", "login_session")

        if o.get("kind") == "host_inventory":
            if o.get("ip"):
                n = add_node(f"network:{o['ip']}", "red", str(o["ip"]))
                add_edge(id_node, n, "has_ip", "asm")
            if o.get("gateway"):
                n = add_node(f"gateway:{o['gateway']}", "red", f"gw:{o['gateway']}")
                add_edge(id_node, n, "uses_gateway", "asm")

        if o.get("kind") == "process_sighting" and o.get("process_name"):
            n = add_node(f"process:{o['process_name']}", "proceso", o["process_name"])
            add_edge(id_node, n, "runs", "psutil")
            n2 = add_node(f"app:{o['process_name']}", "aplicacion", o["process_name"])
            add_edge(id_node, n2, "uses_app", "psutil")

        if o.get("kind") == "incident_link" and o.get("incident_id"):
            n = add_node(f"incident:{o['incident_id']}", "incidente", o["incident_id"])
            add_edge(id_node, n, "related_incident", "imcm")

    # Read-only enrichment from SDL for IOC/playbook if incident nodes exist
    try:
        from services.sdl import search as sdl_search
        for nid, node in list(nodes.items()):
            if node.get("kind") != "incidente":
                continue
            iid = node.get("label")
            res = sdl_search(incident_id=iid, limit=30)
            for r in res.get("records") or []:
                if r.get("ioc") and str(r.get("ioc")) != NA:
                    n = add_node(f"ioc:{r['ioc']}", "ioc", str(r["ioc"]))
                    add_edge(nid, n, "related_ioc", "sdl")
                if r.get("playbook_id") and str(r.get("playbook_id")) != NA:
                    n = add_node(f"playbook:{r['playbook_id']}", "playbook", str(r["playbook_id"]))
                    add_edge(nid, n, "playbook", "sdl")
                if r.get("engine") == "forense" or r.get("record_type") in ("forensic_event", "custody", "evidence"):
                    n = add_node(f"evidence:{r.get('uuid')}", "evidencia", str(r.get("uuid"))[:8])
                    add_edge(nid, n, "forensic_evidence", "sdl")
    except Exception:
        pass

    return {
        "ok": True,
        "focus": identity_uuid or NA,
        "nodes": list(nodes.values()),
        "edges": edges,
        "message": None if nodes else NA,
        "invented": False,
        "note": "Solo relaciones observadas; sin aristas inventadas.",
    }
