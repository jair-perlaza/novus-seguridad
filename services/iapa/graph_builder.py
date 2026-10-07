#!/usr/bin/env python3
"""
Attack Graph builder — solo aristas con evidencia observada.
No inventa grupos/roles/credenciales si no existen en fuentes.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional, Set, Tuple

from services.iapa.limitations import NA, NI
from services.iapa.readers import sdl_search, val, peek_sources


def _nid(kind: str, value: str) -> str:
    return f"{kind}:{value}"


def build_attack_graph(limit: int = 500) -> Dict[str, Any]:
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    edge_set: Set[Tuple[str, str, str]] = set()
    missing_capabilities: List[str] = []
    sources_status = {k: {"available": v.get("available"), "status": v.get("status")} for k, v in peek_sources().items()}

    def add_node(kind: str, value: Optional[str], meta: Optional[Dict] = None) -> Optional[str]:
        if not value or value == NA:
            return None
        nid = _nid(kind, value)
        if nid not in nodes:
            nodes[nid] = {"id": nid, "kind": kind, "value": value, "meta": meta or {}, "high_value": False}
        elif meta:
            nodes[nid]["meta"].update({k: v for k, v in meta.items() if v not in (None, NA)})
        return nid

    def add_edge(a: Optional[str], b: Optional[str], rel: str, evidence: str):
        if not a or not b or a == b:
            return
        key = (a, b, rel)
        if key in edge_set:
            return
        edge_set.add(key)
        edges.append({"from": a, "to": b, "relation": rel, "evidence": evidence})

    # --- ASM inventory (real) ---
    try:
        from services.asm.store import load_inventory
        inv = load_inventory() or {}
        host = inv.get("local_host") or {}
        if host:
            host_label = host.get("hostname") or host.get("ip") or "local"
            h = add_node("equipo", host_label, {"ip": host.get("ip"), "mac": host.get("mac"), "os": host.get("os")})
            if host.get("ip"):
                ipn = add_node("activo", str(host.get("ip")), {"type": "ip"})
                add_edge(h, ipn, "has_ip", "asm")
            if host.get("gateway"):
                gwn = add_node("activo", f"gw:{host.get('gateway')}", {"type": "gateway"})
                add_edge(h, gwn, "uses_gateway", "asm")
            crit = inv.get("criticality") or {}
            if isinstance(crit, dict) and (crit.get("level") in ("ALTO", "CRITICO", "CRITICAL", "HIGH") or (crit.get("score") or 0) >= 70):
                if h:
                    nodes[h]["high_value"] = True
            # software sample
            for sw in (inv.get("software") or [])[:30]:
                name = sw.get("name") if isinstance(sw, dict) else str(sw)
                if name:
                    sn = add_node("software", name)
                    add_edge(h, sn, "has_software", "asm")
            for svc in (inv.get("services") or [])[:30]:
                name = svc.get("name") if isinstance(svc, dict) else str(svc)
                if name:
                    sn = add_node("servicio", name)
                    add_edge(h, sn, "runs_service", "asm")
            for p in (inv.get("open_ports") or [])[:40]:
                port = p.get("port") if isinstance(p, dict) else p
                if port is not None:
                    pn = add_node("puerto", str(port), {"protocol": p.get("protocol") if isinstance(p, dict) else None})
                    add_edge(h, pn, "listens_on", "asm")
                    # link service name if present
                    if isinstance(p, dict) and p.get("service"):
                        sn = add_node("servicio", str(p["service"]))
                        add_edge(pn, sn, "service_on_port", "asm")
        else:
            missing_capabilities.append("ASM inventory empty -> host graph PARCIAL")
    except Exception as exc:
        missing_capabilities.append(f"ASM: {str(exc)[:80]}")

    # --- UEBA identities (read-only) ---
    try:
        from services.identity_intelligence import list_identities, build_identity_graph
        idents = list_identities()
        for ident in idents[:80]:
            itype = ident.get("type") or "identidad"
            kind_map = {
                "usuario": "usuario",
                "equipo": "equipo",
                "cuenta_servicio": "cuenta_servicio",
                "aplicacion": "software",
                "proceso_persistente": "proceso",
            }
            kind = kind_map.get(itype, "identidad")
            n = add_node(kind, ident.get("label") or ident.get("natural_key") or ident.get("uuid"),
                         {"uuid": ident.get("uuid"), "type": itype})
            # privileged heuristic only if label/attrs indicate admin/service objectively
            label = (ident.get("label") or "").lower()
            attrs = ident.get("attrs") or {}
            if itype == "cuenta_servicio" or "admin" in label or "administrador" in label:
                if n:
                    nodes[n]["meta"]["privileged"] = True
            # link user to last_ip if present
            if itype == "usuario" and attrs.get("last_ip"):
                ipn = add_node("activo", str(attrs["last_ip"]), {"type": "ip"})
                add_edge(n, ipn, "authenticated_from", "ueba")
        # Merge edges from UEBA identity graph for top user
        users = [i for i in idents if i.get("type") == "usuario"]
        if users:
            ug = build_identity_graph(users[0].get("uuid"))
            for e in (ug.get("edges") or [])[:100]:
                # map UEBA node ids into our graph loosely via labels already added
                fr, to, rel = e.get("from"), e.get("to"), e.get("relation") or "ueba_link"
                # only keep if both endpoints exist as our nodes by suffix match — avoid inventing
                # Instead re-parse kinds from UEBA node list
            for un in (ug.get("nodes") or [])[:60]:
                k = un.get("kind") or "identidad"
                kind_map2 = {
                    "usuario": "usuario", "equipo": "equipo", "red": "activo", "proceso": "proceso",
                    "aplicacion": "software", "incidente": "incidente", "ioc": "ioc",
                    "playbook": "playbook", "evidencia": "evidencia", "evento": "evento",
                }
                add_node(kind_map2.get(k, "identidad"), un.get("label") or un.get("value") or un.get("id"))
            # edges between nodes that we successfully added
            label_to_id = {n["value"]: n["id"] for n in nodes.values()}
            for e in (ug.get("edges") or [])[:80]:
                # UEBA uses id like identity:uuid — skip unless we can resolve via node list
                pass
            # Rebuild UEBA edges using node list pairing from same graph structure
            ug_nodes = {n["id"]: n for n in (ug.get("nodes") or [])}
            for e in (ug.get("edges") or [])[:100]:
                a = ug_nodes.get(e.get("from"))
                b = ug_nodes.get(e.get("to"))
                if not a or not b:
                    continue
                kind_map2 = {
                    "usuario": "usuario", "equipo": "equipo", "red": "activo", "proceso": "proceso",
                    "aplicacion": "software", "incidente": "incidente", "ioc": "ioc",
                    "playbook": "playbook", "evidencia": "evidencia", "evento": "evento",
                    "device": "equipo", "gateway": "activo",
                }
                na = add_node(kind_map2.get(a.get("kind"), "identidad"), a.get("label") or a.get("value") or a.get("id"))
                nb = add_node(kind_map2.get(b.get("kind"), "identidad"), b.get("label") or b.get("value") or b.get("id"))
                add_edge(na, nb, e.get("relation") or "observed", "ueba_graph")
    except Exception as exc:
        missing_capabilities.append(f"UEBA: {str(exc)[:80]}")

    # --- SDL / IMCM / VIEM / TIE records ---
    res = sdl_search(limit=limit)
    rows = res.get("records") or []
    if not rows:
        missing_capabilities.append("SDL sin registros o NO DISPONIBLE")

    for r in rows:
        engine = (r.get("engine") or "").lower()
        user = val(r, "user_ref")
        asset = val(r, "asset", "device", "endpoint_ref", "server_ref")
        ioc = val(r, "ioc")
        cve = val(r, "cve")
        incident = val(r, "incident_id")
        playbook = val(r, "playbook_id")
        malware = val(r, "malware", "ransomware", "apt")
        mitre = val(r, "mitre")
        network = val(r, "network")

        un = add_node("usuario", user) if user else None
        an = add_node("activo", asset) if asset else None
        iocn = add_node("ioc", ioc) if ioc else None
        cven = add_node("cve", cve) if cve else None
        incn = add_node("incidente", incident) if incident else None
        pbn = add_node("playbook", playbook) if playbook else None
        thrn = add_node("amenaza", malware) if malware else None
        netn = add_node("activo", network, {"type": "network"}) if network else None

        # Co-occurrence edges only
        if un and an:
            add_edge(un, an, "associated_with", "sdl_same_record")
        if an and iocn:
            add_edge(an, iocn, "observed_ioc", "sdl_same_record")
        if an and cven:
            add_edge(an, cven, "has_cve", "sdl_same_record")
        if cven and incn:
            add_edge(cven, incn, "cve_in_incident", "sdl_same_record")
        if iocn and incn:
            add_edge(iocn, incn, "ioc_in_incident", "sdl_same_record")
        if pbn and incn:
            add_edge(pbn, incn, "playbook_for", "sdl_same_record")
        if thrn and incn:
            add_edge(thrn, incn, "threat_in_incident", "sdl_same_record")
        if un and incn:
            add_edge(un, incn, "user_in_incident", "sdl_same_record")
        if netn and an:
            add_edge(an, netn, "on_network", "sdl_same_record")
        if mitre and incn:
            mn = add_node("amenaza", f"mitre:{mitre}")
            add_edge(mn, incn, "mitre_technique", "sdl_same_record")

        # vulnerability record type
        if (r.get("record_type") or "") == "vulnerability":
            vn = add_node("vulnerabilidad", val(r, "cve") or r.get("uuid") or "vuln")
            if an and vn:
                add_edge(an, vn, "has_vulnerability", "viem_via_sdl")
            if cven and vn and cven != vn:
                add_edge(cven, vn, "cve_maps_vuln", "viem_via_sdl")

        # forensic evidence
        if engine == "forense" or (r.get("record_type") or "") in ("forensic_event", "custody", "evidence"):
            en = add_node("evidencia", str(r.get("uuid") or "")[:12] or NA)
            if incn and en:
                add_edge(incn, en, "forensic_evidence", "sdl")

    # Groups / roles / credentials / CPE — only if present; else document NI
    for cap in ("grupos", "roles", "credenciales", "cpe"):
        # Search if any node kind exists
        if not any(n.get("kind") == cap.rstrip("s") or n.get("kind") == cap for n in nodes.values()):
            # check field presence in rows
            found = False
            for r in rows[:50]:
                if val(r, cap, "group", "role", "credential", "cpe"):
                    found = True
                    break
            if not found:
                missing_capabilities.append(f"{cap}: {NI} (sin campos en fuentes actuales)")

    # Mark high value from ASM criticality already; also servers
    for n in nodes.values():
        if n["kind"] in ("equipo", "activo") and ("server" in str(n.get("meta")).lower() or n.get("high_value")):
            n["high_value"] = True

    return {
        "ok": True,
        "nodes": list(nodes.values()),
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "sources_status": sources_status,
        "missing_capabilities": missing_capabilities,
        "invented": False,
        "note": "Solo nodos/aristas con evidencia. Sin inferencia.",
    }
