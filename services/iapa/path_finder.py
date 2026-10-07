#!/usr/bin/env python3
"""Attack path finder — BFS sobre aristas reales únicamente."""
from __future__ import annotations
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Set, Tuple

from services.iapa.limitations import NA, NI
from services.iapa.graph_builder import build_attack_graph


def _adj(edges: List[Dict[str, Any]], undirected: bool = True):
    g = defaultdict(list)
    for e in edges:
        a, b, rel = e.get("from"), e.get("to"), e.get("relation")
        if not a or not b:
            continue
        g[a].append((b, rel, e.get("evidence")))
        if undirected:
            g[b].append((a, rel, e.get("evidence")))
    return g


def find_paths(
    source_kind: Optional[str] = None,
    target_high_value: bool = True,
    max_depth: int = 6,
    max_paths: int = 30,
    graph: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    gdata = graph or build_attack_graph()
    nodes = {n["id"]: n for n in (gdata.get("nodes") or [])}
    edges = gdata.get("edges") or []
    if not nodes or not edges:
        return {"ok": True, "paths": [], "message": NA, "invented": False}

    adj = _adj(edges)
    sources = []
    for nid, n in nodes.items():
        if source_kind and n.get("kind") != source_kind:
            continue
        if not source_kind and n.get("kind") not in ("usuario", "ioc", "cve", "vulnerabilidad", "proceso"):
            continue
        sources.append(nid)

    targets = [nid for nid, n in nodes.items() if n.get("high_value")] if target_high_value else list(nodes.keys())
    if not targets:
        # fallback: equipos/activos as targets if no high_value marked
        targets = [nid for nid, n in nodes.items() if n.get("kind") in ("equipo", "activo", "incidente")]
    if not targets:
        return {"ok": True, "paths": [], "message": NA, "note": "Sin nodos objetivo evidenciados", "invented": False}

    paths = []
    for src in sources[:40]:
        # BFS
        q = deque([(src, [src], [])])
        visited_depth = {src: 0}
        while q and len(paths) < max_paths:
            cur, path, rels = q.popleft()
            if len(path) > 1 and cur in targets and cur != src:
                paths.append({
                    "nodes": path[:],
                    "labels": [nodes[x]["value"] for x in path if x in nodes],
                    "kinds": [nodes[x]["kind"] for x in path if x in nodes],
                    "relations": rels[:],
                    "length": len(path) - 1,
                    "source": src,
                    "target": cur,
                    "target_high_value": bool(nodes.get(cur, {}).get("high_value")),
                })
                continue
            if len(path) > max_depth:
                continue
            for nxt, rel, _ev in adj.get(cur, []):
                if nxt in path:
                    continue
                nd = len(path)
                if nxt in visited_depth and visited_depth[nxt] < nd:
                    continue
                visited_depth[nxt] = nd
                q.append((nxt, path + [nxt], rels + [rel]))

    paths.sort(key=lambda p: (p["length"], not p.get("target_high_value")))
    shortest = paths[0] if paths else None
    return {
        "ok": True,
        "paths": paths[:max_paths],
        "shortest": shortest or NA,
        "count": len(paths),
        "message": None if paths else NA,
        "invented": False,
    }


def pivot_nodes(graph: Optional[Dict[str, Any]] = None, top_n: int = 15) -> Dict[str, Any]:
    """Nodos cuya eliminación rompe más rutas (grado + aparición en paths)."""
    gdata = graph or build_attack_graph()
    paths = find_paths(graph=gdata, max_paths=50)
    counts = defaultdict(int)
    for p in paths.get("paths") or []:
        for nid in p.get("nodes") or []:
            counts[nid] += 1
    # also degree
    deg = defaultdict(int)
    for e in gdata.get("edges") or []:
        deg[e.get("from")] += 1
        deg[e.get("to")] += 1
    nodes = {n["id"]: n for n in (gdata.get("nodes") or [])}
    ranked = []
    for nid, c in counts.items():
        n = nodes.get(nid) or {"id": nid, "kind": NA, "value": nid}
        ranked.append({
            "id": nid,
            "kind": n.get("kind"),
            "value": n.get("value"),
            "path_appearances": c,
            "degree": deg.get(nid, 0),
            "break_score": c * 2 + deg.get(nid, 0),
        })
    ranked.sort(key=lambda x: x["break_score"], reverse=True)
    return {"ok": True, "pivots": ranked[:top_n] if ranked else [], "message": None if ranked else NA, "invented": False}


def critical_paths(graph: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    paths = find_paths(graph=graph, max_paths=40)
    critical = [p for p in (paths.get("paths") or []) if p.get("target_high_value") or p.get("length", 99) <= 3]
    if not critical:
        critical = (paths.get("paths") or [])[:10]
    return {"ok": True, "critical_paths": critical, "count": len(critical), "message": None if critical else NA, "invented": False}
