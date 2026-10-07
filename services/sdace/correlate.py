#!/usr/bin/env python3
"""Correlaciones SDACE — solo cuando hay evidencia compartida en registros reales."""
from __future__ import annotations
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from services.sdace.limitations import NA
from services.sdace.readers import sdl_search, parse_ts


def _val(r: Dict, *keys) -> Optional[str]:
    for k in keys:
        v = r.get(k)
        if v is not None and str(v).strip() and str(v) != NA:
            return str(v)
    return None


def _bucket_delta(seconds: float) -> str:
    if seconds < 60: return "segundos"
    if seconds < 3600: return "minutos"
    if seconds < 86400: return "horas"
    if seconds < 86400 * 30: return "dias"
    if seconds < 86400 * 365: return "meses"
    return "anos"


def temporal_correlate(limit: int = 300, max_pairs: int = 100) -> Dict[str, Any]:
    """Relaciona pares de eventos con mismo eje (incident/asset/ioc/user) ordenados en el tiempo."""
    res = sdl_search(limit=limit)
    rows = res.get("records") or []
    if len(rows) < 2:
        return {"ok": True, "pairs": [], "message": NA, "invented": False, "by_scale": {}}

    # Group by shared identity keys that actually exist
    groups: Dict[str, List[Dict]] = defaultdict(list)
    for r in rows:
        for kind, val in (
            ("incident_id", _val(r, "incident_id")),
            ("asset", _val(r, "asset", "device", "endpoint_ref")),
            ("ioc", _val(r, "ioc")),
            ("user", _val(r, "user_ref")),
            ("cve", _val(r, "cve")),
        ):
            if val:
                groups[f"{kind}:{val}"].append(r)

    pairs = []
    by_scale: Counter = Counter()
    for gkey, items in groups.items():
        dated = []
        for r in items:
            dt = parse_ts(r.get("timestamp_utc"))
            if dt:
                dated.append((dt, r))
        dated.sort(key=lambda x: x[0])
        for i in range(len(dated) - 1):
            a_dt, a = dated[i]
            b_dt, b = dated[i + 1]
            if a.get("uuid") == b.get("uuid") and a.get("version") == b.get("version"):
                continue
            delta = abs((b_dt - a_dt).total_seconds())
            scale = _bucket_delta(delta)
            by_scale[scale] += 1
            pairs.append({
                "group": gkey,
                "scale": scale,
                "delta_seconds": delta,
                "first": {"uuid": a.get("uuid"), "ts": a.get("timestamp_utc"), "engine": a.get("engine"), "type": a.get("record_type")},
                "second": {"uuid": b.get("uuid"), "ts": b.get("timestamp_utc"), "engine": b.get("engine"), "type": b.get("record_type")},
                "evidence": "shared_key_and_timestamps",
            })
            if len(pairs) >= max_pairs:
                break
        if len(pairs) >= max_pairs:
            break

    return {
        "ok": True,
        "pairs": pairs,
        "by_scale": dict(by_scale),
        "groups_examined": len(groups),
        "message": None if pairs else NA,
        "invented": False,
    }


def identity_correlate(limit: int = 400) -> Dict[str, Any]:
    """Agrupa por usuarios/equipos/activos/IPs/MAC cuando el campo existe."""
    res = sdl_search(limit=limit)
    rows = res.get("records") or []
    axes = {
        "usuarios": Counter(),
        "activos": Counter(),
        "ips_network": Counter(),
        "devices": Counter(),
        "endpoints": Counter(),
        "servers": Counter(),
    }
    relations = []
    # certificates/domains/processes/services: only if present in payload text as real fields
    for r in rows:
        u = _val(r, "user_ref")
        a = _val(r, "asset")
        net = _val(r, "network")
        dev = _val(r, "device")
        ep = _val(r, "endpoint_ref")
        srv = _val(r, "server_ref")
        if u: axes["usuarios"][u] += 1
        if a: axes["activos"][a] += 1
        if net: axes["ips_network"][net] += 1
        if dev: axes["devices"][dev] += 1
        if ep: axes["endpoints"][ep] += 1
        if srv: axes["servers"][srv] += 1
        # relation only if at least two identity fields coexist on same record
        present = [(k, v) for k, v in (("user", u), ("asset", a), ("network", net), ("device", dev)) if v]
        if len(present) >= 2:
            relations.append({
                "uuid": r.get("uuid"),
                "engine": r.get("engine"),
                "identities": dict(present),
                "evidence": "co_occurrence_on_same_record",
            })

    tops = {k: c.most_common(10) for k, c in axes.items()}
    empty_axes = [k for k, c in axes.items() if not c]
    return {
        "ok": True,
        "tops": tops,
        "relations": relations[:100],
        "axes_without_data": empty_axes,
        "certificates": NA,  # unless found below
        "dominios": NA,
        "procesos": NA,
        "servicios": NA,
        "mac": NA,
        "invented": False,
        "note": "Campos ausentes en SDL se reportan NA; no se inventan.",
    }


def ioc_correlate(limit: int = 400) -> Dict[str, Any]:
    res = sdl_search(limit=limit)
    rows = res.get("records") or []
    by_ioc: Dict[str, List] = defaultdict(list)
    counts = Counter()
    for r in rows:
        for field, label in (
            ("ioc", "ioc"), ("malware", "malware"), ("ransomware", "ransomware"),
            ("apt", "apt"), ("campaign", "campaign"),
        ):
            v = _val(r, field)
            if v:
                counts[f"{label}:{v}"] += 1
                by_ioc[f"{label}:{v}"].append({
                    "uuid": r.get("uuid"), "engine": r.get("engine"),
                    "type": r.get("record_type"), "incident_id": _val(r, "incident_id"),
                })
    # Also free-text hash/url/domain only when record_type is ioc and value looks real
    for r in rows:
        if r.get("record_type") != "ioc":
            continue
        v = _val(r, "ioc")
        if not v:
            continue
        kind = "ioc"
        if len(v) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in v):
            kind = "hash"
        elif v.startswith("http"):
            kind = "url"
        elif "." in v and " " not in v and not v.replace(".", "").isdigit():
            # could be domain or ip — only classify domain if not ipv4-like
            parts = v.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                kind = "ip"
            else:
                kind = "domain"
        counts[f"{kind}:{v}"] += 1

    reused = [{k: v} for k, v in counts.most_common(20) if v > 1]
    return {
        "ok": True,
        "top_iocs": counts.most_common(20),
        "reused": reused if reused else [],
        "linked": {k: v[:10] for k, v in list(by_ioc.items())[:20]},
        "message": None if counts else NA,
        "invented": False,
        "botnet": NA if not any(str(k).startswith("apt:") or "botnet" in str(k).lower() for k in counts) else "see_top_iocs",
    }


def cve_correlate(limit: int = 400) -> Dict[str, Any]:
    res = sdl_search(limit=limit)
    rows = res.get("records") or []
    by_cve: Dict[str, Dict[str, Any]] = {}
    freq = Counter()
    for r in rows:
        cve = _val(r, "cve")
        if not cve:
            # also search payload for CVE- pattern without inventing new CVEs — only if field empty skip
            continue
        freq[cve] += 1
        entry = by_cve.setdefault(cve, {
            "cve": cve, "assets": set(), "incidents": set(), "engines": set(),
            "software": NA, "version": NA, "port": NA, "service": NA, "records": 0,
        })
        entry["records"] += 1
        a = _val(r, "asset")
        if a: entry["assets"].add(a)
        iid = _val(r, "incident_id")
        if iid: entry["incidents"].add(iid)
        if r.get("engine"): entry["engines"].add(r.get("engine"))

    linked = []
    for cve, e in by_cve.items():
        linked.append({
            "cve": cve,
            "records": e["records"],
            "assets": list(e["assets"]) or NA,
            "incidents": list(e["incidents"]) or NA,
            "engines": list(e["engines"]),
            "software": e["software"],
            "version": e["version"],
            "port": e["port"],
            "service": e["service"],
            "threat_intelligence": "linked" if "threat_intelligence_enterprise" in e["engines"] or "tie" in str(e["engines"]).lower() else NA,
        })
    linked.sort(key=lambda x: x["records"], reverse=True)
    return {
        "ok": True,
        "top_cves": freq.most_common(20),
        "linked": linked[:50],
        "message": None if freq else NA,
        "invented": False,
        "note": "software/version/port/service solo si existen en registros; hoy tipicamente NA desde SDL fields.",
    }


def mitre_correlate(limit: int = 400) -> Dict[str, Any]:
    res = sdl_search(limit=limit)
    rows = res.get("records") or []
    tactics = Counter()
    techniques = Counter()
    links = []
    for r in rows:
        m = _val(r, "mitre")
        if not m:
            continue
        # Do not invent ATT&CK catalog — only count observed strings
        if m.startswith("TA") or "tactic" in m.lower():
            tactics[m] += 1
        else:
            techniques[m] += 1
        links.append({
            "mitre": m,
            "incident_id": _val(r, "incident_id") or NA,
            "engine": r.get("engine"),
            "uuid": r.get("uuid"),
        })
    return {
        "ok": True,
        "tactics": tactics.most_common(20) if tactics else [],
        "techniques": techniques.most_common(20) if techniques else [],
        "subtechniques": [],  # no separate field in SDL unless present
        "links": links[:50],
        "message": None if (tactics or techniques or links) else NA,
        "invented": False,
        "note": "Sin catalogo MITRE inventado; solo valores presentes en registros.",
    }
