#!/usr/bin/env python3
"""Threat Hunting unificado — consulta solo motores reales."""
from __future__ import annotations
import re
from typing import Any, Dict, List, Optional
from services.soc.limitations import NA
from services.soc.store import save_hunt


def _q_norm(q: str) -> str:
    return (q or "").strip()


def hunt(query: str, category: Optional[str] = None, limit: int = 50, *, tenant_id: str) -> Dict[str, Any]:
    q = _q_norm(query)
    tid = str(tenant_id or "").strip()
    if not tid:
        return {"ok": False, "error": "tenant_id_required", "results": [], "invented": False}
    if not q:
        return {"ok": False, "error": "empty_query", "results": [], "invented": False}

    results: List[Dict[str, Any]] = []
    sources_queried: List[str] = []
    cat = (category or "auto").lower()

    # Auto-detect category hints
    looks_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", q))
    looks_cve = bool(re.match(r"^CVE-\d{4}-\d+", q, re.I))
    looks_hash = bool(re.match(r"^[a-fA-F0-9]{32,64}$", q))
    looks_inc = bool(re.match(r"^INC-\d+", q, re.I))

    # IMCM
    if cat in ("auto", "incidente", "caso", "usuario", "equipo", "activo", "playbook"):
        sources_queried.append("imcm")
        try:
            from services.imcm import search_incidents, get_incident
            if looks_inc:
                inc = get_incident(q.upper(), tenant_id=tid)
                if inc:
                    results.append({"source": "imcm", "type": "incident", "id": inc.get("id"), "title": inc.get("title"), "data": inc})
            else:
                for inc in search_incidents(keyword=q, limit=limit, tenant_id=tid):
                    results.append({
                        "source": "imcm", "type": "incident", "id": inc.get("id"),
                        "title": inc.get("title"), "severity": inc.get("severity"),
                        "estado": inc.get("estado"), "threat_type": inc.get("threat_type"),
                    })
        except Exception as exc:
            results.append({"source": "imcm", "type": "error", "detail": str(exc)[:120], "status": NA})

    # TIE / IOC
    if cat in ("auto", "ioc", "ip", "dominio", "hash", "malware", "ransomware", "botnet", "apt", "campana", "url"):
        sources_queried.append("tie")
        try:
            from services.threat_intelligence_enterprise import search_iocs
            iocs = search_iocs(value=q, limit=limit)
            if not isinstance(iocs, list):
                iocs = []
            for ioc in iocs[:limit]:
                results.append({"source": "tie", "type": "ioc", "data": ioc})
            if looks_ip or looks_hash or cat in ("ip", "hash", "dominio"):
                try:
                    from services.threat_intelligence_enterprise.connectors import enrich_indicator
                    enr = enrich_indicator(q)
                    if enr:
                        results.append({"source": "tie", "type": "enrichment", "data": enr})
                except Exception:
                    pass
        except Exception as exc:
            results.append({"source": "tie", "type": "error", "detail": str(exc)[:120], "status": NA})

    # VIEM / CVE
    if cat in ("auto", "cve", "vulnerabilidad") or looks_cve:
        sources_queried.append("viem")
        try:
            from services.viem import search_vulns
            for v in search_vulns(keyword=q, limit=limit):
                results.append({"source": "viem", "type": "vulnerability", "data": v})
        except Exception as exc:
            results.append({"source": "viem", "type": "error", "detail": str(exc)[:120], "status": NA})

    # ASM
    if cat in ("auto", "activo", "equipo", "ip", "servidor", "endpoint"):
        sources_queried.append("asm")
        try:
            from services.asm.store import load_inventory
            inv = load_inventory() or {}
            host = inv.get("local_host") or {}
            blob = str(inv).lower()
            if q.lower() in blob:
                results.append({
                    "source": "asm", "type": "asset",
                    "hostname": host.get("hostname", NA),
                    "ip": host.get("ip", NA),
                    "mac": host.get("mac", NA),
                    "match": True,
                })
            nodes = inv.get("network_nodes") or []
            for n in nodes:
                if q.lower() in str(n).lower():
                    results.append({"source": "asm", "type": "network_node", "data": n})
        except Exception as exc:
            results.append({"source": "asm", "type": "error", "detail": str(exc)[:120], "status": NA})

    # SOPE playbooks
    if cat in ("auto", "playbook", "mitre"):
        sources_queried.append("sope")
        try:
            from services.sope.playbook_catalog import PLAYBOOKS
            for pid, pb in PLAYBOOKS.items():
                if isinstance(pb, dict) and q.lower() in str(pb).lower():
                    results.append({
                        "source": "sope", "type": "playbook",
                        "id": pid, "nombre": pb.get("nombre") or pb.get("name"),
                        "amenaza": pb.get("threat_type") or pb.get("amenaza") or pid,
                    })
        except Exception as exc:
            results.append({"source": "sope", "type": "error", "detail": str(exc)[:120], "status": NA})

    # Threat type keywords from IMCM already covered; also map ransomware/malware etc.
    if cat in ("ransomware", "malware", "botnet", "apt", "phishing") or q.lower() in (
        "ransomware", "malware", "botnet", "apt", "phishing", "exfiltration", "lateral_movement"
    ):
        sources_queried.append("imcm_threat")
        try:
            from services.imcm import search_incidents
            for inc in search_incidents(threat_type=q.lower(), limit=limit, tenant_id=tid):
                results.append({"source": "imcm", "type": "incident_by_threat", "data": {"id": inc.get("id"), "title": inc.get("title")}})
        except Exception:
            pass

    payload = {
        "ok": True,
        "query": q,
        "category": cat,
        "tenant_id": tid,
        "sources_queried": list(dict.fromkeys(sources_queried)),
        "count": len([r for r in results if r.get("type") != "error"]),
        "results": results[:limit],
        "invented": False,
        "note": NA if not results else None,
    }
    if not results:
        payload["message"] = NA
    save_hunt({"query": q, "category": cat, "count": payload["count"]}, tenant_id=tid)
    return payload
