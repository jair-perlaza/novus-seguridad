#!/usr/bin/env python3
"""Motor principal VIEM — ciclo de vida completo de vulnerabilidades."""
from __future__ import annotations
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.viem.limitations import NA
from services.viem.scanner import scan_local_vulnerabilities, enrich_with_tie, compute_risk_scores
from services.viem.store import (
    load_vulns, load_history, load_remediations,
    record_history, record_remediation, save_snapshot, load_snapshot,
)
from utils.logger import logger

def _utc(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def run_full_scan() -> Dict[str, Any]:
    t0 = time.perf_counter()
    vulns = scan_local_vulnerabilities()
    vulns = enrich_with_tie(vulns)
    vulns = compute_risk_scores(vulns)

    by_risk = {}; by_type = {}; by_status = {}
    for v in vulns:
        r = v.get("risk_level", "MEDIO"); by_risk[r] = by_risk.get(r, 0) + 1
        t = v.get("type", "unknown"); by_type[t] = by_type.get(t, 0) + 1
        s = v.get("remediation_status", "pending"); by_status[s] = by_status.get(s, 0) + 1

    result = {
        "vulnerabilities": vulns,
        "summary": {
            "total": len(vulns),
            "by_risk": by_risk,
            "by_type": by_type,
            "by_status": by_status,
            "critical": by_risk.get("CRITICO", 0),
            "high": by_risk.get("ALTO", 0),
            "medium": by_risk.get("MEDIO", 0),
            "low": by_risk.get("BAJO", 0),
        },
        "scan_duration_ms": round((time.perf_counter() - t0) * 1000, 2),
        "scanned_at_utc": _utc(),
        "invented": False,
    }
    save_snapshot(result)
    record_history({"event": "full_scan", "vulns_found": len(vulns), "duration_ms": result["scan_duration_ms"]})
    return result


def propose_remediation(vuln_id: str, proposal: str, user: Optional[str] = None) -> Dict[str, Any]:
    entry = {
        "vuln_id": vuln_id, "action": "propose", "proposal": proposal,
        "user": user, "status": "proposed", "timestamp_utc": _utc(),
    }
    record_remediation(entry)
    record_history({"event": "remediation_proposed", "vuln_id": vuln_id, "user": user})
    return entry


def verify_remediation(vuln_id: str, evidence: str, user: Optional[str] = None) -> Dict[str, Any]:
    entry = {
        "vuln_id": vuln_id, "action": "verify", "evidence": evidence,
        "user": user, "status": "verified", "timestamp_utc": _utc(),
    }
    record_remediation(entry)
    record_history({"event": "remediation_verified", "vuln_id": vuln_id, "user": user})
    return entry


def get_dashboard() -> Dict[str, Any]:
    snap = load_snapshot()
    if not snap:
        return {"status": "no_scan_yet", "note": "Ejecute un scan primero."}
    vulns = snap.get("vulnerabilities", [])
    top_risk = sorted(vulns, key=lambda v: v.get("risk_score", 0), reverse=True)[:15]
    return {
        "summary": snap.get("summary", {}),
        "top_risk_vulnerabilities": top_risk,
        "remediation_history": load_remediations(50),
        "scan_history": load_history(20),
        "scanned_at_utc": snap.get("scanned_at_utc"),
        "invented": False,
    }


def search_vulns(
    risk_level: Optional[str] = None,
    vuln_type: Optional[str] = None,
    status: Optional[str] = None,
    keyword: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    snap = load_snapshot()
    if not snap: return []
    vulns = snap.get("vulnerabilities", [])
    results = []
    for v in vulns:
        if risk_level and v.get("risk_level") != risk_level: continue
        if vuln_type and v.get("type") != vuln_type: continue
        if status and v.get("remediation_status") != status: continue
        if keyword and keyword.lower() not in str(v).lower(): continue
        results.append(v)
        if len(results) >= limit: break
    return results


def stats() -> Dict[str, Any]:
    snap = load_snapshot()
    if not snap: return {"status": "no_scan", "total": 0}
    return {
        "total": snap.get("summary", {}).get("total", 0),
        "critical": snap.get("summary", {}).get("critical", 0),
        "high": snap.get("summary", {}).get("high", 0),
        "remediations": len(load_remediations(500)),
        "scanned_at_utc": snap.get("scanned_at_utc"),
    }
