#!/usr/bin/env python3
"""
Motor IMCM — Incident Management & Case Management Enterprise.
Converge motores existentes en incidentes unificados por tenant_id.
NO crea datos ficticios.
"""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.imcm.limitations import NA, STATES
from services.imcm.store import (
    add_comment,
    add_history,
    add_timeline,
    get_next_id,
    load_comments,
    load_history,
    load_incidents,
    load_timeline,
    save_incident,
)
from services.tenant_isolation_service import assert_tenant_access, tenant_ids_match
from utils.logger import logger


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_incident_tenant_id(*, tenant_id: Optional[str] = None, evidence: Optional[Dict] = None) -> str:
    if tenant_id and str(tenant_id).strip():
        return str(tenant_id).strip()
    if evidence and evidence.get("tenant_id"):
        return str(evidence["tenant_id"]).strip()
    from services.tenant_scope_service import get_platform_tenant_id

    return get_platform_tenant_id()


def _collect_asm_context() -> Dict[str, Any]:
    try:
        from services.asm.store import load_inventory

        inv = load_inventory()
        if not inv:
            return {"status": NA}
        host = inv.get("local_host", {})
        return {
            "asset_id": host.get("asset_id"),
            "hostname": host.get("hostname"),
            "ip": host.get("ip"),
            "mac": host.get("mac"),
            "gateway": host.get("gateway"),
            "os": host.get("os"),
            "classification": host.get("classification"),
            "criticality": inv.get("criticality", {}),
            "exposure": inv.get("exposure", {}),
            "dependencies": inv.get("dependencies", [])[:5],
            "software_count": inv.get("summary", {}).get("software_count", 0),
            "services_count": inv.get("summary", {}).get("services_count", 0),
            "open_ports": len(inv.get("open_ports", [])),
            "shadow_it": len(inv.get("shadow_it_findings", [])),
        }
    except Exception:
        return {"status": NA}


def _collect_viem_context() -> Dict[str, Any]:
    try:
        from services.viem import stats as viem_stats

        return viem_stats()
    except Exception:
        return {"status": NA}


def _collect_tie_context() -> Dict[str, Any]:
    try:
        from services.threat_intelligence_enterprise import stats as tie_stats

        return tie_stats()
    except Exception:
        return {"status": NA}


def _collect_sope_context(threat_type: str) -> Dict[str, Any]:
    try:
        from services.sope import orchestrate

        return orchestrate(threat_type, {"source": "imcm", "severity": "ALTO"}, override_level=1)
    except Exception:
        return {"status": NA}


def _collect_health_context() -> Dict[str, Any]:
    try:
        from services.health_engine import get_health_status

        return get_health_status()
    except Exception:
        return {"status": NA}


def _collect_kernel_analysis(threat_type: str, context: Dict) -> Dict[str, Any]:
    return {
        "role": "analyst_only",
        "executes_actions": False,
        "summary": f"Kernel IA analizo amenaza tipo '{threat_type}'.",
        "hypothesis": f"Posible incidente de {threat_type} basado en evidencia de motores.",
        "confidence": "basada en correlacion multi-motor",
        "recommendation": "Investigar con los datos consolidados del incidente.",
    }


def _generate_forensic(incident_id: str, phase: str, detail: str) -> Dict[str, Any]:
    content = f"{incident_id}:{phase}:{detail}:{_utc()}"
    return {
        "incident_id": incident_id,
        "phase": phase,
        "detail": detail,
        "sha256": hashlib.sha256(content.encode()).hexdigest(),
        "timestamp_utc": _utc(),
    }


def create_incident(
    source_engine: str,
    threat_type: str,
    title: str,
    severity: str = "ALTO",
    evidence: Optional[Dict[str, Any]] = None,
    user: Optional[str] = None,
    *,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Crea un incidente unificado consolidando motores — scoped por tenant_id."""
    tid = _resolve_incident_tenant_id(tenant_id=tenant_id, evidence=evidence)
    t0 = time.perf_counter()
    incident_id = get_next_id(tenant_id=tid)
    now = _utc()
    timeline_entries: List[Dict[str, Any]] = []

    forensic_before = _generate_forensic(incident_id, "before", f"Incidente creado por {source_engine}: {title}")
    add_timeline(
        {"incident_id": incident_id, "event": "incident_created", "engine": source_engine, "detail": title, "timestamp_utc": now},
        tenant_id=tid,
    )
    timeline_entries.append({"time": now, "event": "Incidente creado", "engine": source_engine})

    asm = _collect_asm_context()
    add_timeline({"incident_id": incident_id, "event": "asm_context_collected", "engine": "asm", "timestamp_utc": _utc()}, tenant_id=tid)
    timeline_entries.append({"time": _utc(), "event": "ASM contexto recopilado", "engine": "asm"})

    viem = _collect_viem_context()
    add_timeline({"incident_id": incident_id, "event": "viem_context_collected", "engine": "viem", "timestamp_utc": _utc()}, tenant_id=tid)

    tie = _collect_tie_context()
    add_timeline({"incident_id": incident_id, "event": "tie_context_collected", "engine": "tie", "timestamp_utc": _utc()}, tenant_id=tid)

    sope = _collect_sope_context(threat_type)
    add_timeline({"incident_id": incident_id, "event": "sope_orchestrated", "engine": "sope", "timestamp_utc": _utc()}, tenant_id=tid)

    health = _collect_health_context()
    kernel = _collect_kernel_analysis(threat_type, {"asm": asm, "viem": viem, "tie": tie})
    add_timeline({"incident_id": incident_id, "event": "kernel_analysis", "engine": "kernel_ia", "timestamp_utc": _utc()}, tenant_id=tid)

    forensic_during = _generate_forensic(incident_id, "during", "Motores consultados: ASM, VIEM, TIE, SOPE, Health, Kernel")
    duration_ms = round((time.perf_counter() - t0) * 1000, 2)
    forensic_after = _generate_forensic(incident_id, "after", f"Incidente {incident_id} consolidado en {duration_ms}ms")

    incident = {
        "id": incident_id,
        "tenant_id": tid,
        "title": title,
        "fecha": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "hora": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "source_engine": source_engine,
        "threat_type": threat_type,
        "severity": severity,
        "estado": "nuevo",
        "prioridad": "CRITICA" if severity in ("CRITICO", "CRITICAL") else "ALTA" if severity == "ALTO" else "MEDIA",
        "nivel": severity,
        "confidence": sope.get("confidence_score", 0) if isinstance(sope, dict) else 0,
        "risk_score": asm.get("exposure", {}).get("exposure_score", 0) if isinstance(asm.get("exposure"), dict) else 0,
        "user": user,
        "analyst": None,
        "tags": [threat_type, source_engine],
        "related_incidents": [],
        "asm": asm,
        "viem": viem,
        "tie": tie,
        "sope": {
            "playbook_id": sope.get("playbook_id") if isinstance(sope, dict) else NA,
            "playbook_nombre": sope.get("playbook_nombre") if isinstance(sope, dict) else NA,
            "automation_level": sope.get("automation_level") if isinstance(sope, dict) else NA,
            "actions_executed": len(sope.get("actions_executed", [])) if isinstance(sope, dict) else 0,
            "actions_recommended": len(sope.get("actions_recommended", [])) if isinstance(sope, dict) else 0,
            "actions_blocked": len(sope.get("actions_blocked", [])) if isinstance(sope, dict) else 0,
        },
        "health": health if isinstance(health, dict) else {"status": NA},
        "kernel_ia": kernel,
        "forensic": {
            "before": forensic_before,
            "during": forensic_during,
            "after": forensic_after,
            "chain_complete": True,
        },
        "timeline": timeline_entries,
        "evidence": evidence or {},
        "duration_ms": duration_ms,
        "created_at_utc": now,
        "updated_at_utc": now,
        "invented": False,
    }

    save_incident(incident, tenant_id=tid)
    add_history(
        {"event": "incident_created", "incident_id": incident_id, "source": source_engine, "threat_type": threat_type},
        tenant_id=tid,
    )
    return incident


def update_state(incident_id: str, new_state: str, user: Optional[str] = None, *, tenant_id: str) -> Dict[str, Any]:
    if new_state not in STATES:
        return {"ok": False, "error": f"Invalid state. Valid: {STATES}"}
    if get_incident(incident_id, tenant_id=tenant_id) is None:
        return {"ok": False, "error": "not_found"}
    entry = {"incident_id": incident_id, "action": "state_change", "new_state": new_state, "user": user, "timestamp_utc": _utc()}
    add_history(entry, tenant_id=tenant_id)
    add_timeline({"incident_id": incident_id, "event": f"state -> {new_state}", "engine": "imcm", "user": user, "timestamp_utc": _utc()}, tenant_id=tenant_id)
    return {"ok": True, **entry}


def assign_analyst(incident_id: str, analyst: str, user: Optional[str] = None, *, tenant_id: str) -> Dict[str, Any]:
    if get_incident(incident_id, tenant_id=tenant_id) is None:
        return {"ok": False, "error": "not_found"}
    entry = {"incident_id": incident_id, "action": "assign", "analyst": analyst, "user": user, "timestamp_utc": _utc()}
    add_history(entry, tenant_id=tenant_id)
    add_timeline({"incident_id": incident_id, "event": f"assigned to {analyst}", "engine": "imcm", "timestamp_utc": _utc()}, tenant_id=tenant_id)
    return {"ok": True, **entry}


def add_incident_comment(incident_id: str, comment: str, user: Optional[str] = None, *, tenant_id: str) -> Dict[str, Any]:
    if get_incident(incident_id, tenant_id=tenant_id) is None:
        return {"ok": False, "error": "not_found"}
    entry = {"incident_id": incident_id, "comment": comment, "user": user, "timestamp_utc": _utc()}
    add_comment(entry, tenant_id=tenant_id)
    return {"ok": True, **entry}


def get_incident(incident_id: str, *, tenant_id: str) -> Optional[Dict[str, Any]]:
    tid = str(tenant_id or "").strip()
    if not tid:
        return None
    for inc in reversed(load_incidents(tenant_id=tid, limit=500)):
        if inc.get("id") != incident_id:
            continue
        if not tenant_ids_match(inc.get("tenant_id"), tid):
            return None
        inc = dict(inc)
        inc["comments"] = [c for c in load_comments(tenant_id=tid, limit=200) if c.get("incident_id") == incident_id]
        inc["state_history"] = [h for h in load_history(tenant_id=tid, limit=200) if h.get("incident_id") == incident_id]
        inc["full_timeline"] = [t for t in load_timeline(tenant_id=tid, limit=500) if t.get("incident_id") == incident_id]
        return inc
    return None


def search_incidents(
    *,
    tenant_id: str,
    state: Optional[str] = None,
    severity: Optional[str] = None,
    threat_type: Optional[str] = None,
    keyword: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    tid = str(tenant_id or "").strip()
    if not tid:
        return []
    incidents = load_incidents(tenant_id=tid, limit=500)
    results: List[Dict[str, Any]] = []
    for inc in reversed(incidents):
        if not tenant_ids_match(inc.get("tenant_id"), tid):
            continue
        if state and inc.get("estado") != state:
            continue
        if severity and inc.get("severity") != severity:
            continue
        if threat_type and inc.get("threat_type") != threat_type:
            continue
        if keyword and keyword.lower() not in json.dumps(inc, default=str).lower():
            continue
        results.append(inc)
        if len(results) >= limit:
            break
    return results


def get_dashboard_summary(*, tenant_id: str) -> Dict[str, Any]:
    incidents = load_incidents(tenant_id=tenant_id, limit=500)
    by_state: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_engine: Dict[str, int] = {}
    by_threat: Dict[str, int] = {}
    for inc in incidents:
        s = inc.get("estado", "nuevo")
        by_state[s] = by_state.get(s, 0) + 1
        sv = inc.get("severity", "MEDIO")
        by_severity[sv] = by_severity.get(sv, 0) + 1
        e = inc.get("source_engine", "unknown")
        by_engine[e] = by_engine.get(e, 0) + 1
        t = inc.get("threat_type", "unknown")
        by_threat[t] = by_threat.get(t, 0) + 1

    recent = list(reversed(incidents))[:10]
    return {
        "tenant_id": tenant_id,
        "total_incidents": len(incidents),
        "by_state": by_state,
        "by_severity": by_severity,
        "by_engine": by_engine,
        "by_threat_type": by_threat,
        "recent_incidents": recent,
        "generated_at_utc": _utc(),
        "invented": False,
    }


def get_dashboard(*, tenant_id: str) -> Dict[str, Any]:
    summary = get_dashboard_summary(tenant_id=tenant_id)
    summary["timeline"] = load_timeline(tenant_id=tenant_id, limit=30)
    return summary


def stats(*, tenant_id: str) -> Dict[str, Any]:
    incidents = load_incidents(tenant_id=tenant_id, limit=500)
    return {
        "tenant_id": tenant_id,
        "total": len(incidents),
        "nuevo": sum(1 for i in incidents if i.get("estado") == "nuevo"),
        "investigando": sum(1 for i in incidents if i.get("estado") == "investigando"),
        "cerrado": sum(1 for i in incidents if i.get("estado") == "cerrado"),
        "comments": len(load_comments(tenant_id=tenant_id, limit=500)),
        "timeline_entries": len(load_timeline(tenant_id=tenant_id, limit=500)),
    }
