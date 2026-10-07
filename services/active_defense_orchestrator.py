"""
Orquestador de defensa activa — contención, resolución y escalado basados en evidencia.
No genera alertas sin evidencia suficiente del motor NOVUS.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from utils.logger import logger

_ade_inflight: Set[str] = set()
_ade_lock = threading.Lock()
_MAX_ADE_WORKERS = 4

ACTIVE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "active_defense")
STATE_FILE = os.path.join(ACTIVE_DIR, "incidents.json")
ESCALATION_THRESHOLD = 3
VERIFY_INTERVAL_MINUTES = 15


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _ensure_dir() -> None:
    os.makedirs(ACTIVE_DIR, exist_ok=True)


def _load_state() -> Dict[str, Any]:
    _ensure_dir()
    if not os.path.isfile(STATE_FILE):
        return {"active": [], "resolved": [], "escalated": []}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {"active": [], "resolved": [], "escalated": []}


def _save_state(state: Dict[str, Any]) -> None:
    _ensure_dir()
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2)


def _finding_id(entry: dict) -> str:
    return str(
        entry.get("id")
        or entry.get("finding_id")
        or f"RT-{entry.get('threat_type', 'TH')}-{entry.get('time', _now())}".replace(" ", "")
    )


def handle_runtime_threat(entry: dict, user_email: Optional[str] = None) -> Dict[str, Any]:
    """
    Pipeline defensa activa para amenaza runtime.
    Retorna acciones ejecutadas; no promueve sin evidencia.
    """
    from services.threat_coverage_service import threat_coverage

    finding = {
        "id": _finding_id(entry),
        "threat_type": entry.get("threat_type"),
        "motor": entry.get("source"),
        "source": entry.get("source"),
        "severity": entry.get("severity"),
        "details": entry.get("details"),
        "evidence": entry.get("evidence") or entry.get("details"),
        "verified": entry.get("verified"),
    }

    category_id, confidence = threat_coverage.classify_finding(finding)
    if not threat_coverage.has_sufficient_evidence(finding, category_id):
        return {
            "status": "skipped",
            "reason": "evidencia_insuficiente",
            "category": category_id,
            "actions": [],
        }

    cat = threat_coverage.get_category(category_id or "") or {}
    caps = cat.get("capabilities") or {}
    actions: List[str] = []
    result: Dict[str, Any] = {
        "status": "active",
        "finding_id": finding["id"],
        "category": category_id,
        "confidence": confidence,
        "actions": actions,
    }

    try:
        from services.defense_coordinator import defense_coordinator

        defense_coordinator.record_detection(
            "active_defense_orchestrator",
            "threat_classified",
            {"category": category_id, "confidence": confidence, "finding": finding["id"]},
            phase="detect",
            outcome="detected",
            threat_type=cat.get("aspe_type"),
            finding_id=finding["id"],
            detail=cat.get("label"),
            confidence=f"{confidence:.0%}",
        )
        actions.append("record_evidence")
    except Exception as exc:
        logger.debug("active_defense record: %s", exc)

    if caps.get("contain") and entry.get("source") != "test_harness":
        try:
            from services.adaptive_sector_protection_engine import aspe

            aspe_result = aspe.evaluate_incident(
                {
                    "id": finding["id"],
                    "tipo": entry.get("threat_type"),
                    "threat_type": cat.get("aspe_type") or entry.get("threat_type"),
                    "motor": entry.get("source"),
                    "descripcion": str(entry.get("details", ""))[:400],
                    "evidencia": entry.get("details") if isinstance(entry.get("details"), dict) else {"raw": entry.get("details")},
                    "verified": True,
                    "confianza": "Alta" if entry.get("severity") in ("HIGH", "CRITICAL", "CRITICO") else "Media",
                },
                user_email=user_email,
                source="active_defense",
            )
            actions.append(f"aspe_{aspe_result.get('status', 'evaluated')}")
        except Exception as exc:
            logger.debug("active_defense ASPE: %s", exc)

    try:
        from services.threat_coverage_service import threat_coverage as tc

        tc.append_intelligence_entry(category_id or "generic", finding, finding.get("evidence") or {})
        actions.append("intel_library")
    except Exception:
        pass

    try:
        from services.defense_coordinator import defense_coordinator

        defense_coordinator.notify_kernel_incident(
            "active_defense_orchestrator",
            "ACTIVE_DEFENSE_THREAT",
            f"{cat.get('label', category_id)} — {finding['id']}",
            incident_id=finding["id"],
            severity=str(entry.get("severity", "medium")).lower(),
            evidence={"category": category_id, "actions": actions},
        )
        actions.append("notify_kernel")
    except Exception:
        pass

    state = _load_state()
    active_entry = {
        "finding_id": finding["id"],
        "category": category_id,
        "threat_type": entry.get("threat_type"),
        "severity": entry.get("severity"),
        "started_at": _now(),
        "last_seen_at": _now(),
        "check_count": 1,
        "escalation_level": 0,
        "actions": actions,
        "status": "active",
    }
    existing = next((a for a in state["active"] if a["finding_id"] == finding["id"]), None)
    if existing:
        existing["last_seen_at"] = _now()
        existing["check_count"] = existing.get("check_count", 0) + 1
        existing["actions"] = list(set((existing.get("actions") or []) + actions))
    else:
        state["active"].append(active_entry)
    _save_state(state)

    result["actions"] = actions
    return result


def _threat_still_present(entry: dict, threat_cache: dict) -> bool:
    """Verifica si la amenaza sigue en caché del motor."""
    fid = entry.get("finding_id", "")
    ttype = str(entry.get("threat_type") or "").lower()
    for t in (threat_cache or {}).get("threats") or []:
        if str(t.get("type") or "").lower() == ttype:
            det = t.get("details") or {}
            if det.get("verified") or det.get("evidence"):
                return True
    for p in (threat_cache or {}).get("suspicious_processes") or []:
        if ttype in ("malware", "trojan", "spyware", "cryptojacking", "endpoints"):
            return True
    if "NDR" in fid or entry.get("category") in ("network", "lateral_movement", "mitm"):
        try:
            from services.network_ndr_service import build_ndr_payload
            ndr = build_ndr_payload(force_refresh=False)
            alerts = ndr.get("alerts") or []
            return len(alerts) > 0
        except Exception:
            return False
    return False


def verify_and_reconcile_active_incidents() -> Dict[str, Any]:
    """
    Re-verifica incidentes activos. Si la amenaza desapareció → resuelve y archiva evidencia.
    Si persiste → escala.
    """
    from services.novus_security_integration import novus_security

    state = _load_state()
    cache = novus_security._threat_cache or {}
    resolved_ids: List[str] = []
    escalated_ids: List[str] = []

    still_active: List[dict] = []
    for entry in state.get("active") or []:
        if entry.get("status") != "active":
            still_active.append(entry)
            continue

        present = _threat_still_present(entry, cache)
        if not present:
            entry["status"] = "resolved"
            entry["resolved_at"] = _now()
            entry["resolution"] = "evidence_absent_on_recheck"
            state.setdefault("resolved", []).append(entry)
            resolved_ids.append(entry["finding_id"])

            try:
                from services.alerts_canonical_service import resolve_alerts_for_finding

                resolve_alerts_for_finding(entry["finding_id"], "evidence_absent_on_recheck")
            except Exception:
                pass

            try:
                from services.adaptive_sector_protection_engine import aspe
                aspe.release_incident(entry["finding_id"], resolved=True)
            except Exception:
                pass

            try:
                from services.defense_coordinator import defense_coordinator

                defense_coordinator.record_detection(
                    "active_defense_orchestrator",
                    "incident_resolved",
                    {"finding_id": entry["finding_id"], "reason": "evidence_cleared"},
                    phase="recover",
                    outcome="success",
                    finding_id=entry["finding_id"],
                    detail="Amenaza no presente en re-verificación",
                )
            except Exception:
                pass

            try:
                from database import SessionLocal, InteligenciaCaso
                db = SessionLocal()
                try:
                    row = db.query(InteligenciaCaso).filter(
                        InteligenciaCaso.source_ref == entry["finding_id"]
                    ).first()
                    if row:
                        row.estado = "cerrado"
                        row.resolucion = "Resuelto — evidencia ausente en re-verificación"
                        db.commit()
                finally:
                    db.close()
            except Exception:
                pass
        else:
            entry["last_seen_at"] = _now()
            entry["check_count"] = entry.get("check_count", 0) + 1
            if entry.get("check_count", 0) >= ESCALATION_THRESHOLD:
                entry["escalation_level"] = entry.get("escalation_level", 0) + 1
                escalated_ids.append(entry["finding_id"])
                state.setdefault("escalated", []).append({
                    "finding_id": entry["finding_id"],
                    "at": _now(),
                    "level": entry["escalation_level"],
                })
                if entry.get("escalation_level", 0) >= 2:
                    try:
                        from services.adaptive_defense_engine import activate_after_failed_remediation
                        from services.resource_backpressure_service import (
                            CAT_HEAVY_AGG,
                            should_run_background,
                        )

                        finding_id = str(entry.get("finding_id") or "")
                        ade_allowed = should_run_background(CAT_HEAVY_AGG)
                        with _ade_lock:
                            if not ade_allowed or not finding_id:
                                pass
                            elif finding_id in _ade_inflight:
                                pass
                            elif len(_ade_inflight) >= _MAX_ADE_WORKERS:
                                logger.debug(
                                    "ADE worker cap reached (%s) — skip %s",
                                    _MAX_ADE_WORKERS,
                                    finding_id[:12],
                                )
                            else:
                                _ade_inflight.add(finding_id)

                                def _ade_worker(fid: str = finding_id):
                                    try:
                                        activate_after_failed_remediation(
                                            fid,
                                            {"id": fid, "type": entry.get("threat_type"), "verified": True},
                                            remediation_result={"status": "failed"},
                                        )
                                    finally:
                                        with _ade_lock:
                                            _ade_inflight.discard(fid)

                                threading.Thread(
                                    target=_ade_worker,
                                    daemon=True,
                                    name=f"ADE-{finding_id[:12]}",
                                ).start()
                    except Exception:
                        pass
                try:
                    from services.defense_coordinator import defense_coordinator

                    defense_coordinator.notify_kernel_incident(
                        "active_defense_orchestrator",
                        "ACTIVE_DEFENSE_ESCALATION",
                        f"Amenaza persistente {entry['finding_id']} — nivel {entry['escalation_level']}",
                        incident_id=entry["finding_id"],
                        severity="high",
                    )
                except Exception:
                    pass
            still_active.append(entry)

    state["active"] = still_active
    _save_state(state)

    return {
        "resolved": resolved_ids,
        "escalated": escalated_ids,
        "active_count": len(still_active),
    }


class ActiveDefenseOrchestrator:
    handle_runtime_threat = staticmethod(handle_runtime_threat)
    verify_and_reconcile_active_incidents = staticmethod(verify_and_reconcile_active_incidents)


active_defense = ActiveDefenseOrchestrator()
