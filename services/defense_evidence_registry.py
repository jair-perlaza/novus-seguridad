"""
Registro central de evidencias y acciones de defensa NOVUS.
Trazabilidad inmutable para detección, contención, remediación y recuperación.
No sustituye motores existentes — agrega capa de auditoría verificable.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger
from utils.verifiable_evidence import passes_defense_event_gate

REGISTRY_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "defense_registry")
EVENTS_FILE = os.path.join(REGISTRY_DIR, "events.jsonl")

PHASES = ("prevent", "detect", "contain", "respond", "recover", "audit")


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _ensure_dir() -> None:
    os.makedirs(REGISTRY_DIR, exist_ok=True)


_bridging_evidence = False
_forensic_alert = False


def record_defense_event(
    phase: str,
    action: str,
    motor: str,
    outcome: str,
    *,
    finding_id: Optional[str] = None,
    threat_type: Optional[str] = None,
    evidence: Optional[dict] = None,
    user_email: Optional[str] = None,
    reversible: bool = False,
    revert_key: Optional[str] = None,
    detail: Optional[str] = None,
    confidence: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Registra un evento de defensa con evidencia.
    outcome: success | failed | skipped | detected
    """
    _ensure_dir()
    if phase not in PHASES:
        phase = "audit"

    ok, skip_reason = passes_defense_event_gate(evidence)
    if not ok:
        logger.debug("Defense registry omitido: %s — %s", action, skip_reason)
        return {"status": "skipped", "reason": skip_reason, "action": action}

    entry = {
        "id": f"DEF-{uuid.uuid4().hex[:12]}",
        "timestamp": _now(),
        "phase": phase,
        "action": action,
        "motor": motor,
        "outcome": outcome,
        "finding_id": finding_id,
        "threat_type": threat_type,
        "evidence": evidence or {},
        "user_email": user_email,
        "reversible": reversible,
        "revert_key": revert_key,
        "detail": (detail or "")[:500],
        "confidence": confidence,
        "event_id": (evidence or {}).get("event_id") if isinstance(evidence, dict) else None,
        "correlation_id": (evidence or {}).get("correlation_id") if isinstance(evidence, dict) else None,
        "scope": (evidence or {}).get("scope") if isinstance(evidence, dict) else None,
        "tenant_id": (evidence or {}).get("tenant_id") if isinstance(evidence, dict) else None,
    }

    try:
        with open(EVENTS_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.error("defense_evidence_registry write: %s", exc)

    try:
        from database import SessionLocal, registrar_log_seguridad
        db = SessionLocal()
        try:
            registrar_log_seguridad(
                db,
                f"DEFENSE_{phase.upper()}_{action.upper()}",
                json.dumps(
                    {
                        "id": entry["id"],
                        "motor": motor,
                        "outcome": outcome,
                        "finding_id": finding_id,
                        "detail": entry["detail"][:200],
                    },
                    ensure_ascii=False,
                )[:400],
            )
            db.commit()
        finally:
            db.close()
    except Exception as db_exc:
        logger.debug("defense registry db log: %s", db_exc)

    try:
        global _bridging_evidence
        if not _bridging_evidence:
            _bridging_evidence = True
            try:
                from services.evidence_center_service import record_from_defense_event
                record_from_defense_event(entry)
            finally:
                _bridging_evidence = False
    except Exception as ev_exc:
        logger.debug("evidence_center bridge: %s", ev_exc)

    try:
        if not _forensic_alert:
            from services.forensic_evidence_integrity_service import hook_seal_defense_entry
            hook_seal_defense_entry(entry)
    except Exception as exc:
        logger.debug("forensic seal defense: %s", exc)

    return entry


def event_exists(event_id: str) -> bool:
    """Verifica si un evento DEF-* está presente en el registro."""
    if not event_id or not os.path.exists(EVENTS_FILE):
        return False
    try:
        with open(EVENTS_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    if row.get("id") == event_id:
                        return True
                except Exception:
                    continue
    except Exception:
        return False
    return False


def _gate_passes(row: Dict[str, Any]) -> bool:
    from utils.verifiable_evidence import passes_defense_event_gate

    ok, _ = passes_defense_event_gate(row.get("evidence"))
    return bool(ok)


def list_recent_events(limit: int = 50, phase: Optional[str] = None) -> List[Dict[str, Any]]:
    from utils.jsonl_tail import stream_jsonl_tail

    if not os.path.exists(EVENTS_FILE):
        return []

    def _pred(row: Dict[str, Any]) -> bool:
        if not _gate_passes(row):
            return False
        if phase and row.get("phase") != phase:
            return False
        return True

    try:
        return stream_jsonl_tail(EVENTS_FILE, limit, predicate=_pred)
    except Exception:
        return []


def count_events_by_phase() -> Dict[str, int]:
    from utils.jsonl_tail import count_jsonl_groups

    try:
        return count_jsonl_groups(
            EVENTS_FILE,
            "phase",
            allowed=tuple(PHASES),
            predicate=_gate_passes,
        )
    except Exception:
        return {p: 0 for p in PHASES}


def get_registry_summary() -> Dict[str, Any]:
    recent = list_recent_events(20)
    return {
        "registry_path": EVENTS_FILE,
        "total_recent": len(recent),
        "by_phase": count_events_by_phase(),
        "last_events": recent[-5:],
    }
