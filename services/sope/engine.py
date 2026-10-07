#!/usr/bin/env python3
"""
Motor principal del SOPE — Security Orchestration & Playbook Engine.
Coordina todos los motores. No detecta amenazas; decide cómo responder.
"""
from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.sope.limitations import AUTOMATION_LEVELS, POLICY
from services.sope.playbook_catalog import PLAYBOOKS, PLAYBOOK_IDS, select_playbook, THREAT_TO_PLAYBOOK
from services.sope.store import (
    record_decision, record_execution, record_forensic,
    load_decisions, load_executions, load_forensic,
)
from utils.logger import logger

_automation_level: int = POLICY["default_automation_level"]
_authorized_actions: set = set()


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def set_automation_level(level: int) -> Dict[str, Any]:
    global _automation_level
    if level not in AUTOMATION_LEVELS:
        return {"ok": False, "error": f"Invalid level {level}. Valid: {list(AUTOMATION_LEVELS.keys())}"}
    _automation_level = level
    return {"ok": True, "level": level, "config": AUTOMATION_LEVELS[level]}


def get_automation_level() -> Dict[str, Any]:
    return {"level": _automation_level, "config": AUTOMATION_LEVELS[_automation_level]}


def authorize_actions(action_ids: List[str]) -> None:
    global _authorized_actions
    _authorized_actions.update(action_ids)


def _consult_engine(engine_name: str, threat_context: Dict[str, Any]) -> Dict[str, Any]:
    """Consulta ligera a un motor para aportar contexto, sin ejecutar acciones."""
    result: Dict[str, Any] = {"engine": engine_name, "status": "consulted", "data": {}}
    try:
        if engine_name == "tie":
            from services.threat_intelligence_enterprise import stats as tie_stats
            result["data"] = tie_stats()
        elif engine_name == "health_engine":
            from services.health_engine import get_health_status
            result["data"] = get_health_status()
        elif engine_name == "kernel_ia":
            result["data"] = {"role": "analyst_only", "executes_playbooks": False}
        elif engine_name == "swarm":
            result["data"] = {"role": "correlator_only", "executes_actions": False}
        elif engine_name == "forense":
            result["data"] = {"role": "evidence_chain"}
        elif engine_name in ("btde", "endpoint", "red", "web_security", "cryptovault", "adaptive_profile", "compliance", "centro_defensa"):
            result["data"] = {"status": "available"}
        else:
            result["data"] = {"status": "unknown_engine"}
    except Exception as exc:
        result["status"] = "error"
        result["data"] = {"error": str(exc)[:200]}
    return result


def _compute_confidence(
    threat_context: Dict[str, Any],
    engine_consults: List[Dict[str, Any]],
) -> float:
    """Calcula confidence score basado en múltiples fuentes."""
    scores: List[float] = []
    severity = str(threat_context.get("severity") or threat_context.get("nivel_riesgo") or "MEDIO").upper()
    sev_map = {"CRITICO": 0.95, "ALTO": 0.75, "MEDIO": 0.5, "BAJO": 0.25}
    scores.append(sev_map.get(severity, 0.5))

    evidence = threat_context.get("evidence") or {}
    if evidence:
        scores.append(min(1.0, len(str(evidence)) / 500.0))

    consulted = sum(1 for c in engine_consults if c.get("status") == "consulted")
    if consulted > 0:
        scores.append(min(1.0, consulted / 5.0))

    return round(sum(scores) / max(1, len(scores)), 4) if scores else 0.0


def _generate_forensic_entry(
    playbook_id: str,
    execution_id: str,
    phase: str,
    detail: str,
    evidence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Genera entrada de cadena de custodia."""
    content = f"{execution_id}:{phase}:{detail}:{_utc()}"
    entry = {
        "execution_id": execution_id,
        "playbook_id": playbook_id,
        "phase": phase,
        "detail": detail,
        "hash_sha256": hashlib.sha256(content.encode()).hexdigest(),
        "timestamp_utc": _utc(),
        "evidence": evidence or {},
    }
    record_forensic(entry)
    return entry


def orchestrate(
    threat_type: str,
    threat_context: Dict[str, Any],
    user_email: Optional[str] = None,
    override_level: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Punto de entrada principal del SOPE.
    Recibe una amenaza detectada y orquesta la respuesta.
    """
    t0 = time.perf_counter()
    execution_id = str(uuid.uuid4())[:12]
    level = override_level if override_level is not None else _automation_level
    level_config = AUTOMATION_LEVELS.get(level, AUTOMATION_LEVELS[1])

    playbook_id = select_playbook(threat_type)
    playbook = PLAYBOOKS.get(playbook_id)
    if not playbook:
        playbook_id = "critical_threat"
        playbook = PLAYBOOKS["critical_threat"]

    # Phase 1: Consult engines
    engine_consults: List[Dict[str, Any]] = []
    for engine in playbook.get("motores", []):
        consult = _consult_engine(engine, threat_context)
        engine_consults.append(consult)

    # Phase 2: Compute confidence
    confidence = _compute_confidence(threat_context, engine_consults)

    # Phase 3: Forensic — BEFORE
    _generate_forensic_entry(playbook_id, execution_id, "before",
        f"Playbook {playbook_id} iniciado para {threat_type}", threat_context)

    # Phase 4: Process actions according to automation level
    actions_executed: List[Dict[str, Any]] = []
    actions_recommended: List[Dict[str, Any]] = []
    actions_blocked: List[Dict[str, Any]] = []

    for action in playbook.get("acciones", []):
        action_type = action.get("tipo", "observe")
        is_destructive = action.get("destructive", False)
        action_result: Dict[str, Any] = {
            "action_id": action["id"],
            "tipo": action_type,
            "descripcion": action.get("descripcion", ""),
            "destructive": is_destructive,
        }

        if action_type in ("observe", "forensic"):
            action_result["status"] = "executed"
            action_result["detail"] = "Observación/evidencia registrada."
            actions_executed.append(action_result)
        elif action_type in ("enrich", "correlate", "analyze"):
            action_result["status"] = "executed"
            action_result["detail"] = f"Consulta {action_type} realizada."
            actions_executed.append(action_result)
        elif action_type == "recommend":
            if level >= 2:
                action_result["status"] = "recommended"
                action_result["detail"] = "Acción recomendada, esperando aprobación."
                actions_recommended.append(action_result)
            else:
                action_result["status"] = "observed_only"
                action_result["detail"] = "Nivel 1: solo observar."
                actions_executed.append(action_result)
        elif action_type == "execute":
            if is_destructive and level < 3:
                action_result["status"] = "blocked"
                action_result["detail"] = f"Acción destructiva bloqueada (nivel={level}, requiere >= 3)."
                actions_blocked.append(action_result)
            elif level == 3 and action["id"] not in _authorized_actions:
                action_result["status"] = "blocked"
                action_result["detail"] = "Nivel 3: acción no pre-autorizada."
                actions_blocked.append(action_result)
            elif level >= 3:
                action_result["status"] = "executed"
                action_result["detail"] = "Acción autorizada ejecutada."
                actions_executed.append(action_result)
            else:
                action_result["status"] = "blocked"
                action_result["detail"] = f"Nivel {level} no permite ejecución."
                actions_blocked.append(action_result)

    # Phase 5: Forensic — DURING
    _generate_forensic_entry(playbook_id, execution_id, "during",
        f"Acciones: {len(actions_executed)} ejecutadas, {len(actions_recommended)} recomendadas, {len(actions_blocked)} bloqueadas")

    # Phase 6: Forensic — AFTER
    duration_ms = round((time.perf_counter() - t0) * 1000, 2)
    _generate_forensic_entry(playbook_id, execution_id, "after",
        f"Playbook {playbook_id} completado en {duration_ms}ms")

    # Build result
    result = {
        "execution_id": execution_id,
        "playbook_id": playbook_id,
        "playbook_nombre": playbook["nombre"],
        "threat_type": threat_type,
        "automation_level": level,
        "automation_level_name": level_config["name"],
        "confidence_score": confidence,
        "motores_consultados": [c["engine"] for c in engine_consults],
        "motores_count": len(engine_consults),
        "actions_executed": actions_executed,
        "actions_recommended": actions_recommended,
        "actions_blocked": actions_blocked,
        "destructive_actions_executed": [a for a in actions_executed if a.get("destructive")],
        "condiciones_exito": playbook.get("condiciones_exito", []),
        "duration_ms": duration_ms,
        "user": user_email,
        "kernel_ia": {"role": "analyst_only", "executed_playbook": False},
        "swarm": {"role": "correlator_only", "executed_action": False},
        "timestamp_utc": _utc(),
    }

    # Record decision
    record_decision({
        "execution_id": execution_id,
        "playbook_id": playbook_id,
        "threat_type": threat_type,
        "automation_level": level,
        "confidence_score": confidence,
        "actions_executed": len(actions_executed),
        "actions_recommended": len(actions_recommended),
        "actions_blocked": len(actions_blocked),
        "destructive_executed": len(result["destructive_actions_executed"]),
        "duration_ms": duration_ms,
        "user": user_email,
    })

    # Record execution
    record_execution(result)

    return result


def get_dashboard() -> Dict[str, Any]:
    decisions = load_decisions(200)
    executions = load_executions(200)
    forensic = load_forensic(200)

    playbook_counts: Dict[str, int] = {}
    for d in decisions:
        pid = d.get("playbook_id", "unknown")
        playbook_counts[pid] = playbook_counts.get(pid, 0) + 1

    return {
        "automation_level": _automation_level,
        "automation_config": AUTOMATION_LEVELS[_automation_level],
        "total_playbooks": len(PLAYBOOK_IDS),
        "playbook_ids": PLAYBOOK_IDS,
        "total_decisions": len(decisions),
        "total_executions": len(executions),
        "total_forensic_entries": len(forensic),
        "playbook_execution_counts": playbook_counts,
        "recent_decisions": decisions[-10:],
        "recent_executions": executions[-5:],
        "recent_forensic": forensic[-10:],
        "policy": POLICY,
        "generated_at_utc": _utc(),
    }


def stats() -> Dict[str, Any]:
    return {
        "automation_level": _automation_level,
        "total_playbooks": len(PLAYBOOK_IDS),
        "decisions": len(load_decisions(500)),
        "executions": len(load_executions(500)),
        "forensic_entries": len(load_forensic(500)),
        "generated_at_utc": _utc(),
    }
