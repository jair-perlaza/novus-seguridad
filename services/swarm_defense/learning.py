"""
Aprendizaje Swarm — anti data-poisoning.
Solo aprende si incidente validado + evidencia consistente + Kernel marca aprendizaje seguro.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from utils.logger import logger

_LOCK = threading.Lock()
_DIR = os.path.join("data", "swarm_defense")
_PATH = os.path.join(_DIR, "learning.jsonl")
_REJECTED_PATH = os.path.join(_DIR, "learning_rejected.jsonl")


def _ensure() -> None:
    os.makedirs(_DIR, exist_ok=True)


def _kernel_learning_safe(correlation: Dict[str, Any], origin_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Kernel IA NO ejecuta; solo evalúa si el aprendizaje es seguro.
    Heurística verificable (no inventa permisividad).
    """
    conf = correlation.get("confidence") or {}
    level = conf.get("level")
    modules = int(conf.get("modules_with_evidence") or 0)
    inds = correlation.get("indicators") or {}
    has_ioc = any(bool(v) for v in inds.values())
    # Poisoning signals: sin módulos, sin IOC, o confianza insuficiente
    if level in (None, "insufficient_evidence"):
        return {"safe": False, "reason": "insufficient_evidence", "by": "kernel_policy"}
    if modules < 2:
        return {"safe": False, "reason": "need_ge_2_modules_with_evidence", "by": "kernel_policy"}
    if not has_ioc and level != "high":
        return {"safe": False, "reason": "no_structured_indicators", "by": "kernel_policy"}
    # Adaptive Profile: no aprender de eventos marcados no-aprendibles
    evidence = origin_event.get("evidence") if isinstance(origin_event.get("evidence"), dict) else {}
    if evidence.get("learnable") is False or evidence.get("poisoning_suspected"):
        return {"safe": False, "reason": "adaptive_profile_or_poison_flag", "by": "kernel_policy"}
    severity = str(origin_event.get("severity") or evidence.get("severity") or "").lower()
    if severity in ("critical", "high") and modules < 3 and level != "high":
        return {"safe": False, "reason": "high_severity_needs_stronger_corroboration", "by": "kernel_policy"}
    return {
        "safe": True,
        "reason": "validated_multi_module_consistent_evidence",
        "by": "kernel_policy",
        "modules_with_evidence": modules,
        "confidence_level": level,
    }


def record_confirmed_incident(
    correlation: Dict[str, Any],
    origin_event: Dict[str, Any],
    *,
    source: str = "swarm",
    response_results: Optional[List[Dict[str, Any]]] = None,
    force: bool = False,
) -> Optional[str]:
    """
    Persiste aprendizaje solo si pasa anti-poisoning (salvo force=True administrativo).
    """
    gate = _kernel_learning_safe(correlation, origin_event)
    if not force and not gate.get("safe"):
        _ensure()
        rejected = {
            "id": f"SWARM-LRN-REJ-{uuid.uuid4().hex[:10]}",
            "ts": datetime.now(timezone.utc).isoformat(),
            "gate": gate,
            "finding_id": origin_event.get("finding_id"),
            "category": (correlation.get("classification") or {}).get("category"),
        }
        try:
            with _LOCK:
                with open(_REJECTED_PATH, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rejected, ensure_ascii=False) + "\n")
        except Exception:
            pass
        logger.info("swarm learning rejected: %s", gate.get("reason"))
        return None

    entry_id = f"SWARM-LRN-{uuid.uuid4().hex[:12]}"
    started = origin_event.get("_swarm_started_at")
    ended = datetime.now(timezone.utc).isoformat()
    entry = {
        "id": entry_id,
        "ts": ended,
        "source": source,
        "validated": True,
        "kernel_learning_gate": gate,
        "threat_type": origin_event.get("threat_type"),
        "category": (correlation.get("classification") or {}).get("category"),
        "evidences": {
            "indicators": correlation.get("indicators"),
            "supporting_modules": (correlation.get("classification") or {}).get("supporting_modules"),
            "confidence": correlation.get("confidence"),
            "priority": correlation.get("priority"),
        },
        "mechanisms_used": [
            c.get("module_id") for c in (correlation.get("contributions") or []) if c.get("found")
        ],
        "patterns": {
            "indicator_types": (correlation.get("classification") or {}).get("indicator_types_present"),
            "tactics": [
                (correlation.get("classification") or {}).get("category"),
                origin_event.get("threat_type"),
            ],
        },
        "response_results": response_results or [],
        "response_time": {"started_at": started, "ended_at": ended},
        "origin_motor": origin_event.get("motor"),
        "finding_id": origin_event.get("finding_id"),
    }
    try:
        _ensure()
        with _LOCK:
            with open(_PATH, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.warning("swarm learning write: %s", exc)
        return None

    try:
        from services.kernel_memory import kernel_memory

        kernel_memory.log_operation(
            {
                "type": "swarm_learning",
                "id": entry_id,
                "category": entry.get("category"),
                "threat_type": entry.get("threat_type"),
                "mechanisms_used": entry.get("mechanisms_used"),
                "confidence": entry.get("evidences", {}).get("confidence"),
                "patterns": entry.get("patterns"),
                "kernel_gate": gate,
            }
        )
    except Exception as exc:
        logger.debug("swarm learning kernel_memory: %s", exc)

    return os.path.abspath(_PATH)


def recent_learning(limit: int = 30) -> List[Dict[str, Any]]:
    if not os.path.isfile(_PATH):
        return []
    rows = []
    try:
        with open(_PATH, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception:
        return []
    return rows[-limit:]


def learning_stats() -> Dict[str, Any]:
    accepted = len(recent_learning(10_000))
    rejected = 0
    if os.path.isfile(_REJECTED_PATH):
        with open(_REJECTED_PATH, encoding="utf-8") as fh:
            rejected = sum(1 for line in fh if line.strip())
    return {"accepted": accepted, "rejected_poison_or_weak": rejected, "path": _PATH}
