#!/usr/bin/env python3
"""
Self-healing seguro.
NUNCA elimina evidencias forenses ni altera custody chain.
NUNCA ejecuta acciones destructivas sobre datos de usuario.
"""
from __future__ import annotations

import time
import os
from typing import Any, Dict, List, Optional

from services.health_engine.store import record_heal, record_history_event
from utils.logger import logger

# Componentes donde está permitido reiniciar workers internos
HEALABLE = {
    "behavioral_threat_detection",
    "network_protection",
    "endpoint",
    "web_security",
    "kernel_ia",
    "background_workers",
    "database",
    "api_rest",
    "scheduler",
}

FORBIDDEN_ACTIONS = (
    "delete_forensic",
    "purge_evidence",
    "drop_tables",
    "wipe_history",
    "alter_custody",
)


def _safe(action_id: str, fn, component_id: str) -> Dict[str, Any]:
    t0 = time.perf_counter()
    try:
        result = fn()
        entry = {
            "action_id": action_id,
            "component_id": component_id,
            "ok": True,
            "result": result if isinstance(result, dict) else {"detail": str(result)[:300]},
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "destructive": False,
            "forensic_touched": False,
        }
    except Exception as exc:
        logger.warning("health self_heal %s: %s", action_id, exc)
        entry = {
            "action_id": action_id,
            "component_id": component_id,
            "ok": False,
            "error": str(exc)[:300],
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "destructive": False,
            "forensic_touched": False,
        }
    record_heal(entry)
    record_history_event("recovery", component_id, entry)
    return entry


def heal_issue(issue: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    code = issue.get("code")
    cid = issue.get("component_id")
    if cid == "forensic" or code in FORBIDDEN_ACTIONS:
        return {
            "action_id": "skipped_forensic_policy",
            "component_id": cid,
            "ok": False,
            "skipped": True,
            "reason": "Nunca alterar evidencias forenses",
            "destructive": False,
            "forensic_touched": False,
        }

    if cid not in HEALABLE and cid not in ("host", "platform"):
        return {
            "action_id": "no_safe_heal",
            "component_id": cid,
            "ok": False,
            "skipped": True,
            "reason": "Sin acción de recuperación segura definida",
        }

    if code in ("service_down", "worker_stopped", "service_degraded") and cid == "behavioral_threat_detection":
        def _restart_btde():
            from services.lazy_engine_manager import start_engine, stop_engine

            stop_engine("btde")
            return start_engine("btde")

        return _safe("restart_btde_worker", _restart_btde, cid)

    if code in ("service_down", "worker_stopped", "service_degraded") and cid == "network_protection":
        def _restart_nme():
            from services.network_monitor_engine import get_monitor_status, start_network_monitor_engine

            if get_monitor_status().get("active"):
                return {"status": "already_active"}
            return start_network_monitor_engine() or {"status": "started"}

        return _safe("restart_network_monitor", _restart_nme, cid)

    if code in ("service_down", "worker_stopped") and cid == "endpoint":
        def _restart_ep():
            from services.lazy_engine_manager import start_if_needed, is_engine_running

            if is_engine_running("endpoint_realtime"):
                return {"status": "already_active"}
            return start_if_needed("endpoint_realtime")

        return _safe("restart_endpoint_monitor", _restart_ep, cid)

    if code in ("service_down", "service_degraded") and cid == "web_security":
        def _restart_ws():
            from services.web_shield_engine import start_web_shield_engine

            start_web_shield_engine()
            return {"status": "started"}

        return _safe("restart_web_shield", _restart_ws, cid)

    if code in ("service_down", "service_degraded") and cid == "kernel_ia":
        def _restart_kernel():
            from services.ai_kernel import ai_kernel, start_ai_kernel

            if getattr(ai_kernel, "_running", False):
                return {"status": "already_running"}
            start_ai_kernel()
            return {"status": "started"}

        return _safe("restart_ai_kernel", _restart_kernel, cid)

    if code in ("service_down", "db_fail") and cid == "database":
        def _reconnect_db():
            from database import SessionLocal
            from sqlalchemy import text

            db = SessionLocal()
            try:
                db.execute(text("SELECT 1"))
                db.commit()
            finally:
                db.close()
            return {"status": "connection_recreated", "ping": "ok"}

        return _safe("recreate_db_connection", _reconnect_db, cid)

    if code == "queue_saturated":
        def _clear_inmemory_queue():
            # Solo colas en memoria del health/fault inject — nunca borrar evidencias
            from services.health_engine.store import set_fault_inject, load_fault_inject

            fault = load_fault_inject()
            if fault.get("kind") == "queue_saturated" and fault.get("component_id") == cid:
                set_fault_inject(None)
                return {"status": "cleared_fault_inject_queue", "forensic_touched": False}
            return {"status": "no_inmemory_queue_to_clear", "forensic_touched": False}

        return _safe("clear_blocked_inmemory_queue", _clear_inmemory_queue, cid or "platform")

    if code in ("worker_stopped",) and cid == "background_workers":
        worker = (issue.get("metric") or {}).get("worker")
        if worker == "btde":
            return heal_issue({"code": "worker_stopped", "component_id": "behavioral_threat_detection"})
        if worker == "zdde":
            def _restart_zdde():
                from services.lazy_engine_manager import start_engine, stop_engine

                stop_engine("zdde")
                return start_engine("zdde")

            return _safe("restart_zdde_worker", _restart_zdde, cid)
        if worker == "network":
            return heal_issue({"code": "service_down", "component_id": "network_protection"})

    if code == "repetitive_errors" and cid == "api_rest":
        # Liberar recursos leves: forzar GC — no borra datos
        def _release():
            import gc

            n = gc.collect()
            return {"gc_collected": n, "forensic_touched": False}

        return _safe("release_resources_gc", _release, cid)

    return {
        "action_id": "no_safe_heal",
        "component_id": cid,
        "ok": False,
        "skipped": True,
        "reason": f"Sin heal seguro para code={code}",
    }


def run_self_healing(issues: List[Dict[str, Any]], *, enabled: bool = True) -> List[Dict[str, Any]]:
    if not enabled:
        return []
    actions: List[Dict[str, Any]] = []
    seen = set()
    # Limitar a 2 acciones por ciclo para no reiniciar en cascada toda la plataforma
    max_actions = int(os.environ.get("NOVUS_HEALTH_MAX_HEALS_PER_CYCLE", "2"))
    # Priorizar colas / DB antes que reinicios de workers
    priority = {"queue_saturated": 0, "db_fail": 1, "service_down": 2, "worker_stopped": 3, "repetitive_errors": 4}
    ordered = sorted(issues, key=lambda i: priority.get(i.get("code"), 99))
    for iss in ordered:
        if len(actions) >= max_actions:
            break
        key = (iss.get("code"), iss.get("component_id"), str((iss.get("metric") or {}).get("worker")))
        if key in seen:
            continue
        seen.add(key)
        code = iss.get("code")
        if code not in (
            "service_down",
            "worker_stopped",
            "queue_saturated",
            "db_fail",
            "repetitive_errors",
        ):
            continue
        if iss.get("severity") not in ("high", "critical") and code not in ("queue_saturated", "db_fail"):
            continue
        # No reiniciar workers solo porque el probe de background_workers lista ausencias
        if code == "worker_stopped" and iss.get("component_id") == "background_workers":
            # Solo heal puntual del worker nombrado, no cascada
            pass
        act = heal_issue(iss)
        if act and not act.get("skipped"):
            actions.append(act)
        elif act and act.get("action_id") == "clear_blocked_inmemory_queue":
            actions.append(act)
    return actions
