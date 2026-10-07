#!/usr/bin/env python3
"""Orquestador Health Engine — ciclos periódicos sobre telemetría real."""
from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from utils.logger import logger

INTERVAL_SEC = int(os.environ.get("NOVUS_HEALTH_INTERVAL", "45"))

_lock = threading.Lock()
_state: Dict[str, Any] = {
    "active": False,
    "started_at": None,
    "last_cycle_at": None,
    "cycles": 0,
    "last_error": None,
    "last_duration_ms": None,
    "last_overall": None,
}
_thread: Optional[threading.Thread] = None
_stop: Optional[threading.Event] = None


def run_health_orchestrator_cycle(**kwargs) -> Dict[str, Any]:
    from services.health_engine.engine import run_health_cycle

    result = run_health_cycle(**kwargs)
    with _lock:
        _state["cycles"] = int(_state.get("cycles") or 0) + 1
        _state["last_cycle_at"] = result.get("timestamp_utc")
        _state["last_duration_ms"] = result.get("duration_ms")
        _state["last_overall"] = (result.get("summary") or {}).get("overall_status")
        if not result.get("ok"):
            _state["last_error"] = result.get("error")
        else:
            _state["last_error"] = None
    return result


def _loop(stop: threading.Event) -> None:
    # Primer ciclo tras breve espera de boot
    stop.wait(5)
    while not stop.is_set():
        try:
            run_health_orchestrator_cycle(publish=True, self_heal=True, persist=True)
        except Exception as exc:
            logger.warning("health loop: %s", exc)
            with _lock:
                _state["last_error"] = str(exc)[:200]
        stop.wait(INTERVAL_SEC)


def start_health_engine() -> Dict[str, Any]:
    global _thread, _stop
    with _lock:
        if _state.get("active") and _thread and _thread.is_alive():
            return {"status": "already_running", "active": True}
        _stop = threading.Event()
        _thread = threading.Thread(target=_loop, args=(_stop,), daemon=True, name="NovusHealthEngine")
        _state["active"] = True
        _state["started_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        _thread.start()
    logger.info("Health Engine started interval=%ss", INTERVAL_SEC)
    return {"status": "started", "active": True, "interval_sec": INTERVAL_SEC}


def stop_health_engine() -> Dict[str, Any]:
    global _thread, _stop
    with _lock:
        if _stop:
            _stop.set()
        _state["active"] = False
    return {"status": "stopped", "active": False}


def get_health_orchestrator_status() -> Dict[str, Any]:
    with _lock:
        return dict(_state)
