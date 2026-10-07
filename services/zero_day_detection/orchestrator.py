#!/usr/bin/env python3
"""Orquestador ZDDE — ciclos periódicos no destructivos."""
from __future__ import annotations

import os
import threading
from typing import Any, Dict, Optional

from utils.logger import logger

INTERVAL_SEC = int(os.environ.get("NOVUS_ZDDE_INTERVAL", "120"))
HEAVY_EVERY_N = 5

_lock = threading.Lock()
_state: Dict[str, Any] = {
    "active": False,
    "started_at": None,
    "last_cycle_at": None,
    "cycles": 0,
    "last_error": None,
    "last_classification": None,
    "last_risk": None,
    "last_duration_ms": None,
}
_thread: Optional[threading.Thread] = None
_stop: Optional[threading.Event] = None


def run_zdde_orchestrator_cycle(*, force_heavy: bool = False) -> Dict[str, Any]:
    from services.zero_day_detection.engine import run_zdde_cycle

    with _lock:
        cycle_n = int(_state.get("cycles") or 0) + 1
        heavy = force_heavy or (cycle_n % HEAVY_EVERY_N == 0)
    result = run_zdde_cycle(heavy=heavy, publish=True)
    with _lock:
        _state["cycles"] = cycle_n
        _state["last_cycle_at"] = result.get("timestamp_utc")
        _state["last_classification"] = result.get("classification")
        _state["last_risk"] = result.get("risk")
        _state["last_duration_ms"] = result.get("duration_ms")
        if not result.get("ok"):
            _state["last_error"] = result.get("error")
        else:
            _state["last_error"] = None
    return result


def _loop(stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            run_zdde_orchestrator_cycle()
        except Exception as exc:
            logger.warning("zdde loop: %s", exc)
            with _lock:
                _state["last_error"] = str(exc)[:200]
        stop.wait(INTERVAL_SEC)


def start_zdde() -> Dict[str, Any]:
    """Start background loop. Does not block on first cycle (avoids stalling boot under RAM pressure).

    Honesty: callers must treat cycles==0 / missing last_cycle_at as IDLE, not ACTIVE.
    """
    global _thread, _stop
    with _lock:
        if _state.get("active") and _thread and _thread.is_alive():
            return {
                "status": "already_running",
                "active": True,
                "cycles": _state.get("cycles"),
                "last_cycle_at": _state.get("last_cycle_at"),
            }
        _stop = threading.Event()
        _thread = threading.Thread(target=_loop, args=(_stop,), daemon=True, name="NovusZDDE")
        _state["active"] = True
        from datetime import datetime, timezone

        _state["started_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        _thread.start()
    logger.info("ZDDE started interval=%ss", INTERVAL_SEC)
    return {"status": "started", "active": True, "interval_sec": INTERVAL_SEC}


def stop_zdde() -> Dict[str, Any]:
    global _thread, _stop
    with _lock:
        if _stop:
            _stop.set()
        _state["active"] = False
    return {"status": "stopped", "active": False}


def get_zdde_orchestrator_status() -> Dict[str, Any]:
    with _lock:
        st = dict(_state)
    # Honest runtime label for consumers (flag alone is not evidence of a completed cycle).
    if st.get("active") and int(st.get("cycles") or 0) > 0 and st.get("last_cycle_at"):
        st["runtime_label"] = "ACTIVE"
    elif st.get("active"):
        st["runtime_label"] = "IDLE"
    else:
        st["runtime_label"] = "IDLE"
    return st
