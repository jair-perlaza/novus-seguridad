"""Orquestador BTDE — ciclos ligeros periódicos."""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict, Optional

from utils.logger import logger

INTERVAL_SEC = int(os.environ.get("NOVUS_BTDE_INTERVAL", "90"))
HEAVY_EVERY_N = 4

_lock = threading.Lock()
_state: Dict[str, Any] = {
    "active": False,
    "started_at": None,
    "last_cycle_at": None,
    "cycles": 0,
    "last_error": None,
    "last_published": 0,
    "last_duration_ms": None,
    "last_risk": None,
}
_thread: Optional[threading.Thread] = None
_stop: Optional[threading.Event] = None


def run_btde_orchestrator_cycle(*, force_heavy: bool = False) -> Dict[str, Any]:
    from services.behavioral_threat_detection.engine import run_btde_cycle

    with _lock:
        cycle_n = int(_state.get("cycles") or 0) + 1
        heavy = force_heavy or (cycle_n % HEAVY_EVERY_N == 0)
    result = run_btde_cycle(heavy=heavy, publish=True)
    with _lock:
        _state["cycles"] = cycle_n
        _state["last_cycle_at"] = result.get("timestamp_utc")
        _state["last_published"] = result.get("published")
        _state["last_duration_ms"] = result.get("duration_ms")
        _state["last_risk"] = (result.get("correlation") or {}).get("risk")
        if not result.get("ok"):
            _state["last_error"] = result.get("error")
        else:
            _state["last_error"] = None
    return result


def _loop(stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            run_btde_orchestrator_cycle()
        except Exception as exc:
            logger.warning("btde loop: %s", exc)
            with _lock:
                _state["last_error"] = str(exc)[:200]
        stop.wait(INTERVAL_SEC)


def start_btde() -> Dict[str, Any]:
    global _thread, _stop
    with _lock:
        if _state.get("active") and _thread and _thread.is_alive():
            return {"status": "already_running", "active": True}
        _stop = threading.Event()
        _thread = threading.Thread(target=_loop, args=(_stop,), daemon=True, name="NovusBTDE")
        _state["active"] = True
        from datetime import datetime, timezone

        _state["started_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        _thread.start()
    logger.info("BTDE started interval=%ss", INTERVAL_SEC)
    return {"status": "started", "active": True, "interval_sec": INTERVAL_SEC}


def stop_btde() -> Dict[str, Any]:
    global _thread, _stop
    with _lock:
        if _stop:
            _stop.set()
        _state["active"] = False
    return {"status": "stopped", "active": False}


def get_btde_orchestrator_status() -> Dict[str, Any]:
    with _lock:
        st = dict(_state)
    from services.behavioral_threat_detection.engine import get_btde_status

    st["engine"] = get_btde_status()
    return st
