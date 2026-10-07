"""
Lazy start manager for P2 heavy engines — single logical instance per process.
Non-blocking HTTP: start_if_needed returns STARTING immediately.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from utils.logger import logger

STATE_AVAILABLE = "AVAILABLE"
STATE_STARTING = "STARTING"
STATE_RUNNING = "RUNNING"
STATE_STOPPED = "STOPPED"
STATE_DEGRADED = "DEGRADED"
STATE_ERROR = "ERROR"

CAT_LAZY_P2 = "lazy_p2_heavy"
STARTUP_TIMEOUT_SEC = float(os.environ.get("NOVUS_LAZY_START_TIMEOUT_SEC", "120"))

_registry_lock = threading.Lock()
_engines: Dict[str, Dict[str, Any]] = {}
_initialized = False


def _utc_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_thread_alive(name: str) -> bool:
    rec = _engines.get(name)
    if not rec:
        return False
    th = rec.get("_start_thread")
    return bool(th and th.is_alive())


def _live_status(name: str) -> Dict[str, Any]:
    rec = _engines.get(name)
    if not rec:
        return {"active": False}
    try:
        return dict(rec["status_fn"]() or {})
    except Exception as exc:
        return {"active": False, "error": str(exc)[:200]}


def _engine_is_running(name: str) -> bool:
    live = _live_status(name)
    if live.get("active") is True:
        return True
    if live.get("running") is True:
        return True
    st = str(live.get("status") or "").lower()
    return st in ("started", "already_running", "running")


def _starter_endpoint_realtime() -> Dict[str, Any]:
    from services.endpoint_realtime_monitor import start_endpoint_realtime_monitor

    return start_endpoint_realtime_monitor()


def _starter_endpoint_enterprise() -> Dict[str, Any]:
    from services.endpoint_enterprise import start_endpoint_enterprise

    return start_endpoint_enterprise()


def _starter_network_endpoint_enterprise() -> Dict[str, Any]:
    from services.network_endpoint_enterprise import start_enterprise_sensor

    return start_enterprise_sensor()


def _starter_btde() -> Dict[str, Any]:
    from services.behavioral_threat_detection import start_btde

    return start_btde()


def _starter_zdde() -> Dict[str, Any]:
    from services.zero_day_detection import start_zdde

    return start_zdde()


def _starter_health_engine() -> Dict[str, Any]:
    from services.health_engine import start_health_engine

    return start_health_engine()


_defense_stack_live = {"active": False}
_forensic_pcap_live = {"active": False}
_enterprise_warmup_live = {"active": False}


def _starter_defense_stack() -> Dict[str, Any]:
    from services.startup_defense_service import initialize_defense_stack

    result = initialize_defense_stack()
    _defense_stack_live["active"] = True
    return result


def _starter_forensic_pcap() -> Dict[str, Any]:
    from services.forensic_pcap_capture_service import ensure_metadata_monitor

    ensure_metadata_monitor()
    _forensic_pcap_live["active"] = True
    return {"status": "started"}


def _starter_enterprise_warmup() -> Dict[str, Any]:
    from services.enterprise_snapshot_service import schedule_all_enterprise_warmup

    schedule_all_enterprise_warmup()
    _enterprise_warmup_live["active"] = True
    return {"status": "scheduled"}


def _stop_endpoint_realtime() -> Dict[str, Any]:
    from services.endpoint_realtime_monitor import stop_endpoint_realtime_monitor

    return stop_endpoint_realtime_monitor()


def _stop_endpoint_enterprise() -> Dict[str, Any]:
    from services.endpoint_enterprise import stop_endpoint_enterprise

    return stop_endpoint_enterprise()


def _stop_network_endpoint_enterprise() -> Dict[str, Any]:
    from services.network_endpoint_enterprise import stop_enterprise_sensor

    return stop_enterprise_sensor()


def _stop_btde() -> Dict[str, Any]:
    from services.behavioral_threat_detection import stop_btde

    return stop_btde()


def _stop_zdde() -> Dict[str, Any]:
    from services.zero_day_detection import stop_zdde

    return stop_zdde()


def _stop_health_engine() -> Dict[str, Any]:
    from services.health_engine import stop_health_engine

    return stop_health_engine()


def _status_endpoint_realtime() -> Dict[str, Any]:
    from services.endpoint_realtime_monitor import get_monitor_status

    return get_monitor_status()


def _status_endpoint_enterprise() -> Dict[str, Any]:
    from services.endpoint_enterprise import get_endpoint_enterprise_status

    return get_endpoint_enterprise_status()


def _status_network_endpoint_enterprise() -> Dict[str, Any]:
    from services.network_endpoint_enterprise import get_enterprise_status

    return get_enterprise_status()


def _status_btde() -> Dict[str, Any]:
    from services.behavioral_threat_detection import get_btde_orchestrator_status

    return get_btde_orchestrator_status()


def _status_zdde() -> Dict[str, Any]:
    from services.zero_day_detection import get_zdde_orchestrator_status

    return get_zdde_orchestrator_status()


def _status_health_engine() -> Dict[str, Any]:
    from services.health_engine import get_health_orchestrator_status

    return get_health_orchestrator_status()


def _ensure_registry() -> None:
    global _initialized
    with _registry_lock:
        if _initialized:
            return
        _initialized = True

        def _rec(
            name: str,
            *,
            start_fn: Callable[[], Dict[str, Any]],
            status_fn: Callable[[], Dict[str, Any]],
            stop_fn: Optional[Callable[[], Dict[str, Any]]] = None,
            priority: str = "P2",
            group: Optional[str] = None,
        ) -> None:
            _engines[name] = {
                "name": name,
                "priority": priority,
                "group": group,
                "state": STATE_AVAILABLE,
                "error": None,
                "started_at": None,
                "last_start_result": None,
                "start_fn": start_fn,
                "stop_fn": stop_fn,
                "status_fn": status_fn,
                "lock": threading.Lock(),
                "_start_thread": None,
            }

        _rec("endpoint_realtime", start_fn=_starter_endpoint_realtime, status_fn=_status_endpoint_realtime, stop_fn=_stop_endpoint_realtime, group="endpoint")
        _rec("endpoint_enterprise", start_fn=_starter_endpoint_enterprise, status_fn=_status_endpoint_enterprise, stop_fn=_stop_endpoint_enterprise, group="endpoint")
        _rec(
            "network_endpoint_enterprise",
            start_fn=_starter_network_endpoint_enterprise,
            status_fn=_status_network_endpoint_enterprise,
            stop_fn=_stop_network_endpoint_enterprise,
            group="endpoint",
        )
        _rec("btde", start_fn=_starter_btde, status_fn=_status_btde, stop_fn=_stop_btde)
        _rec("zdde", start_fn=_starter_zdde, status_fn=_status_zdde, stop_fn=_stop_zdde)
        _rec("health_engine", start_fn=_starter_health_engine, status_fn=_status_health_engine, stop_fn=_stop_health_engine)
        _rec(
            "defense_stack",
            start_fn=_starter_defense_stack,
            status_fn=lambda: dict(_defense_stack_live),
        )
        _rec(
            "forensic_pcap",
            start_fn=_starter_forensic_pcap,
            status_fn=lambda: dict(_forensic_pcap_live),
        )
        _rec(
            "enterprise_warmup",
            start_fn=_starter_enterprise_warmup,
            status_fn=lambda: dict(_enterprise_warmup_live),
        )


def _backpressure_blocks_start() -> tuple[bool, str]:
    from services.resource_backpressure_service import get_backpressure_level, should_run_background

    if not should_run_background(CAT_LAZY_P2):
        level = get_backpressure_level()
        return True, f"RAM backpressure level={level}"
    return False, ""


def _set_state(name: str, state: str, *, error: Optional[str] = None, result: Optional[Dict[str, Any]] = None) -> None:
    rec = _engines[name]
    rec["state"] = state
    if error is not None:
        rec["error"] = error
    if result is not None:
        rec["last_start_result"] = result
    if state == STATE_RUNNING:
        rec["started_at"] = time.time()
    elif state in (STATE_AVAILABLE, STATE_STOPPED):
        rec["started_at"] = None


def _run_start(name: str) -> None:
    rec = _engines[name]
    started = time.time()
    try:
        result = rec["start_fn"]()
        rec["last_start_result"] = result
        deadline = started + STARTUP_TIMEOUT_SEC
        while time.time() < deadline:
            if _engine_is_running(name):
                _set_state(name, STATE_RUNNING, result=result)
                logger.info("Lazy engine %s → RUNNING", name)
                return
            time.sleep(0.5)
        _set_state(name, STATE_ERROR, error=f"startup_timeout_{STARTUP_TIMEOUT_SEC}s", result=result)
        if rec.get("stop_fn"):
            try:
                rec["stop_fn"]()
            except Exception as stop_exc:
                logger.debug("lazy rollback stop %s: %s", name, stop_exc)
        _set_state(name, STATE_ERROR, error=f"startup_timeout_{STARTUP_TIMEOUT_SEC}s")
    except Exception as exc:
        logger.error("Lazy engine %s start failed: %s", name, exc, exc_info=True)
        _set_state(name, STATE_ERROR, error=str(exc)[:300])
        if rec.get("stop_fn"):
            try:
                rec["stop_fn"]()
            except Exception:
                pass


def _start_async_locked(name: str) -> Dict[str, Any]:
    _ensure_registry()
    if name not in _engines:
        return {"engine": name, "state": STATE_ERROR, "error": "unknown_engine"}

    rec = _engines[name]
    with rec["lock"]:
        if _engine_is_running(name):
            _set_state(name, STATE_RUNNING)
            return engine_status(name)

        if rec["state"] == STATE_STARTING and _is_thread_alive(name):
            return engine_status(name)

        blocked, reason = _backpressure_blocks_start()
        if blocked:
            _set_state(name, STATE_DEGRADED, error=reason)
            return engine_status(name)

        _set_state(name, STATE_STARTING, error=None)

        def _worker() -> None:
            try:
                _run_start(name)
            finally:
                rec["_start_thread"] = None

        th = threading.Thread(target=_worker, daemon=True, name=f"LazyStart-{name}")
        rec["_start_thread"] = th
        th.start()

    return engine_status(name)


def start_engine(name: str) -> Dict[str, Any]:
    """Inicia motor (async). Devuelve de inmediato con STARTING o estado actual."""
    return _start_async_locked(name)


def start_if_needed(name: str) -> Dict[str, Any]:
    """Alias semántico — no bloquea HTTP."""
    _ensure_registry()
    try:
        from services.cloud_runtime_service import may_start_engine

        if not may_start_engine(name):
            return {
                "engine": name,
                "state": STATE_STOPPED,
                "engine_running": False,
                "skipped": True,
                "reason": "cloud_runtime_client_node_only",
                "observed_at": _utc_iso(),
            }
    except Exception:
        pass
    if name == "endpoint":
        return start_endpoint_group()
    status = engine_status(name)
    if status.get("state") == STATE_RUNNING:
        return status
    if status.get("state") == STATE_STARTING:
        return status
    return start_engine(name)


def start_endpoint_group() -> Dict[str, Any]:
    """Grupo Endpoint: realtime + enterprise + network sensor."""
    _ensure_registry()
    names = ["endpoint_realtime", "endpoint_enterprise", "network_endpoint_enterprise"]
    blocked, reason = _backpressure_blocks_start()
    if blocked:
        for n in names:
            _set_state(n, STATE_DEGRADED, error=reason)
        return {
            "engine": "endpoint",
            "state": STATE_DEGRADED,
            "engine_running": False,
            "members": {n: _single_engine_status(n) for n in names},
            "error": reason,
            "observed_at": _utc_iso(),
        }

    results: Dict[str, Dict[str, Any]] = {}
    any_starting = False
    all_running = True
    for n in names:
        st = _single_engine_status(n)
        if st.get("state") != STATE_RUNNING:
            all_running = False
        if st.get("state") == STATE_STARTING:
            any_starting = True
        elif st.get("state") != STATE_RUNNING:
            results[n] = start_engine(n)
            if results[n].get("state") == STATE_STARTING:
                any_starting = True
            if results[n].get("state") != STATE_RUNNING:
                all_running = False
        else:
            results[n] = st

    group_state = STATE_RUNNING if all_running else (STATE_STARTING if any_starting else STATE_AVAILABLE)
    return {
        "engine": "endpoint",
        "state": group_state,
        "engine_running": all_running,
        "members": {n: _single_engine_status(n) for n in names},
        "observed_at": _utc_iso(),
    }


def stop_engine(name: str) -> Dict[str, Any]:
    _ensure_registry()
    if name not in _engines:
        return {"engine": name, "state": STATE_ERROR, "error": "unknown_engine"}
    rec = _engines[name]
    with rec["lock"]:
        if rec.get("stop_fn"):
            try:
                rec["stop_fn"]()
            except Exception as exc:
                _set_state(name, STATE_ERROR, error=str(exc)[:200])
                return engine_status(name)
        else:
            # Motores sin stop explícito: marcar STOPPED
            pass
        _set_state(name, STATE_STOPPED)
        rec["_start_thread"] = None
    return engine_status(name)


def _single_engine_status(name: str) -> Dict[str, Any]:
    if name not in _engines:
        return {"engine": name, "state": STATE_ERROR, "error": "unknown_engine", "engine_running": False}

    rec = _engines[name]
    live = _live_status(name)
    running = _engine_is_running(name)
    state = rec["state"]
    if running and state != STATE_ERROR:
        state = STATE_RUNNING
    elif state == STATE_STARTING and not _is_thread_alive(name) and not running:
        state = STATE_ERROR if rec.get("error") else STATE_AVAILABLE

    return {
        "engine": name,
        "state": state,
        "engine_running": running,
        "priority": rec["priority"],
        "group": rec.get("group"),
        "started_at": rec.get("started_at"),
        "error": rec.get("error"),
        "live": live,
        "last_start_result": rec.get("last_start_result"),
        "observed_at": _utc_iso(),
    }


def _endpoint_group_status() -> Dict[str, Any]:
    names = ["endpoint_realtime", "endpoint_enterprise", "network_endpoint_enterprise"]
    members = {n: _single_engine_status(n) for n in names}
    all_running = all(m.get("engine_running") for m in members.values())
    any_starting = any(m.get("state") == STATE_STARTING for m in members.values())
    any_error = any(m.get("state") == STATE_ERROR for m in members.values())
    any_degraded = any(m.get("state") == STATE_DEGRADED for m in members.values())
    if all_running:
        gstate = STATE_RUNNING
    elif any_starting:
        gstate = STATE_STARTING
    elif any_error:
        gstate = STATE_ERROR
    elif any_degraded:
        gstate = STATE_DEGRADED
    else:
        gstate = STATE_AVAILABLE
    return {
        "engine": "endpoint",
        "state": gstate,
        "engine_running": all_running,
        "members": members,
        "observed_at": _utc_iso(),
    }


def engine_status(name: str) -> Dict[str, Any]:
    _ensure_registry()
    if name == "endpoint":
        return _endpoint_group_status()
    return _single_engine_status(name)


def is_engine_running(name: str) -> bool:
    _ensure_registry()
    if name == "endpoint":
        return all(is_engine_running(n) for n in ("endpoint_realtime", "endpoint_enterprise"))
    if name not in _engines:
        return False
    st = _single_engine_status(name)
    return st.get("state") == STATE_RUNNING or st.get("engine_running") is True


def list_engine_statuses(*, priority: Optional[str] = None) -> Dict[str, Any]:
    _ensure_registry()
    out: Dict[str, Any] = {}
    for name in sorted(_engines.keys()):
        st = engine_status(name)
        if priority and st.get("priority") != priority:
            continue
        out[name] = st
    out["endpoint"] = _endpoint_group_status()
    p2_pending = [
        n
        for n, st in out.items()
        if n != "endpoint" and st.get("priority") == "P2" and not st.get("engine_running")
    ]
    return {
        "engines": out,
        "p2_pending": p2_pending,
        "observed_at": _utc_iso(),
    }


def lazy_start_hook(module: str) -> Dict[str, Any]:
    """Mapa módulo UI → motor lazy."""
    mapping = {
        "endpoint": "endpoint",
        "endpoints": "endpoint",
        "btde": "btde",
        "zdde": "zdde",
        "health": "health_engine",
        "health_engine": "health_engine",
        "health-center": "health_engine",
        "xdr": "defense_stack",
        "forensics": "forensic_pcap",
        "enterprise": "enterprise_warmup",
    }
    target = mapping.get(module, module)
    return start_if_needed(target)
