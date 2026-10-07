"""Monitorización continua del endpoint local (procesos, conexiones, ejecutables)."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import psutil

from utils.logger import logger

INTERVAL_SEC = int(os.environ.get("NOVUS_ENDPOINT_MONITOR_INTERVAL", "30"))
_watch_roots: List[str] = []
_state: Dict[str, Any] = {
    "active": False,
    "last_cycle_at": None,
    "last_error": None,
    "events_total": 0,
}
_lock = threading.Lock()
_prev_pids: Set[int] = set()
_prev_conns: Set[str] = set()
_known_exes: Set[str] = set()


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def default_watch_roots() -> List[str]:
    roots = []
    home = os.path.expanduser("~")
    for sub in ("Downloads", "Desktop"):
        p = os.path.join(home, sub)
        if os.path.isdir(p):
            roots.append(os.path.normpath(p))
    temp = os.environ.get("TEMP") or os.path.join(home, "AppData", "Local", "Temp")
    if temp and os.path.isdir(temp):
        roots.append(os.path.normpath(temp))
    return list(dict.fromkeys(roots))[:6]


def set_watch_roots(paths: Optional[List[str]] = None) -> List[str]:
    global _watch_roots
    if paths:
        _watch_roots = [os.path.normpath(p) for p in paths if p and os.path.isdir(p)]
    elif not _watch_roots:
        _watch_roots = default_watch_roots()
    return _watch_roots


def _severity_for_process(name: str, cmdline: str) -> str:
    cl = (cmdline or "").lower()
    if any(x in cl for x in ("mimikatz", "xmrig", "powershell -enc", "downloadstring(")):
        return "critical"
    if name.lower() in ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"):
        return "medium"
    return "low"


def _persist_event(event_type: str, severity: str, detail: dict) -> None:
    from database import SessionLocal, EndpointMonitorEvent

    ts = _now()
    with _lock:
        _state["events_total"] = int(_state.get("events_total") or 0) + 1
    db = SessionLocal()
    try:
        db.add(
            EndpointMonitorEvent(
                event_type=event_type,
                severity=severity,
                detail_json=json.dumps({**detail, "verified": True, "host": socket.gethostname()}, ensure_ascii=False),
                timestamp=ts,
            )
        )
        db.commit()
    except Exception as exc:
        logger.debug("endpoint monitor persist: %s", exc)
    finally:
        db.close()
    evidence_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "endpoint_scan")
    os.makedirs(evidence_dir, exist_ok=True)
    try:
        with open(os.path.join(evidence_dir, "monitor_events.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"timestamp": ts, "type": event_type, "severity": severity, **detail}, ensure_ascii=False) + "\n")
    except Exception:
        pass
    # Publicar a Swarm/Forense/APE solo severidad media+
    if (severity or "").lower() in ("medium", "high", "critical"):
        try:
            from services.network_endpoint_enterprise.publish import publish_event

            publish_event(
                motor="endpoint_realtime_monitor",
                action=f"endpoint_{event_type}",
                evidence={**detail, "event_type": event_type, "severity": severity, "verified": True},
                threat_type=event_type,
                confidence="medium",
                detail=f"endpoint monitor: {event_type}",
                finding_id=f"EPM-{event_type}-{abs(hash(str(detail))) % 10**10}",
                feed_ape=(severity or "").lower() == "medium",
                risk_level=severity,
            )
        except Exception as exc:
            logger.debug("endpoint swarm publish: %s", exc)


def run_monitor_cycle() -> dict:
    global _prev_pids, _prev_conns, _known_exes
    set_watch_roots()
    stats = {"new_processes": 0, "new_connections": 0, "new_executables": 0}
    try:
        procs = {}
        for p in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
            try:
                info = p.info
                procs[info["pid"]] = info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        current_pids = set(procs.keys())
        for pid in current_pids - _prev_pids:
            if not _prev_pids:
                continue
            info = procs.get(pid) or {}
            name = info.get("name") or "unknown"
            cmd = " ".join(info.get("cmdline") or [])[:500]
            sev = _severity_for_process(name, cmd)
            _persist_event(
                "new_process",
                sev,
                {"pid": pid, "name": name, "cmdline": cmd},
            )
            stats["new_processes"] += 1
        _prev_pids = current_pids

        conn_keys = set()
        for c in psutil.net_connections(kind="inet"):
            if c.status != psutil.CONN_ESTABLISHED:
                continue
            key = f"{c.laddr.ip}:{c.laddr.port}->{getattr(c.raddr, 'ip', '')}:{getattr(c.raddr, 'port', '')}"
            conn_keys.add(key)
        for key in conn_keys - _prev_conns:
            if not _prev_conns:
                continue
            _persist_event("new_connection", "low", {"connection": key})
            stats["new_connections"] += 1
        _prev_conns = conn_keys

        for root in _watch_roots:
            if not os.path.isdir(root):
                continue
            try:
                for entry in os.scandir(root):
                    if not entry.is_file():
                        continue
                    if not entry.name.lower().endswith((".exe", ".dll", ".scr", ".bat", ".ps1")):
                        continue
                    fp = entry.path
                    if fp in _known_exes:
                        continue
                    if _known_exes:
                        _persist_event("new_executable", "medium", {"path": fp, "root": root})
                        stats["new_executables"] += 1
                    _known_exes.add(fp)
            except (PermissionError, OSError):
                continue

        with _lock:
            _state["last_cycle_at"] = _now()
            _state["last_error"] = None
    except Exception as exc:
        with _lock:
            _state["last_error"] = str(exc)
        logger.warning("endpoint monitor cycle: %s", exc)
    return stats


def _loop(stop_event: threading.Event) -> None:
    with _lock:
        _state["active"] = True
    while not stop_event.is_set():
        run_monitor_cycle()
        stop_event.wait(INTERVAL_SEC)
    with _lock:
        _state["active"] = False


_stop_event: Optional[threading.Event] = None
_thread: Optional[threading.Thread] = None


def start_endpoint_realtime_monitor() -> dict:
    global _stop_event, _thread
    if _thread and _thread.is_alive():
        return {"status": "already_running", **_state}
    set_watch_roots()
    _stop_event = threading.Event()
    _thread = threading.Thread(target=_loop, args=(_stop_event,), daemon=True, name="EndpointRealtimeMonitor")
    _thread.start()
    logger.info("Endpoint Realtime Monitor iniciado (intervalo %ss)", INTERVAL_SEC)
    return {"status": "started", "interval_sec": INTERVAL_SEC, "watch_roots": _watch_roots}


def stop_endpoint_realtime_monitor() -> dict:
    global _stop_event, _thread
    if _stop_event:
        _stop_event.set()
    if _thread:
        _thread.join(timeout=8)
        _thread = None
    with _lock:
        _state["active"] = False
    return {"status": "stopped", **_state}


def get_monitor_status() -> dict:
    with _lock:
        return {
            "active": _state.get("active"),
            "last_cycle_at": _state.get("last_cycle_at"),
            "last_error": _state.get("last_error"),
            "events_total": _state.get("events_total"),
            "interval_sec": INTERVAL_SEC,
            "watch_roots": list(_watch_roots or default_watch_roots()),
        }


def list_monitor_events(limit: int = 50) -> List[dict]:
    from database import SessionLocal, EndpointMonitorEvent

    db = SessionLocal()
    try:
        rows = (
            db.query(EndpointMonitorEvent)
            .order_by(EndpointMonitorEvent.id.desc())
            .limit(min(limit, 200))
            .all()
        )
        out = []
        for r in rows:
            try:
                detail = json.loads(r.detail_json or "{}")
            except json.JSONDecodeError:
                detail = {}
            out.append(
                {
                    "event_type": r.event_type,
                    "severity": r.severity,
                    "timestamp": r.timestamp,
                    "detail": detail,
                }
            )
        return out
    finally:
        db.close()
