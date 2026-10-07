"""
Telemetría verificable de motores de defensa — Dashboard / monitoreo.
Solo registra eventos reales (inicio/fin/error). Nunca inventa progreso.
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from utils.logger import logger

_LOCK = threading.RLock()
_DIR = os.path.join("data", "motor_telemetry")
_JSONL = os.path.join(_DIR, "events.jsonl")
_active: Dict[str, Dict[str, Any]] = {}  # key = session_id:motor_id
_session_events: Dict[str, List[Dict[str, Any]]] = {}
_subscribers: List[Any] = []  # threading.Event + queue pairs for SSE wake


_MAX_SESSIONS_IN_MEMORY = 24


def _prune_session_events() -> None:
    if len(_session_events) <= _MAX_SESSIONS_IN_MEMORY:
        return
    keys = sorted(_session_events.keys(), key=lambda k: len(_session_events[k]))
    for k in keys[: max(0, len(_session_events) - _MAX_SESSIONS_IN_MEMORY)]:
        _session_events.pop(k, None)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure() -> None:
    os.makedirs(_DIR, exist_ok=True)


def _persist(entry: Dict[str, Any]) -> None:
    _ensure()
    try:
        with open(_JSONL, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.warning("motor_telemetry jsonl: %s", exc)

    try:
        from database import SessionLocal, registrar_log_seguridad

        db = SessionLocal()
        try:
            registrar_log_seguridad(
                db,
                f"MOTOR_TELEMETRY_{entry.get('status', 'EVENT')}".upper()[:80],
                json.dumps(
                    {
                        "event_id": entry.get("event_id"),
                        "session_id": entry.get("session_id"),
                        "motor_id": entry.get("motor_id"),
                        "motor_label": entry.get("motor_label"),
                        "status": entry.get("status"),
                        "started_at": entry.get("started_at"),
                        "finished_at": entry.get("finished_at"),
                        "duration_sec": entry.get("duration_sec"),
                        "elements_analyzed": entry.get("elements_analyzed"),
                        "result": entry.get("result"),
                        "evidence": entry.get("evidence"),
                        "errors": entry.get("errors"),
                        "progress_pct_at_event": entry.get("progress_pct_at_event"),
                    },
                    ensure_ascii=False,
                )[:4000],
            )
            db.commit()
        finally:
            db.close()
    except Exception as exc:
        logger.debug("motor_telemetry db: %s", exc)

    try:
        from database import SessionLocal, MotorTelemetryEvent

        db = SessionLocal()
        try:
            row = MotorTelemetryEvent(
                event_id=entry.get("event_id"),
                session_id=entry.get("session_id") or "",
                motor_id=entry.get("motor_id") or "",
                motor_label=entry.get("motor_label") or "",
                status=entry.get("status") or "",
                started_at=entry.get("started_at"),
                finished_at=entry.get("finished_at"),
                duration_sec=entry.get("duration_sec"),
                elements_analyzed=json.dumps(entry.get("elements_analyzed") or {}, ensure_ascii=False),
                result=str(entry.get("result") or "")[:500],
                evidence_json=json.dumps(entry.get("evidence") or {}, ensure_ascii=False),
                errors_json=json.dumps(entry.get("errors") or [], ensure_ascii=False),
                progress_pct=entry.get("progress_pct_at_event"),
                created_at=entry.get("recorded_at") or _utc_now(),
            )
            db.add(row)
            db.commit()
        finally:
            db.close()
    except Exception as exc:
        logger.debug("motor_telemetry ORM: %s", exc)

    status = str(entry.get("status") or "").lower()
    if status in ("error", "failed", "fault", "critical"):
        try:
            from services.email_delivery_service import send_to_ceo

            send_to_ceo(
                subject=f"[NOVUS] Telemetría motor — {entry.get('motor_id', 'motor')}",
                body=json.dumps(entry, ensure_ascii=False, indent=2)[:6000],
                category="motor_telemetry",
            )
        except Exception as mail_exc:
            logger.debug("CEO motor telemetry: %s", mail_exc)


def _notify() -> None:
    with _LOCK:
        subs = list(_subscribers)
    for ev in subs:
        try:
            ev.set()
        except Exception:
            pass


def register_wake_event(ev: threading.Event) -> None:
    with _LOCK:
        _subscribers.append(ev)


def unregister_wake_event(ev: threading.Event) -> None:
    with _LOCK:
        if ev in _subscribers:
            _subscribers.remove(ev)


def motor_start(
    *,
    session_id: str,
    motor_id: str,
    motor_label: str,
    activity: str = "",
    evidence: Optional[dict] = None,
) -> Dict[str, Any]:
    key = f"{session_id}:{motor_id}"
    entry = {
        "event_id": f"MT-{uuid.uuid4().hex[:12]}",
        "session_id": session_id,
        "motor_id": motor_id,
        "motor_label": motor_label,
        "status": "running",
        "started_at": _utc_now(),
        "finished_at": None,
        "duration_sec": None,
        "elements_analyzed": {},
        "result": None,
        "evidence": evidence or {},
        "errors": [],
        "activity": activity or f"Ejecutando {motor_label}",
        "recorded_at": _utc_now(),
        "progress_pct_at_event": None,
    }
    with _LOCK:
        _active[key] = {**entry, "_t0": time.time()}
        _session_events.setdefault(session_id, []).append(entry)
        if len(_session_events[session_id]) > 200:
            _session_events[session_id] = _session_events[session_id][-200:]
        _prune_session_events()
    _persist(entry)
    _notify()
    return entry


def motor_complete(
    *,
    session_id: str,
    motor_id: str,
    motor_label: Optional[str] = None,
    elements_analyzed: Optional[dict] = None,
    result: str = "ok",
    evidence: Optional[dict] = None,
    errors: Optional[list] = None,
    progress_pct: Optional[int] = None,
) -> Dict[str, Any]:
    key = f"{session_id}:{motor_id}"
    with _LOCK:
        prev = _active.pop(key, None)
    started = (prev or {}).get("started_at") or _utc_now()
    t0 = (prev or {}).get("_t0")
    duration = round(time.time() - t0, 3) if t0 else None
    entry = {
        "event_id": f"MT-{uuid.uuid4().hex[:12]}",
        "session_id": session_id,
        "motor_id": motor_id,
        "motor_label": motor_label or (prev or {}).get("motor_label") or motor_id,
        "status": "completed",
        "started_at": started,
        "finished_at": _utc_now(),
        "duration_sec": duration,
        "elements_analyzed": elements_analyzed or {},
        "result": result,
        "evidence": evidence or {},
        "errors": errors or [],
        "activity": None,
        "recorded_at": _utc_now(),
        "progress_pct_at_event": progress_pct,
    }
    with _LOCK:
        _session_events.setdefault(session_id, []).append(entry)
        _prune_session_events()
    _persist(entry)
    _notify()
    return entry


def motor_fail(
    *,
    session_id: str,
    motor_id: str,
    motor_label: Optional[str] = None,
    error: str,
    elements_analyzed: Optional[dict] = None,
    evidence: Optional[dict] = None,
    progress_pct: Optional[int] = None,
) -> Dict[str, Any]:
    key = f"{session_id}:{motor_id}"
    with _LOCK:
        prev = _active.pop(key, None)
    started = (prev or {}).get("started_at") or _utc_now()
    t0 = (prev or {}).get("_t0")
    duration = round(time.time() - t0, 3) if t0 else None
    entry = {
        "event_id": f"MT-{uuid.uuid4().hex[:12]}",
        "session_id": session_id,
        "motor_id": motor_id,
        "motor_label": motor_label or (prev or {}).get("motor_label") or motor_id,
        "status": "failed",
        "started_at": started,
        "finished_at": _utc_now(),
        "duration_sec": duration,
        "elements_analyzed": elements_analyzed or {},
        "result": "error",
        "evidence": evidence or {},
        "errors": [str(error)[:500]],
        "activity": None,
        "recorded_at": _utc_now(),
        "progress_pct_at_event": progress_pct,
    }
    with _LOCK:
        _session_events.setdefault(session_id, []).append(entry)
        _prune_session_events()
    _persist(entry)
    _notify()
    return entry


def motor_heartbeat(
    *,
    session_id: str,
    motor_id: str,
    elements_processed: Optional[int] = None,
    activity: Optional[str] = None,
    speed_per_sec: Optional[float] = None,
    eta_sec: Optional[float] = None,
) -> Optional[Dict[str, Any]]:
    """Actualiza actividad de un motor en ejecución — sin inventar % global."""
    key = f"{session_id}:{motor_id}"
    with _LOCK:
        cur = _active.get(key)
        if not cur:
            return None
        if elements_processed is not None:
            cur.setdefault("elements_analyzed", {})["processed"] = elements_processed
        if activity:
            cur["activity"] = activity
        if speed_per_sec is not None:
            cur["speed_per_sec"] = speed_per_sec
        if eta_sec is not None:
            cur["eta_sec"] = eta_sec
        cur["heartbeat_at"] = _utc_now()
        snap = dict(cur)
        snap.pop("_t0", None)
    _notify()
    return snap


def list_session_events(session_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    with _LOCK:
        rows = list(_session_events.get(session_id) or [])
        active = [
            {k: v for k, v in e.items() if k != "_t0"}
            for key, e in _active.items()
            if key.startswith(f"{session_id}:")
        ]
    return (rows + active)[-limit:]


def active_motors(session_id: str) -> List[Dict[str, Any]]:
    with _LOCK:
        out = []
        for key, e in _active.items():
            if key.startswith(f"{session_id}:"):
                snap = {k: v for k, v in e.items() if k != "_t0"}
                out.append(snap)
        return out


def compute_progress_from_completions(
    *,
    total_motors: int,
    completed_motor_ids: List[str],
) -> Dict[str, Any]:
    """Progreso únicamente por motores realmente completados."""
    total = max(int(total_motors), 1)
    done = len(set(completed_motor_ids))
    pct = int(round(100.0 * done / total))
    return {
        "progress_pct": max(0, min(100, pct)),
        "completed_count": done,
        "total_motors": total,
        "progress_source": "completed_motors_only",
        "verifiable": True,
    }


def recent_events(limit: int = 50) -> List[Dict[str, Any]]:
    from utils.jsonl_tail import stream_jsonl_tail

    try:
        return stream_jsonl_tail(_JSONL, limit)
    except Exception:
        return []
