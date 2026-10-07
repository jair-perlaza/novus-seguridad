#!/usr/bin/env python3
"""Persistencia real de historial, alertas y snapshots del Health Engine."""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(ROOT, "data", "health_engine")
HISTORY_PATH = os.path.join(DATA_DIR, "history.jsonl")
ALERTS_PATH = os.path.join(DATA_DIR, "alerts.jsonl")
LAST_SNAPSHOT = os.path.join(DATA_DIR, "last_snapshot.json")
HEAL_LOG = os.path.join(DATA_DIR, "self_heal.jsonl")
MEM_BASELINE = os.path.join(DATA_DIR, "memory_baseline.json")
FAULT_INJECT = os.path.join(DATA_DIR, "fault_inject.json")

_lock = threading.Lock()


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_dir() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)


def append_jsonl(path: str, entry: Dict[str, Any]) -> None:
    ensure_dir()
    row = dict(entry)
    row.setdefault("timestamp_utc", _utc())
    with _lock:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")


def read_jsonl_tail(path: str, limit: int = 100) -> List[Dict[str, Any]]:
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    for line in lines[-max(1, limit) :]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def save_snapshot(payload: Dict[str, Any]) -> None:
    ensure_dir()
    with _lock:
        with open(LAST_SNAPSHOT, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2, default=str)


def load_snapshot() -> Optional[Dict[str, Any]]:
    if not os.path.isfile(LAST_SNAPSHOT):
        return None
    try:
        with open(LAST_SNAPSHOT, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def record_history_event(event_type: str, component_id: str, detail: Dict[str, Any]) -> None:
    append_jsonl(
        HISTORY_PATH,
        {
            "event_type": event_type,
            "component_id": component_id,
            "detail": detail,
        },
    )


def record_alert(alert: Dict[str, Any]) -> None:
    append_jsonl(ALERTS_PATH, alert)


def record_heal(action: Dict[str, Any]) -> None:
    append_jsonl(HEAL_LOG, action)


def load_memory_baseline() -> Dict[str, Any]:
    if not os.path.isfile(MEM_BASELINE):
        return {}
    try:
        with open(MEM_BASELINE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_memory_baseline(data: Dict[str, Any]) -> None:
    ensure_dir()
    with _lock:
        with open(MEM_BASELINE, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)


def load_fault_inject() -> Dict[str, Any]:
    """Fault inject solo para pentest controlado — no inventa telemetría de producción."""
    if not os.path.isfile(FAULT_INJECT):
        return {}
    try:
        with open(FAULT_INJECT, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not data.get("active"):
            return {}
        return data
    except Exception:
        return {}


def set_fault_inject(payload: Optional[Dict[str, Any]]) -> None:
    ensure_dir()
    with _lock:
        if not payload:
            if os.path.isfile(FAULT_INJECT):
                os.remove(FAULT_INJECT)
            return
        with open(FAULT_INJECT, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
