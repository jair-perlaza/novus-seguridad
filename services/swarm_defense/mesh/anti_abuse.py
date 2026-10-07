#!/usr/bin/env python3
"""
Anti-replay / anti-poisoning del Swarm Mesh.
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict, Set

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
SEEN_PATH = os.path.join(ROOT, "data", "swarm_mesh", "seen_msg_ids.json")
_lock = threading.RLock()
_MAX_AGE_SEC = 3600 * 6
_MAX_SKEW_SEC = 300


def _load_seen() -> Dict[str, float]:
    os.makedirs(os.path.dirname(SEEN_PATH), exist_ok=True)
    if not os.path.isfile(SEEN_PATH):
        return {}
    try:
        with open(SEEN_PATH, encoding="utf-8") as fh:
            raw = json.load(fh)
        return {str(k): float(v) for k, v in (raw or {}).items()}
    except Exception:
        return {}


def _save_seen(data: Dict[str, float]) -> None:
    now = time.time()
    pruned = {k: v for k, v in data.items() if now - v < _MAX_AGE_SEC}
    tmp = SEEN_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(pruned, fh)
    os.replace(tmp, SEEN_PATH)


def check_and_remember(msg_id: str, created_ts: int) -> Dict[str, Any]:
    """Rechaza replay y mensajes fuera de ventana temporal."""
    now = int(time.time())
    if abs(now - int(created_ts or 0)) > _MAX_SKEW_SEC:
        return {"ok": False, "reason": "timestamp_skew", "skew_limit_sec": _MAX_SKEW_SEC}
    if not msg_id:
        return {"ok": False, "reason": "missing_msg_id"}
    with _lock:
        seen = _load_seen()
        if msg_id in seen:
            return {"ok": False, "reason": "replay_detected"}
        seen[msg_id] = float(now)
        _save_seen(seen)
    return {"ok": True, "reason": "fresh"}


def validate_intel_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Anti-poisoning: exige indicadores estructurados reales.
    No acepta payloads vacíos ni campos inventados sin evidencia.
    """
    if not isinstance(payload, dict):
        return {"ok": False, "reason": "not_object"}
    indicators = payload.get("indicators") or {}
    if not isinstance(indicators, dict):
        return {"ok": False, "reason": "indicators_not_object"}
    # Al menos un IOC/IOA concreto
    keys = ("ips", "domains", "urls", "hashes", "iocs", "ioas", "behaviors")
    count = 0
    for k in keys:
        v = indicators.get(k)
        if isinstance(v, list):
            count += len([x for x in v if x])
        elif isinstance(v, dict):
            count += len(v)
        elif v:
            count += 1
    if count < 1:
        return {"ok": False, "reason": "no_structured_indicators"}
    if payload.get("invented") is True or payload.get("synthetic") is True:
        return {"ok": False, "reason": "synthetic_forbidden"}
    origin = payload.get("origin") or {}
    if not origin.get("source_event_id") and not origin.get("correlation_id"):
        # permitir si hay evidence_ref
        if not payload.get("evidence_ref"):
            return {"ok": False, "reason": "missing_origin_trace"}
    return {"ok": True, "indicator_count": count}
