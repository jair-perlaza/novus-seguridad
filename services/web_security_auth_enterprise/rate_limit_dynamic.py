"""
T12 — Rate limit dinámico endurecible por Swarm.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional, Tuple

_lock = threading.Lock()
_multipliers: Dict[str, float] = {}  # key -> multiplier (<1 endurece)
_until: Dict[str, float] = {}


def swarm_harden(*, key: str, multiplier: float = 0.5, ttl_sec: int = 600) -> Dict[str, Any]:
    """Reduce el techo efectivo de rate-limit (multiplier 0.5 = mitad de requests)."""
    mult = max(0.1, min(1.0, float(multiplier)))
    with _lock:
        _multipliers[key] = mult
        _until[key] = time.time() + max(60, ttl_sec)
    return {"ok": True, "key": key, "multiplier": mult, "ttl_sec": ttl_sec}


def effective_limit(base_limit: int, *, key: str) -> int:
    with _lock:
        until = _until.get(key) or 0
        if time.time() > until:
            _multipliers.pop(key, None)
            _until.pop(key, None)
            return int(base_limit)
        mult = _multipliers.get(key, 1.0)
    return max(1, int(base_limit * mult))


def get_hardening_status() -> Dict[str, Any]:
    now = time.time()
    with _lock:
        active = {
            k: {"multiplier": _multipliers[k], "remaining_sec": int(max(0, _until[k] - now))}
            for k in list(_multipliers)
            if _until.get(k, 0) > now
        }
    return {"active": active, "verified": True}
