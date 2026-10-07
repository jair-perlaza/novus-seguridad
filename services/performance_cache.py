"""
Caché TTL para lecturas seguras — no altera lógica de seguridad ni frecuencia de escaneos en background.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple

_lock = threading.Lock()
_MAX_ENTRIES = int(os.environ.get("NOVUS_PERF_CACHE_MAX", "48"))
_store: Dict[str, Tuple[float, Any]] = {}
_access_order: list = []


def _evict_if_needed() -> None:
    while len(_store) > _MAX_ENTRIES and _access_order:
        old_key = _access_order.pop(0)
        _store.pop(old_key, None)


def get_or_compute(key: str, ttl_sec: float, factory: Callable[[], Any]) -> Any:
    """Devuelve valor cacheado si está fresco; si no, ejecuta factory."""
    if ttl_sec <= 0:
        return factory()
    now = time.time()
    with _lock:
        entry = _store.get(key)
        if entry and (now - entry[0]) <= ttl_sec:
            if key in _access_order:
                _access_order.remove(key)
            _access_order.append(key)
            return entry[1]
    value = factory()
    with _lock:
        _store[key] = (time.time(), value)
        if key in _access_order:
            _access_order.remove(key)
        _access_order.append(key)
        _evict_if_needed()
    return value


def peek_cached(key: str) -> Optional[Any]:
    """Devuelve valor cacheado sin ejecutar factory (puede estar expirado)."""
    with _lock:
        entry = _store.get(key)
        if entry:
            return entry[1]
    return None


def invalidate(key: Optional[str] = None) -> None:
    with _lock:
        if key is None:
            _store.clear()
            _access_order.clear()
        else:
            _store.pop(key, None)
            if key in _access_order:
                _access_order.remove(key)


def cache_stats() -> Dict[str, Any]:
    with _lock:
        return {"entries": len(_store), "max_entries": _MAX_ENTRIES, "keys": list(_store.keys())[:20]}
