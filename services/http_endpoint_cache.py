"""
Caché de respuestas HTTP para endpoints críticos de lectura.
Evita recomputar payloads bajo ráfagas concurrentes — datos siguen siendo LIVE/CACHED reales.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple

_lock = threading.Lock()
_inflight: Dict[str, threading.Event] = {}
_store: Dict[str, Tuple[float, Any]] = {}
_SHARED_TENANT_PATHS = frozenset({
    "/api/dashboard/live",
    "/api/security/summary",
    "/api/tenant/scope",
    "/api/manual-defense/summary",
})
_MAX = int(os.environ.get(
    "NOVUS_HTTP_ENDPOINT_CACHE_MAX",
    "256" if os.environ.get("NOVUS_LOADTEST_MODE", "").strip().lower() in ("1", "true", "yes", "on") else "512",
))


def _singleflight(key: str, factory: Callable[[], Any]) -> Any:
    """
    Un solo builder por clave. Followers NUNCA ejecutan factory en paralelo
    (evita stampede de probes bajo 600 tenants concurrentes).
    """
    deadline = time.time() + 30.0
    while True:
        with _lock:
            entry = _store.get(key)
            if entry and (time.time() - entry[0]) <= _ttl_from_key(key):
                return entry[1]
            ev = _inflight.get(key)
            if ev is None:
                ev = threading.Event()
                _inflight[key] = ev
                leader = True
            else:
                leader = False
        if not leader:
            remaining = max(0.05, deadline - time.time())
            ev.wait(timeout=min(5.0, remaining))
            with _lock:
                entry = _store.get(key)
                if entry:
                    return entry[1]
                # líder aún trabajando o falló — reintentar esperar, no fabricar en paralelo
                if key in _inflight and time.time() < deadline:
                    continue
                if time.time() >= deadline:
                    # último recurso: devolver stale si existe
                    stale = _store.get(key)
                    if stale:
                        return stale[1]
                    raise TimeoutError(f"singleflight timeout: {key}")
            continue
        try:
            value = factory()
            with _lock:
                _store[key] = (time.time(), value)
                while len(_store) > _MAX:
                    oldest = min(_store.items(), key=lambda kv: kv[1][0])[0]
                    _store.pop(oldest, None)
            return value
        finally:
            with _lock:
                done = _inflight.pop(key, None)
            if done:
                done.set()


def _ttl_from_key(key: str) -> float:
    path = key.split(":", 1)[0]
    return _ttl(path)


def _ttl(path: str) -> float:
    p = (path or "").split("?")[0].rstrip("/")
    defaults = {
        "/api/dashboard/live": float(os.environ.get("NOVUS_CACHE_TTL_DASHBOARD_LIVE", "15")),
        "/api/security/summary": float(os.environ.get("NOVUS_CACHE_TTL_SECURITY_SUMMARY", "12")),
        "/api/tenant/scope": float(os.environ.get("NOVUS_CACHE_TTL_TENANT_SCOPE", "30")),
        "/api/manual-defense/summary": float(os.environ.get("NOVUS_CACHE_TTL_DEFENSE_SUMMARY", "20")),
        "/api/notifications": float(os.environ.get("NOVUS_CACHE_TTL_NOTIFICATIONS", "10")),
        "/api/security/vulnerabilities": float(os.environ.get("NOVUS_CACHE_TTL_VULNERABILITIES", "20")),
        "/api/security/threats": float(os.environ.get("NOVUS_CACHE_TTL_THREATS", "15")),
    }
    return defaults.get(p, float(os.environ.get("NOVUS_CACHE_TTL_DEFAULT", "10")))


def cache_key(
    path: str,
    *,
    tenant_id: Optional[str] = None,
    user_id: Optional[str] = None,
    variant: Optional[str] = None,
) -> str:
    p = (path or "").split("?")[0].rstrip("/")
    suffix = f":{variant}" if variant else ""
    # Telemetría HOST_GLOBAL de plataforma — no fragmentar por tenant (evita stampede 600×).
    # /api/security/summary EXCLUIDO: mezcla HOST + TENANT; key debe incluir tenant_id
    # (P1-CRITICAL-001). Sigue en _SHARED_TENANT_PATHS → path:tenant_id (sin user_id).
    if p in (
        "/api/manual-defense/summary",
        "/api/dashboard/live",
        "/api/security/vulnerabilities",
        "/api/security/threats",
    ):
        return f"{p}:platform{suffix}"
    if p in _SHARED_TENANT_PATHS:
        return f"{p}:{tenant_id or 'default'}{suffix}"
    return f"{p}:{tenant_id or 'default'}:{user_id or 'anon'}{suffix}"


def get_cached(
    path: str,
    *,
    tenant_id: Optional[str] = None,
    user_id: Optional[str] = None,
    variant: Optional[str] = None,
) -> Optional[Any]:
    key = cache_key(path, tenant_id=tenant_id, user_id=user_id, variant=variant)
    now = time.time()
    with _lock:
        entry = _store.get(key)
        if entry and (now - entry[0]) <= _ttl(path):
            return entry[1]
    return None


def set_cached(
    path: str,
    payload: Any,
    *,
    tenant_id: Optional[str] = None,
    user_id: Optional[str] = None,
    variant: Optional[str] = None,
) -> None:
    key = cache_key(path, tenant_id=tenant_id, user_id=user_id, variant=variant)
    with _lock:
        _store[key] = (time.time(), payload)
        if len(_store) > _MAX:
            oldest = min(_store.items(), key=lambda kv: kv[1][0])[0]
            _store.pop(oldest, None)


def get_or_build(
    path: str,
    factory: Callable[[], Any],
    *,
    tenant_id: Optional[str] = None,
    user_id: Optional[str] = None,
    variant: Optional[str] = None,
) -> Any:
    key = cache_key(path, tenant_id=tenant_id, user_id=user_id, variant=variant)
    cached = get_cached(path, tenant_id=tenant_id, user_id=user_id, variant=variant)
    if cached is not None:
        out = dict(cached) if isinstance(cached, dict) else cached
        if isinstance(out, dict):
            out["http_cache"] = {"hit": True, "path": path, "ttl_sec": _ttl(path)}
        return out
    value = _singleflight(key, factory)
    if isinstance(value, dict):
        out = dict(value)
        out["http_cache"] = {"hit": False, "path": path, "ttl_sec": _ttl(path)}
        return out
    return value


def invalidate(path_prefix: Optional[str] = None) -> None:
    with _lock:
        if path_prefix is None:
            _store.clear()
            return
        for key in list(_store.keys()):
            if key.startswith(path_prefix):
                _store.pop(key, None)


def trim_to(max_entries: int) -> int:
    """Recorta caché bajo presión de memoria — no inventa datos, solo libera entradas viejas."""
    removed = 0
    with _lock:
        while len(_store) > max(32, max_entries):
            oldest = min(_store.items(), key=lambda kv: kv[1][0])[0]
            _store.pop(oldest, None)
            removed += 1
    return removed


def purge_expired() -> int:
    """Remove entries past their path TTL (bounded store can still retain expired until max)."""
    now = time.time()
    removed = 0
    with _lock:
        for key, (ts, _val) in list(_store.items()):
            if (now - ts) > _ttl_from_key(key):
                _store.pop(key, None)
                removed += 1
    return removed


def stats() -> Dict[str, Any]:
    with _lock:
        return {"entries": len(_store), "max": _MAX, "keys_sample": list(_store.keys())[:12]}
