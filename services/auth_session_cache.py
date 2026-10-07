"""
Caché process-local para user loader y tenant scope — reduce lecturas SQLite por request.
TTL corto: no debilita revocación de sesión ni tenant isolation.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict, Optional, Tuple

_USER_TTL = float(os.environ.get("NOVUS_USER_CACHE_TTL", "30"))
_TENANT_TTL = float(os.environ.get("NOVUS_TENANT_SCOPE_CACHE_TTL", "60"))
_USER_CACHE_MAX = int(os.environ.get("NOVUS_USER_CACHE_MAX", "2048"))
_TENANT_CACHE_MAX = int(os.environ.get("NOVUS_TENANT_SCOPE_CACHE_MAX", "2048"))
_lock = threading.Lock()
_users: Dict[str, Tuple[float, Any]] = {}
_tenant_rows: Dict[str, Tuple[float, Any]] = {}


def get_cached_user(user_id: str):
    now = time.time()
    with _lock:
        entry = _users.get(str(user_id))
        if entry and (now - entry[0]) <= _USER_TTL:
            return entry[1]
    return None


def set_cached_user(user_id: str, user) -> None:
    with _lock:
        _users[str(user_id)] = (time.time(), user)
        while len(_users) > _USER_CACHE_MAX:
            oldest = min(_users.items(), key=lambda kv: kv[1][0])[0]
            _users.pop(oldest, None)


def invalidate_user(user_id: Optional[str] = None) -> None:
    with _lock:
        if user_id is None:
            _users.clear()
        else:
            _users.pop(str(user_id), None)


def get_cached_tenant_scope(tenant_id: str):
    now = time.time()
    with _lock:
        entry = _tenant_rows.get(str(tenant_id))
        if entry and (now - entry[0]) <= _TENANT_TTL:
            return entry[1]
    return None


def set_cached_tenant_scope(tenant_id: str, record) -> None:
    with _lock:
        _tenant_rows[str(tenant_id)] = (time.time(), record)
        while len(_tenant_rows) > _TENANT_CACHE_MAX:
            oldest = min(_tenant_rows.items(), key=lambda kv: kv[1][0])[0]
            _tenant_rows.pop(oldest, None)


def invalidate_tenant_scope(tenant_id: Optional[str] = None) -> None:
    with _lock:
        if tenant_id is None:
            _tenant_rows.clear()
        else:
            _tenant_rows.pop(str(tenant_id), None)


def purge_expired() -> Dict[str, int]:
    """Drop TTL-expired entries so process RAM does not retain dead objects until max eviction."""
    now = time.time()
    removed_u = 0
    removed_t = 0
    with _lock:
        for k, (ts, _v) in list(_users.items()):
            if (now - ts) > _USER_TTL:
                _users.pop(k, None)
                removed_u += 1
        for k, (ts, _v) in list(_tenant_rows.items()):
            if (now - ts) > _TENANT_TTL:
                _tenant_rows.pop(k, None)
                removed_t += 1
    return {"users_purged": removed_u, "tenant_scopes_purged": removed_t}


def stats() -> Dict[str, Any]:
    with _lock:
        return {
            "users": len(_users),
            "users_max": _USER_CACHE_MAX,
            "tenant_scopes": len(_tenant_rows),
            "tenant_scopes_max": _TENANT_CACHE_MAX,
            "user_ttl_sec": _USER_TTL,
            "tenant_ttl_sec": _TENANT_TTL,
        }
