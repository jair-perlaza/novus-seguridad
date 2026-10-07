"""
Pool acotado para trabajo post-request — evita thread leak (1 Thread por login).
No desactiva seguridad: solo limita concurrencia de hooks asíncronos.
"""
from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Optional

from utils.logger import logger

_lock = threading.Lock()
_pool: Optional[ThreadPoolExecutor] = None
_MAX = int(os.environ.get("NOVUS_BG_POOL_WORKERS", "6"))
_QUEUE_CAP = int(os.environ.get("NOVUS_BG_POOL_QUEUE_CAP", "200"))
_pending = 0
_pending_lock = threading.Lock()


def get_pool() -> ThreadPoolExecutor:
    global _pool
    with _lock:
        if _pool is None:
            _pool = ThreadPoolExecutor(max_workers=max(2, _MAX), thread_name_prefix="NovusBg")
        return _pool


def submit_background(fn: Callable[..., Any], *args, name: str = "bg", **kwargs) -> bool:
    """
    Encola trabajo. Si la cola está saturada, descarta con log (no crea threads nuevos).
    Retorna True si se aceptó.
    """
    global _pending
    with _pending_lock:
        if _pending >= _QUEUE_CAP:
            logger.warning("background pool saturated (%s) — skip %s", _QUEUE_CAP, name)
            return False
        _pending += 1

    def _wrap():
        global _pending
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            logger.debug("background %s: %s", name, exc)
        finally:
            with _pending_lock:
                _pending = max(0, _pending - 1)

    try:
        get_pool().submit(_wrap)
        return True
    except Exception as exc:
        with _pending_lock:
            _pending = max(0, _pending - 1)
        logger.debug("background submit failed %s: %s", name, exc)
        return False


def pool_stats() -> dict:
    with _pending_lock:
        return {"max_workers": _MAX, "pending": _pending, "queue_cap": _QUEUE_CAP}
