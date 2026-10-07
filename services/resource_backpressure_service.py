"""
Backpressure dinámico por RAM — pausa warmups pesados sin deshabilitar seguridad.
Reversible: cuando RAM baja, se reanudan tareas en cola.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional, Set

import psutil

from utils.logger import logger

_lock = threading.Lock()
_level = "normal"
_paused_categories: Set[str] = set()
_last_sample: Dict[str, Any] = {}
_monitor_started = False

# Categorías de tareas background
CAT_ESSENTIAL = "essential"
CAT_NETWORK = "network"
CAT_SECURITY_LIGHT = "security_light"
CAT_ENTERPRISE = "enterprise_warmup"
CAT_HEAVY_AGG = "heavy_aggregation"
CAT_ENDPOINT = "endpoint_telemetry"
CAT_LAZY_P2 = "lazy_p2_heavy"


def sample_resources() -> Dict[str, Any]:
    import os

    global _last_sample, _level, _paused_categories

    vm = psutil.virtual_memory()
    # No bloquear 50ms+ en hot path: CPU non-blocking / cache corto
    with _lock:
        last = _last_sample
        now = time.time()
        if last and (now - float(last.get("sampled_at") or 0)) < 2.0:
            cpu = float(last.get("cpu_system_pct") or 0)
        else:
            cpu = psutil.cpu_percent(interval=None)
    out = {
        "ram_system_pct": round(vm.percent, 1),
        "ram_used_gb": round(vm.used / (1024**3), 2),
        "ram_available_gb": round(vm.available / (1024**3), 2),
        "cpu_system_pct": round(cpu, 1),
        "sampled_at": time.time(),
    }
    loadtest = os.environ.get("NOVUS_LOADTEST_MODE", "").strip().lower() in ("1", "true", "yes", "on")
    with _lock:
        _last_sample = dict(out)
        prev = _level
        # Orden descendente — umbrales más tempranos en hosts ~8GB (evidencia Fase 4: thrash ~97%).
        if vm.percent >= 88:
            _level = "critical"
            _paused_categories = {
                CAT_ENTERPRISE,
                CAT_HEAVY_AGG,
                CAT_ENDPOINT,
                CAT_LAZY_P2,
                CAT_NETWORK,
            }
        elif vm.percent >= 84:
            _level = "high"
            _paused_categories = {CAT_ENTERPRISE, CAT_HEAVY_AGG, CAT_LAZY_P2, CAT_ENDPOINT}
        elif vm.percent >= 78:
            # En hosts ~8GB, 78–84% sigue siendo presión real: no reanudar P2/agg
            _level = "elevated"
            _paused_categories = {CAT_ENTERPRISE, CAT_HEAVY_AGG, CAT_LAZY_P2}
        else:
            _level = "normal"
            _paused_categories = set()
        # LOADTEST: nunca arrancar P2/agg pesados durante benchmarks (motores siguen etiquetados)
        if loadtest:
            _paused_categories = set(_paused_categories) | {CAT_HEAVY_AGG, CAT_LAZY_P2, CAT_ENTERPRISE}
            if _level == "normal":
                _level = "elevated"
        if prev != _level:
            logger.info(
                "Resource backpressure level=%s ram=%.1f%% paused=%s",
                _level,
                vm.percent,
                sorted(_paused_categories),
            )
        # Liberar entradas TTL expiradas bajo presión (no desactiva seguridad; no inventa datos)
        if _level in ("elevated", "high", "critical"):
            try:
                from services.http_endpoint_cache import purge_expired as http_purge, trim_to

                http_purge()
                if _level == "critical":
                    trim_to(64)
                elif _level == "high":
                    trim_to(128)
                else:
                    trim_to(256)
            except Exception:
                pass
            try:
                from services.auth_session_cache import purge_expired as auth_purge

                auth_purge()
            except Exception:
                pass
            try:
                from services.http_abuse_guard import prune_stale_windows

                prune_stale_windows(window=10.0, max_keys=2048 if _level == "critical" else 4096)
            except Exception:
                pass
            try:
                from services.ai_capability_registry import capability_registry

                if hasattr(capability_registry, "trim_cache"):
                    capability_registry.trim_cache(max_entries=64 if _level == "critical" else 128)
            except Exception:
                pass
        out["backpressure_level"] = _level
        out["paused_categories"] = sorted(_paused_categories)
    return out


def get_backpressure_level() -> str:
    with _lock:
        return _level


def should_run_background(category: str) -> bool:
    sample_resources()
    with _lock:
        if category in _paused_categories:
            return False
        if _level == "critical" and category not in (
            CAT_ESSENTIAL,
            CAT_SECURITY_LIGHT,
            CAT_NETWORK,
        ):
            return False
        return True


def wait_for_capacity(category: str, *, max_wait_sec: float = 120.0, poll_sec: float = 5.0) -> bool:
    """Espera hasta que la categoría pueda ejecutarse o timeout."""
    deadline = time.time() + max_wait_sec
    while time.time() < deadline:
        if should_run_background(category):
            return True
        time.sleep(poll_sec)
    return should_run_background(category)


def get_status() -> Dict[str, Any]:
    sample_resources()
    with _lock:
        return {
            "level": _level,
            "paused_categories": sorted(_paused_categories),
            "last_sample": dict(_last_sample),
        }


def _monitor_loop() -> None:
    while True:
        try:
            sample_resources()
            # Poda periódica aunque el nivel sea normal (evita growth lento de buckets)
            try:
                from services.http_abuse_guard import prune_stale_windows

                prune_stale_windows(window=10.0, max_keys=4096)
            except Exception:
                pass
            try:
                from services.http_endpoint_cache import purge_expired

                purge_expired()
            except Exception:
                pass
        except Exception as exc:
            logger.debug("backpressure monitor: %s", exc)
        time.sleep(8.0)


def ensure_monitor_started() -> None:
    global _monitor_started
    with _lock:
        if _monitor_started:
            return
        _monitor_started = True
    threading.Thread(target=_monitor_loop, daemon=True, name="ResourceBackpressure").start()
