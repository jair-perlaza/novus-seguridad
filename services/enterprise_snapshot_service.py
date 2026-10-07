"""
Lectura rápida de dashboards enterprise vía snapshots en disco.

GET HTTP nunca ejecuta agregación pesada sincrónica.
Los refrescos corren en background (daemon threads).
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from utils.logger import logger

NA = "NOT AVAILABLE"
UNKNOWN = "UNKNOWN"

_lock = threading.Lock()
_refresh_inflight: Dict[str, bool] = {}

_SNAPSHOT_PATHS = {
    "tie": os.path.join("data", "threat_intelligence_enterprise", "dashboard_snapshot.json"),
    "sope": os.path.join("data", "sope", "dashboard_snapshot.json"),
    "imcm": os.path.join("data", "imcm", "dashboard_snapshot.json"),
    "imcm_timeline": os.path.join("data", "imcm", "timeline_snapshot.json"),
    "asm": os.path.join("data", "asm", "dashboard_snapshot.json"),
    "viem": os.path.join("data", "viem", "dashboard_snapshot.json"),
    "soc": os.path.join("data", "soc", "overview_snapshot.json"),
    "sdl": os.path.join("data", "sdl", "dashboard_snapshot.json"),
    "sdace": os.path.join("data", "sdace", "dashboard_snapshot.json"),
    "deception": os.path.join("data", "deception", "dashboard_snapshot.json"),
    "iapa": os.path.join("data", "iapa", "dashboard_snapshot.json"),
    "csv_bas": os.path.join("data", "csv_bas", "dashboard_snapshot.json"),
    "identity_intel": os.path.join("data", "identity_intelligence", "dashboard_snapshot.json"),
    "health": os.path.join("data", "health_engine", "dashboard_snapshot.json"),
}


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _abs_path(module: str) -> str:
    return os.path.join(_root(), _SNAPSHOT_PATHS[module])


def load_module_snapshot(module: str) -> Optional[Dict[str, Any]]:
    path = _abs_path(module)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        logger.debug("snapshot read %s: %s", module, exc)
        return None


def save_module_snapshot(module: str, dashboard: Dict[str, Any], *, source: str) -> None:
    path = _abs_path(module)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {
        "dashboard": dashboard,
        "generated_at_utc": _utc(),
        "source": source,
        "source_type": "snapshot",
    }
    with _lock:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2, default=str)


def _is_stale(generated_at: Optional[str], stale_sec: float) -> bool:
    if not generated_at:
        return True
    try:
        ts = datetime.strptime(generated_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - ts).total_seconds() > stale_sec
    except Exception:
        return True


def _schedule_refresh(module: str, factory: Callable[[], Dict[str, Any]], *, source: str) -> None:
    from services.resource_backpressure_service import CAT_ENTERPRISE, should_run_background

    if not should_run_background(CAT_ENTERPRISE):
        logger.debug("enterprise snapshot refresh skipped (%s) — backpressure", module)
        return
    with _lock:
        if _refresh_inflight.get(module):
            return
        _refresh_inflight[module] = True

    def _worker() -> None:
        try:
            from services.resource_backpressure_service import should_run_background, CAT_ENTERPRISE

            if not should_run_background(CAT_ENTERPRISE):
                logger.debug("enterprise snapshot worker aborted (%s) — backpressure", module)
                return
            dashboard = factory()
            save_module_snapshot(module, dashboard, source=source)
        except Exception as exc:
            logger.debug("snapshot refresh %s: %s", module, exc)
        finally:
            with _lock:
                _refresh_inflight[module] = False

    threading.Thread(
        target=_worker,
        daemon=True,
        name=f"EnterpriseSnap-{module}",
    ).start()


def _age_sec(generated_at: Optional[str]) -> Optional[float]:
    if not generated_at:
        return None
    try:
        ts = datetime.strptime(generated_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return round((datetime.now(timezone.utc) - ts).total_seconds(), 1)
    except Exception:
        return None


def read_dashboard_api(
    module: str,
    factory: Callable[[], Dict[str, Any]],
    *,
    source: str,
    stale_sec: float = 60.0,
    trigger_refresh: bool = True,
) -> Dict[str, Any]:
    """Respuesta para API GET /dashboard — snapshot only, refresh async si stale."""
    snap = load_module_snapshot(module)
    generated_at = (snap or {}).get("generated_at_utc")
    stale = _is_stale(generated_at, stale_sec)

    if trigger_refresh and (snap is None or stale):
        _schedule_refresh(module, factory, source=source)

    if snap and snap.get("dashboard") is not None:
        dash = dict(snap["dashboard"])
        dash.setdefault("snapshot_meta", {})
        dash["snapshot_meta"].update({
            "generated_at_utc": generated_at,
            "age_sec": _age_sec(generated_at),
            "source": snap.get("source", source),
            "source_type": "snapshot",
            "snapshot_stale": stale,
            "refresh_inflight": bool(_refresh_inflight.get(module)),
        })
        return dash

    return {
        "status": NA,
        "status_label": "Datos aún no disponibles",
        "message": "Datos aún no disponibles — el motor está generando el snapshot en background.",
        "generated_at_utc": None,
        "source": source,
        "source_type": "snapshot",
        "snapshot_pending": True,
        "snapshot_stale": True,
        "refresh_inflight": bool(_refresh_inflight.get(module)),
        "invented": False,
    }


def read_timeline_api(
    *,
    factory: Callable[[], list],
    limit: int = 30,
    stale_sec: float = 45.0,
) -> Dict[str, Any]:
    """Timeline IMCM — snapshot paginado, refresh async."""
    module = "imcm_timeline"
    snap = load_module_snapshot(module)
    generated_at = (snap or {}).get("generated_at_utc")
    stale = _is_stale(generated_at, stale_sec)

    if snap is None or stale:
        _schedule_refresh(
            module,
            lambda: {"entries": factory(), "limit": limit},
            source="services.imcm.store.load_timeline",
        )

    if snap and snap.get("dashboard"):
        entries = snap["dashboard"].get("entries") or []
        return {
            "timeline": entries[:limit],
            "generated_at_utc": generated_at,
            "age_sec": _age_sec(generated_at),
            "source": snap.get("source"),
            "source_type": "snapshot",
            "snapshot_stale": stale,
            "total_available": len(entries),
            "invented": False,
        }

    return {
        "timeline": [],
        "status": NA,
        "message": "Timeline aún no disponible — generando snapshot en background.",
        "generated_at_utc": None,
        "source_type": "snapshot",
        "snapshot_pending": True,
        "invented": False,
    }


def invalidate_module(module: str) -> None:
    path = _abs_path(module)
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass
    from services.performance_cache import invalidate

    keys = {
        "tie": "tie_dashboard",
        "sope": "sope_dashboard",
        "imcm": "imcm_dashboard",
        "imcm_timeline": "imcm_timeline",
    }
    invalidate(keys.get(module))


def schedule_all_enterprise_warmup() -> None:
    """Precalienta snapshots enterprise — solo si NOVUS_ENTERPRISE_WARMUP=1 (fuera del MVP)."""
    try:
        from services.production_runtime_guard import enterprise_warmup_enabled

        if not enterprise_warmup_enabled():
            logger.info("enterprise warmup disabled — MVP/non-lab runtime")
            return
    except Exception:
        return

    def _warm() -> None:
        from services.resource_backpressure_service import (
            CAT_ENTERPRISE,
            should_run_background,
            wait_for_capacity,
        )

        time.sleep(5)
        if not wait_for_capacity(CAT_ENTERPRISE, max_wait_sec=180):
            logger.warning("enterprise warmup skipped — RAM backpressure")
            return

        sequence = [
            ("tie", "services.threat_intelligence_enterprise", "get_dashboard"),
            ("sope", "services.sope", "get_dashboard"),
            ("imcm", "services.imcm", "get_dashboard_summary"),
            ("asm", "services.asm", "get_dashboard"),
            ("viem", "services.viem", "get_dashboard"),
            ("soc", "services.soc", "get_overview"),
            ("sdl", "services.sdl", "get_dashboard"),
            ("sdace", "services.sdace", "get_dashboard"),
            ("deception", "services.deception_platform", "get_dashboard"),
            ("iapa", "services.iapa", "get_dashboard"),
            ("csv_bas", "services.csv_bas", "get_dashboard"),
            ("identity_intel", "services.identity_intelligence.dashboard", "get_dashboard"),
            ("health", "services.health_engine", "get_health_dashboard"),
        ]
        import importlib

        for mod_key, mod_path, fn_name in sequence:
            if not should_run_background(CAT_ENTERPRISE):
                logger.info("enterprise warmup halted at %s — RAM backpressure", mod_key)
                break
            try:
                mod = importlib.import_module(mod_path)
                factory = getattr(mod, fn_name)
                read_dashboard_api(
                    mod_key,
                    factory,
                    source=f"{mod_path}.{fn_name}",
                    trigger_refresh=True,
                )
            except Exception as exc:
                logger.debug("warmup %s: %s", mod_key, exc)
            time.sleep(15.0)

    threading.Thread(target=_warm, daemon=True, name="EnterpriseSnapWarmup").start()
