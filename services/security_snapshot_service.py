"""
Security Summary snapshot — GET HTTP nunca ejecuta agregación pesada sincrona.
Stale-while-revalidate: devuelve snapshot inmediato; refresh en background.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from utils.logger import logger

_lock = threading.Lock()
_refresh_inflight = False
_last_refresh_trigger_at = 0.0
_REFRESH_MIN_INTERVAL_SEC = float(os.environ.get("NOVUS_SECURITY_SNAPSHOT_REFRESH_MIN_SEC", "30"))
_SNAPSHOT_PATH = os.path.join("data", "security", "summary_snapshot.json")
_STALE_SEC = 120.0


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _abs_path() -> str:
    return os.path.join(_root(), _SNAPSHOT_PATH)


def _age_sec(generated_at: Optional[str]) -> Optional[float]:
    if not generated_at:
        return None
    try:
        ts = datetime.strptime(generated_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return round((datetime.now(timezone.utc) - ts).total_seconds(), 1)
    except Exception:
        return None


def _is_stale(generated_at: Optional[str], stale_sec: float = _STALE_SEC) -> bool:
    age = _age_sec(generated_at)
    return age is None or age > stale_sec


def _network_context_fingerprint() -> Optional[str]:
    try:
        from services.network_scan_coordinator import context_fingerprint, get_network_context

        return context_fingerprint(get_network_context())
    except Exception:
        return None


def _snapshot_context_mismatch(snap: Optional[Dict[str, Any]]) -> bool:
    if not snap or not snap.get("body"):
        return False
    stored = snap.get("network_context_fingerprint") or (snap.get("body") or {}).get(
        "network_context_fingerprint"
    )
    current = _network_context_fingerprint()
    if not stored or not current:
        return False
    return stored != current


def load_snapshot() -> Optional[Dict[str, Any]]:
    path = _abs_path()
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        logger.debug("security snapshot read: %s", exc)
        return None


def save_snapshot(body: Dict[str, Any], *, source: str) -> None:
    path = _abs_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {
        "body": body,
        "generated_at_utc": _utc(),
        "source": source,
        "source_type": "snapshot",
        "network_context_fingerprint": _network_context_fingerprint(),
    }
    with _lock:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2, default=str)


def _build_body(tenant_id: Optional[str]) -> Dict[str, Any]:
    from datetime import datetime

    from services.platform_metrics_service import get_unified_security_payload

    payload = get_unified_security_payload(tenant_id=tenant_id)
    counters = payload.get("counters") or {}
    return {
        "status": "ok",
        "system_health": payload.get("system_health", {}),
        "threats": payload.get("threats", {}),
        "total_threats": payload.get("total_threats"),
        "vulnerabilities": payload.get("vulnerabilities", []),
        "endpoints": payload.get("endpoints", {}),
        "counters": counters,
        "endpoint_inventory": payload.get("endpoint_inventory", []),
        "ransomware_active": payload.get("ransomware_active", []),
        "has_active_ransomware": payload.get("has_active_ransomware", False),
        "alerts_active": payload.get("alerts_active"),
        "alerts": payload.get("alerts", []),
        "component_status": payload.get("component_status") or {
            "endpoint_inventory": "ready",
            "alerts": "ready",
            "network_discovery": "ready",
        },
        "timestamp": datetime.now().isoformat(),
        "source": "services.platform_metrics_service.get_unified_security_payload",
        "source_type": "canonical_metrics",
        "observed_at": _utc(),
        "confidence": "verified",
        "metric_sources": (counters.get("sources") if isinstance(counters, dict) else None),
    }


def _build_body_fast(tenant_id: Optional[str]) -> Dict[str, Any]:
    from datetime import datetime

    from services.platform_metrics_service import get_fast_security_payload

    payload = get_fast_security_payload(tenant_id=tenant_id)
    counters = payload.get("counters") or {}
    return {
        **payload,
        "timestamp": datetime.now().isoformat(),
        "observed_at": _utc(),
        "snapshot_pending": True,
        "metric_sources": counters.get("sources") if isinstance(counters, dict) else None,
    }


def _schedule_refresh(tenant_id: Optional[str]) -> None:
    global _refresh_inflight, _last_refresh_trigger_at
    now = time.time()
    with _lock:
        if _refresh_inflight:
            return
        if (now - _last_refresh_trigger_at) < _REFRESH_MIN_INTERVAL_SEC:
            return
        _refresh_inflight = True
        _last_refresh_trigger_at = now

    def _worker() -> None:
        global _refresh_inflight
        try:
            from services.resource_backpressure_service import should_run_background, CAT_HEAVY_AGG

            if not should_run_background(CAT_HEAVY_AGG):
                logger.debug("security snapshot full refresh deferred — backpressure")
                return
            try:
                fast = _build_body_fast(tenant_id)
                save_snapshot(fast, source="security_snapshot_service._build_body_fast")
            except Exception as exc:
                logger.debug("security snapshot fast refresh: %s", exc)
            if not should_run_background(CAT_HEAVY_AGG):
                return
            body = _build_body(tenant_id)
            save_snapshot(body, source="security_snapshot_service._build_body")
            cache_key = f"security_summary_api:{tenant_id or 'default'}"
            from services import performance_cache as pc

            with pc._lock:
                pc._store[cache_key] = (time.time(), body)
        except Exception as exc:
            logger.warning("security snapshot refresh failed: %s", exc, exc_info=True)
        finally:
            with _lock:
                _refresh_inflight = False

    threading.Thread(target=_worker, daemon=True, name="SecuritySummarySnapRefresh").start()


def _pending_body(*, refresh_inflight: bool) -> Dict[str, Any]:
    return {
        "status": "loading",
        "status_label": "Actualizando métricas de seguridad",
        "message": "Generando snapshot en background — datos parciales disponibles en breve.",
        "system_health": {},
        "threats": {},
        "total_threats": None,
        "vulnerabilities": [],
        "endpoints": {},
        "counters": {},
        "endpoint_inventory": [],
        "ransomware_active": [],
        "has_active_ransomware": False,
        "alerts_active": None,
        "alerts": [],
        "timestamp": None,
        "source": "services.security_snapshot_service",
        "source_type": "snapshot_pending",
        "observed_at": _utc(),
        "confidence": "pending",
        "snapshot_pending": True,
        "snapshot_stale": True,
        "refresh_inflight": refresh_inflight,
        "invented": False,
    }


def read_security_summary_api(tenant_id: Optional[str], *, trigger_refresh: bool = True) -> Dict[str, Any]:
    """Respuesta inmediata para GET /api/security/summary — nunca bloquea en factory pesada."""
    snap = load_snapshot()
    generated_at = (snap or {}).get("generated_at_utc")
    stale = _is_stale(generated_at) or _snapshot_context_mismatch(snap)

    if trigger_refresh and stale and not _refresh_inflight:
        _schedule_refresh(tenant_id)

    if snap and snap.get("body") is not None:
        body = dict(snap["body"])
        context_mismatch = _snapshot_context_mismatch(snap)
        body["snapshot_meta"] = {
            "generated_at_utc": generated_at,
            "age_sec": _age_sec(generated_at),
            "source_type": "snapshot",
            "snapshot_stale": stale,
            "context_mismatch": context_mismatch,
            "network_context_fingerprint": snap.get("network_context_fingerprint"),
            "data_freshness": "STALE" if stale else "CACHED",
            "refresh_inflight": _refresh_inflight,
        }
        if stale or context_mismatch:
            body["status"] = "stale"
            body["message"] = (
                "Métricas en caché desactualizadas — actualización en background."
                if stale
                else "Contexto de red cambió — métricas en caché no aplican a la red actual."
            )
            # No reutilizar telemetría vieja como si fuera LIVE
            body["threats"] = {}
            body["total_threats"] = None
            body["vulnerabilities"] = []
            body["endpoints"] = {}
            body["counters"] = {}
            body["endpoint_inventory"] = []
            body["ransomware_active"] = []
            body["has_active_ransomware"] = False
            body["alerts_active"] = None
            body["alerts"] = []
            body["system_health"] = {}
        return body

    # Sin snapshot: respuesta inmediata pending — refresh solo en background
    return _pending_body(refresh_inflight=_refresh_inflight)


def schedule_security_warmup() -> None:
    """Precalienta snapshot al arranque."""

    def _warm() -> None:
        import time

        time.sleep(4)
        try:
            _schedule_refresh(None)
        except Exception as exc:
            logger.debug("security warmup: %s", exc)

    threading.Thread(target=_warm, daemon=True, name="SecuritySummaryWarmup").start()
