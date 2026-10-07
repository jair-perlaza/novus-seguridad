#!/usr/bin/env python3
"""Health Monitoring & Self-Healing Engine — ciclo canónico."""
from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.health_engine.catalog import (
    COMPONENT_IDS,
    NA,
    STATUS_ACTIVE,
    STATUS_DEGRADED,
    STATUS_STOPPED,
    STATUS_UNAVAILABLE,
)
from services.health_engine.detector import build_alerts, detect_issues
from services.health_engine.limitations import LIMITATIONS, POLICY
from services.health_engine.probes import probe_all
from services.health_engine.publish import publish_cycle_to_swarm
from services.health_engine.self_heal import run_self_healing
from services.health_engine.store import (
    load_snapshot,
    read_jsonl_tail,
    record_alert,
    record_history_event,
    save_snapshot,
    ALERTS_PATH,
    HISTORY_PATH,
    HEAL_LOG,
)
from utils.logger import logger

_lock = threading.Lock()
_state: Dict[str, Any] = {
    "last_cycle_at": None,
    "cycles": 0,
    "last_error": None,
    "last_duration_ms": None,
    "last_cycle_id": None,
}


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _summarize(components: List[Dict[str, Any]], host: Dict[str, Any], issues: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    active = sum(1 for c in components if c.get("status") == STATUS_ACTIVE)
    degraded = sum(1 for c in components if c.get("status") == STATUS_DEGRADED)
    stopped = sum(1 for c in components if c.get("status") == STATUS_STOPPED)
    unavailable = sum(1 for c in components if c.get("status") == STATUS_UNAVAILABLE)
    total = max(len(components), 1)
    measurable = sum(1 for c in components if c.get("measurable"))
    # Disponibilidad: activos / (total - no_disponible) si hay medibles
    denom = max(total - unavailable, 1)
    availability = round(100.0 * active / denom, 1)

    if stopped >= 3 or any(i.get("code") == "multi_component_failure" for i in issues):
        overall = STATUS_STOPPED
        overall_label = "Crítico"
    elif stopped > 0 or degraded > 0 or alerts:
        overall = STATUS_DEGRADED
        overall_label = "Degradado"
    elif unavailable == total:
        overall = STATUS_UNAVAILABLE
        overall_label = "NO DISPONIBLE"
    else:
        overall = STATUS_ACTIVE
        overall_label = "Operativo"

    # Latencia media solo de valores numéricos
    lats = []
    for c in components:
        for k in ("latency_ms", "response_time_ms"):
            v = c.get(k)
            if isinstance(v, (int, float)):
                lats.append(float(v))
                break
    avg_lat = round(sum(lats) / len(lats), 2) if lats else NA

    return {
        "overall_status": overall,
        "overall_status_label": overall_label,
        "availability_pct": availability,
        "services_active": active,
        "services_degraded": degraded,
        "services_down": stopped,
        "services_unavailable": unavailable,
        "components_total": total,
        "components_measurable": measurable,
        "components_catalog": list(COMPONENT_IDS),
        "cpu_percent": host.get("cpu_percent", NA),
        "ram_percent": host.get("ram_percent", NA),
        "disk_percent": host.get("disk_percent", NA),
        "process_cpu_percent": host.get("process_cpu_percent", NA),
        "process_rss_mb": host.get("process_rss_mb", NA),
        "latency_avg_ms": avg_lat,
        "errors": sum(
            int(c["error_count"])
            for c in components
            if isinstance(c.get("error_count"), (int, float))
        ),
        "warnings": degraded + len([a for a in alerts if a.get("severity") == "medium"]),
        "alert_count": len(alerts),
        "issue_count": len(issues),
        "platform_uptime_sec": host.get("uptime_sec", NA),
    }


def run_health_cycle(
    *,
    publish: bool = True,
    self_heal: bool = True,
    persist: bool = True,
) -> Dict[str, Any]:
    t0 = time.perf_counter()
    cycle_id = uuid.uuid4().hex[:12].upper()
    previous = load_snapshot()
    try:
        probed = probe_all()
        components = probed.get("components") or []
        host = probed.get("host") or {}
        issues = detect_issues(probed, previous)
        alerts = build_alerts(issues)
        summary = _summarize(components, host, issues, alerts)

        if persist:
            for a in alerts:
                record_alert(a)
            # Historial de cambios de estado
            prev_map = {c.get("component_id"): c for c in (previous or {}).get("components") or []}
            for c in components:
                cid = c.get("component_id")
                prev = prev_map.get(cid) or {}
                if prev.get("status") and prev.get("status") != c.get("status"):
                    record_history_event(
                        "status_change",
                        cid,
                        {"from": prev.get("status"), "to": c.get("status"), "cycle_id": cycle_id},
                    )
            record_history_event(
                "cycle",
                "platform",
                {
                    "cycle_id": cycle_id,
                    "overall_status": summary.get("overall_status"),
                    "issue_count": len(issues),
                    "alert_count": len(alerts),
                    "cpu_percent": summary.get("cpu_percent"),
                    "ram_percent": summary.get("ram_percent"),
                },
            )

        heal_actions = run_self_healing(issues, enabled=self_heal) if self_heal else []

        published = None
        if publish:
            published = publish_cycle_to_swarm(
                issues=issues,
                alerts=alerts,
                summary=summary,
                cycle_id=cycle_id,
            )

        duration_ms = round((time.perf_counter() - t0) * 1000, 2)
        result = {
            "ok": True,
            "cycle_id": cycle_id,
            "timestamp_utc": _utc(),
            "duration_ms": duration_ms,
            "summary": summary,
            "host": host,
            "components": components,
            "issues": issues,
            "alerts": alerts,
            "self_heal": heal_actions,
            "published": published,
            "fault_inject_active": bool(probed.get("fault_inject_active")),
            "policy": POLICY,
            "limitations": LIMITATIONS,
            "fake_telemetry": False,
            "invented_alerts": False,
        }
        if persist:
            save_snapshot(result)
        with _lock:
            _state["cycles"] = int(_state.get("cycles") or 0) + 1
            _state["last_cycle_at"] = result["timestamp_utc"]
            _state["last_duration_ms"] = duration_ms
            _state["last_cycle_id"] = cycle_id
            _state["last_error"] = None
        return result
    except Exception as exc:
        logger.error("health cycle failed: %s", exc, exc_info=True)
        with _lock:
            _state["last_error"] = str(exc)[:300]
        return {
            "ok": False,
            "cycle_id": cycle_id,
            "timestamp_utc": _utc(),
            "error": str(exc)[:500],
            "fake_telemetry": False,
        }


def get_health_status() -> Dict[str, Any]:
    with _lock:
        st = dict(_state)
    snap = load_snapshot()
    return {
        "engine": "health_engine",
        "orchestrator": st,
        "has_snapshot": snap is not None,
        "last_overall": (snap or {}).get("summary", {}).get("overall_status") if snap else None,
        "components_catalog": list(COMPONENT_IDS),
        "policy": POLICY,
    }


_refresh_inflight = False
_refresh_lock = threading.Lock()


def _health_snapshot_is_stale() -> bool:
    import os

    snap = load_snapshot()
    observed_at = (snap or {}).get("timestamp_utc")
    if not snap or not observed_at:
        return True
    stale_sec = int(os.environ.get("NOVUS_HEALTH_STALE_SEC", "60"))
    try:
        from datetime import datetime, timezone

        ts = datetime.strptime(observed_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - ts).total_seconds() > stale_sec
    except Exception:
        return True


def schedule_health_status_refresh_if_stale() -> None:
    """Encola refresh pesado en background — single-flight, respeta backpressure."""
    global _refresh_inflight
    if not _health_snapshot_is_stale():
        return
    try:
        from services.resource_backpressure_service import CAT_HEAVY_AGG, should_run_background

        if not should_run_background(CAT_HEAVY_AGG):
            return
    except Exception:
        pass
    with _refresh_lock:
        if _refresh_inflight:
            return
        _refresh_inflight = True

    def _worker() -> None:
        global _refresh_inflight
        try:
            from services.lazy_engine_manager import start_if_needed

            start_if_needed("health_engine")
            run_health_cycle(publish=True, self_heal=True, persist=True)
            from services.performance_cache import invalidate

            invalidate("health_status_api")
        except Exception as exc:
            logger.debug("health scheduled refresh: %s", exc)
        finally:
            with _refresh_lock:
                _refresh_inflight = False

    threading.Thread(target=_worker, daemon=True, name="HealthStatusRefresh").start()


def get_health_status_response(*, trigger_refresh: bool = False) -> Dict[str, Any]:
    """
    Respuesta rápida para API HTTP — último snapshot REAL sin ejecutar probe_all en request.
    """
    from services.health_engine.orchestrator import get_health_orchestrator_status

    snap = load_snapshot()
    orch = get_health_orchestrator_status()
    stale = _health_snapshot_is_stale()

    if trigger_refresh and stale:
        schedule_health_status_refresh_if_stale()

    summary = (snap or {}).get("summary") or {}
    observed_at = (snap or {}).get("timestamp_utc")
    if stale or not snap:
        stale_label = observed_at or "desconocida"
        return {
            "engine": "health_engine",
            "source": "services.health_engine.store.LAST_SNAPSHOT",
            "source_type": "snapshot",
            "observed_at": observed_at,
            "confidence": "stale" if snap else "unknown",
            "data_freshness": "STALE" if snap else "NOT_AVAILABLE",
            "status": STATUS_UNAVAILABLE,
            "status_label": "Datos no disponibles",
            "snapshot_stale": True,
            "snapshot_pending": snap is None,
            "user_message": (
                f"Datos de salud temporalmente no disponibles. "
                f"Última actualización: {stale_label}."
            ),
            "orchestrator": orch,
            "summary": {},
            "host": {},
            "components": [],
            "cycle_id": (snap or {}).get("cycle_id"),
            "duration_ms_last_cycle": (snap or {}).get("duration_ms"),
            "policy": POLICY,
            "limitations": LIMITATIONS,
        }
    return {
        "engine": "health_engine",
        "source": "services.health_engine.store.LAST_SNAPSHOT",
        "source_type": "snapshot",
        "observed_at": observed_at,
        "confidence": "verified",
        "data_freshness": "LIVE",
        "status": summary.get("overall_status") if summary else NA,
        "status_label": summary.get("overall_status_label") if summary else NA,
        "snapshot_stale": False,
        "snapshot_pending": False,
        "orchestrator": orch,
        "summary": summary,
        "host": (snap or {}).get("host") or {},
        "components": (snap or {}).get("components") or [],
        "cycle_id": (snap or {}).get("cycle_id"),
        "duration_ms_last_cycle": (snap or {}).get("duration_ms"),
        "policy": POLICY,
        "limitations": LIMITATIONS,
    }


def get_health_dashboard() -> Dict[str, Any]:
    snap = load_snapshot()
    if not snap:
        def _bg() -> None:
            try:
                run_health_cycle(publish=False, self_heal=False, persist=True)
            except Exception as exc:
                logger.debug("health dashboard bg: %s", exc)

        threading.Thread(target=_bg, daemon=True, name="HealthDashboardBoot").start()
        return {
            "generated_at_utc": _utc(),
            "summary": {},
            "host": {},
            "components": [],
            "issues": [],
            "alerts": [],
            "alerts_history": [],
            "history": [],
            "self_heal_history": [],
            "cycle_id": None,
            "timestamp_utc": None,
            "policy": POLICY,
            "limitations": LIMITATIONS,
            "na_sentinel": NA,
            "realtime_note": "Snapshot pendiente — ciclo en background. No bloquear HTTP.",
            "snapshot_pending": True,
        }
    history = read_jsonl_tail(HISTORY_PATH, limit=50)
    alerts_hist = read_jsonl_tail(ALERTS_PATH, limit=50)
    heals = read_jsonl_tail(HEAL_LOG, limit=30)
    return {
        "generated_at_utc": _utc(),
        "summary": snap.get("summary") or {},
        "host": snap.get("host") or {},
        "components": snap.get("components") or [],
        "issues": snap.get("issues") or [],
        "alerts": snap.get("alerts") or [],
        "alerts_history": alerts_hist,
        "history": history,
        "self_heal_history": heals,
        "cycle_id": snap.get("cycle_id"),
        "timestamp_utc": snap.get("timestamp_utc"),
        "policy": POLICY,
        "limitations": LIMITATIONS,
        "na_sentinel": NA,
        "realtime_note": "Datos del último ciclo real; refrescar vía /api/health/cycle o orquestador.",
    }
