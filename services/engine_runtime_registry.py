"""
Registro canónico de estado RUNTIME de motores NOVUS.
Separa implementación (catálogo) de ejecución verificable (telemetría/probes).
"""
from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

from utils.logger import logger

_runtime_summary_lock = threading.Lock()
_runtime_summary_cache: tuple = (0.0, {}, None)
_runtime_summary_inflight: Dict[Any, threading.Event] = {}

RUNTIME_RUNNING = "running"
RUNTIME_ACTIVE = "active"
RUNTIME_IDLE = "idle"
RUNTIME_PAUSED = "paused"
RUNTIME_STOPPED = "stopped"
RUNTIME_ERROR = "error"
RUNTIME_NOT_CONFIGURED = "not_configured"
RUNTIME_NOT_IMPLEMENTED = "not_implemented"
RUNTIME_NOT_VERIFIABLE = "not_verifiable"

IMPLEMENTATION_IMPLEMENTED = "implemented"
IMPLEMENTATION_PLANNED = "planned"
IMPLEMENTATION_NEEDS_INTEGRATION = "needs_integration"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _row(
    engine_id: str,
    engine_name: str,
    *,
    implementation_status: str,
    runtime_status: str,
    started_at: Optional[str] = None,
    last_execution_at: Optional[str] = None,
    last_cycle_at: Optional[str] = None,
    last_success_at: Optional[str] = None,
    last_error_at: Optional[str] = None,
    execution_count: Optional[int] = None,
    health: Optional[str] = None,
    telemetry_available: bool = False,
    error_message: Optional[str] = None,
    detail: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "engine_id": engine_id,
        "engine_name": engine_name,
        "implementation_status": implementation_status,
        "runtime_status": runtime_status,
        "started_at": started_at,
        "last_execution_at": last_execution_at,
        "last_cycle_at": last_cycle_at,
        "last_success_at": last_success_at,
        "last_error_at": last_error_at,
        "execution_count": execution_count,
        "health": health,
        "telemetry_available": telemetry_available,
        "error_message": error_message,
        "detail": detail,
        "observed_at": _utc_now(),
    }


def _from_live_active(
    engine_id: str,
    engine_name: str,
    live: Dict[str, Any],
    *,
    impl: str = IMPLEMENTATION_IMPLEMENTED,
    active_keys: tuple = ("active", "running"),
    cycle_keys: tuple = ("last_cycle_at", "last_scan_at", "last_execution_at"),
) -> Dict[str, Any]:
    if not live:
        return _row(
            engine_id,
            engine_name,
            implementation_status=impl,
            runtime_status=RUNTIME_NOT_VERIFIABLE,
            telemetry_available=False,
        )
    is_active = any(live.get(k) for k in active_keys)
    last_cycle = next((live.get(k) for k in cycle_keys if live.get(k)), None)
    last_err = live.get("last_error") or live.get("error")
    cycles = live.get("cycles") or live.get("execution_count")
    if last_err and not is_active:
        rt = RUNTIME_ERROR
    elif is_active and last_cycle:
        rt = RUNTIME_RUNNING
    elif is_active:
        rt = RUNTIME_IDLE
    else:
        rt = RUNTIME_STOPPED
    return _row(
        engine_id,
        engine_name,
        implementation_status=impl,
        runtime_status=rt,
        started_at=live.get("started_at"),
        last_execution_at=live.get("last_execution_at") or last_cycle,
        last_cycle_at=last_cycle,
        last_success_at=live.get("last_success_at"),
        last_error_at=last_err,
        execution_count=int(cycles) if isinstance(cycles, (int, float)) else None,
        health=live.get("status") or live.get("engine_state"),
        telemetry_available=True,
        error_message=str(last_err)[:300] if last_err else None,
        detail=str(live.get("summary") or live.get("detail") or "")[:200] or None,
    )


def _probe_network_monitor() -> Dict[str, Any]:
    try:
        from services.network_monitor_engine import get_monitor_status

        live = get_monitor_status() or {}
        row = _from_live_active("network_monitor", "Network Monitor", live)
        if live.get("active") and not live.get("last_scan_at"):
            row["runtime_status"] = RUNTIME_IDLE
        return row
    except Exception as exc:
        return _row(
            "network_monitor",
            "Network Monitor",
            implementation_status=IMPLEMENTATION_IMPLEMENTED,
            runtime_status=RUNTIME_ERROR,
            error_message=str(exc)[:300],
        )


def _probe_web_shield() -> Dict[str, Any]:
    try:
        from services.web_shield_engine import get_engine_status

        live = get_engine_status() or {}
        inner = live.get("status") if isinstance(live.get("status"), dict) else live
        row = _from_live_active("web_shield", "Web Shield", inner)
        if inner.get("active") and inner.get("last_cycle_at"):
            row["runtime_status"] = RUNTIME_RUNNING
            row["last_cycle_at"] = inner.get("last_cycle_at")
            row["execution_count"] = inner.get("cycles")
        elif inner.get("active"):
            row["runtime_status"] = RUNTIME_IDLE
        return row
    except Exception as exc:
        return _row(
            "web_shield",
            "Web Shield",
            implementation_status=IMPLEMENTATION_IMPLEMENTED,
            runtime_status=RUNTIME_ERROR,
            error_message=str(exc)[:300],
        )


def _probe_mail_shield() -> Dict[str, Any]:
    try:
        from services.mail_shield_engine import get_engine_status

        live = get_engine_status() or {}
        connected = (live.get("integrations") or {}).get("any_connected")
        if not connected:
            return _row(
                "mail_shield",
                "Mail Shield",
                implementation_status=IMPLEMENTATION_NEEDS_INTEGRATION,
                runtime_status=RUNTIME_NOT_CONFIGURED,
                telemetry_available=True,
                detail=(live.get("integrations") or {}).get("summary_message"),
                error_message="OAuth/correo no configurado",
            )
        return _from_live_active("mail_shield", "Mail Shield", live)
    except Exception as exc:
        return _row(
            "mail_shield",
            "Mail Shield",
            implementation_status=IMPLEMENTATION_NEEDS_INTEGRATION,
            runtime_status=RUNTIME_NOT_CONFIGURED,
            error_message=str(exc)[:300],
        )


def _probe_threat_scanner() -> Dict[str, Any]:
    try:
        from services.novus_security_integration import novus_security

        cache = dict(novus_security._threat_cache or {})
        scanning = bool(getattr(novus_security, "_threat_scanning", False))
        last_scan = cache.get("last_scan")
        audit = cache.get("scan_audit") or {}
        if scanning:
            rt = RUNTIME_RUNNING
        elif last_scan:
            rt = RUNTIME_ACTIVE
        else:
            rt = RUNTIME_STOPPED
        return _row(
            "threat_scanner",
            "Threat Scanner",
            implementation_status=IMPLEMENTATION_IMPLEMENTED,
            runtime_status=rt,
            last_execution_at=last_scan,
            last_cycle_at=last_scan,
            execution_count=audit.get("execution_count"),
            health="scanning" if scanning else ("ready" if last_scan else "never_run"),
            telemetry_available=True,
            detail=f"verified_threats={novus_security.get_cached_threat_count()}",
        )
    except Exception as exc:
        return _row(
            "threat_scanner",
            "Threat Scanner",
            implementation_status=IMPLEMENTATION_IMPLEMENTED,
            runtime_status=RUNTIME_ERROR,
            error_message=str(exc)[:300],
        )


def _probe_vulnerability_scanner() -> Dict[str, Any]:
    try:
        from services.novus_security_integration import novus_security

        cache = dict(novus_security._threat_cache or {})
        audit = cache.get("vulnerabilities_audit") or {}
        ts = audit.get("timestamp")
        pending = cache.get("vulnerabilities") is None and not ts
        if pending:
            rt = RUNTIME_STOPPED
        elif ts:
            rt = RUNTIME_ACTIVE
        else:
            rt = RUNTIME_STOPPED
        vulns = cache.get("vulnerabilities")
        count = len(vulns) if isinstance(vulns, list) else None
        return _row(
            "vulnerability_scanner",
            "Vulnerability Scanner",
            implementation_status=IMPLEMENTATION_IMPLEMENTED,
            runtime_status=rt,
            last_execution_at=ts,
            last_cycle_at=ts,
            telemetry_available=True,
            detail=f"findings={count}" if count is not None else "sin_analisis",
        )
    except Exception as exc:
        return _row(
            "vulnerability_scanner",
            "Vulnerability Scanner",
            implementation_status=IMPLEMENTATION_IMPLEMENTED,
            runtime_status=RUNTIME_ERROR,
            error_message=str(exc)[:300],
        )


def _probe_ai_kernel() -> Dict[str, Any]:
    try:
        from services.ai_kernel import ai_kernel

        st = ai_kernel.get_status() or {}
        op = str(st.get("operational_status") or "STOPPED").upper()
        mapping = {
            "ACTIVE": RUNTIME_ACTIVE,
            "IDLE": RUNTIME_IDLE,
            "STOPPED": RUNTIME_STOPPED,
            "ERROR": RUNTIME_ERROR,
            "DEGRADED": RUNTIME_IDLE,
        }
        rt = mapping.get(op, RUNTIME_NOT_VERIFIABLE)
        return _row(
            "ai_kernel",
            "AI Kernel",
            implementation_status=IMPLEMENTATION_IMPLEMENTED,
            runtime_status=rt,
            started_at=st.get("started_at"),
            last_execution_at=st.get("last_execution_at"),
            last_error_at=st.get("last_execution_error"),
            health=op.lower(),
            telemetry_available=True,
            error_message=st.get("last_execution_error"),
            detail=f"sessions={st.get('sessions_active', 0)}",
        )
    except Exception as exc:
        return _row(
            "ai_kernel",
            "AI Kernel",
            implementation_status=IMPLEMENTATION_IMPLEMENTED,
            runtime_status=RUNTIME_ERROR,
            error_message=str(exc)[:300],
        )


def _probe_lazy(name: str, label: str) -> Dict[str, Any]:
    try:
        from services.lazy_engine_manager import engine_status, STATE_DEGRADED, STATE_ERROR, STATE_RUNNING, STATE_STARTING

        st = engine_status(name)
        state = st.get("state")
        live = st.get("live") or {}
        if state == STATE_DEGRADED:
            rt = RUNTIME_PAUSED
        elif state == STATE_ERROR:
            rt = RUNTIME_ERROR
        elif state == STATE_RUNNING or st.get("engine_running"):
            rt = RUNTIME_RUNNING if live.get("last_cycle_at") else RUNTIME_IDLE
        elif state == STATE_STARTING:
            rt = RUNTIME_RUNNING
        else:
            rt = RUNTIME_STOPPED
        return _row(
            name,
            label,
            implementation_status=IMPLEMENTATION_IMPLEMENTED,
            runtime_status=rt,
            started_at=live.get("started_at") or st.get("started_at"),
            last_cycle_at=live.get("last_cycle_at"),
            health=state,
            telemetry_available=bool(live),
            error_message=st.get("error"),
            detail=str(live)[:200] if live else None,
        )
    except Exception as exc:
        return _row(
            name,
            label,
            implementation_status=IMPLEMENTATION_IMPLEMENTED,
            runtime_status=RUNTIME_NOT_VERIFIABLE,
            error_message=str(exc)[:300],
        )


def _probe_swarm() -> Dict[str, Any]:
    try:
        from services.swarm_defense import swarm_defense_engine

        st = swarm_defense_engine.status() or {}
        ok = bool(st.get("ok"))
        err = st.get("error")
        if err:
            rt = RUNTIME_ERROR
        elif ok:
            rt = RUNTIME_IDLE
        else:
            rt = RUNTIME_STOPPED
        return _row(
            "swarm_defense",
            "Swarm Defense",
            implementation_status=IMPLEMENTATION_IMPLEMENTED,
            runtime_status=rt,
            telemetry_available=True,
            error_message=str(err)[:300] if err else None,
            detail=str((st.get("mesh") or {}))[:200],
        )
    except Exception as exc:
        return _row(
            "swarm_defense",
            "Swarm Defense",
            implementation_status=IMPLEMENTATION_IMPLEMENTED,
            runtime_status=RUNTIME_NOT_VERIFIABLE,
            error_message=str(exc)[:300],
        )


def _probe_adaptive_profile() -> Dict[str, Any]:
    try:
        from services.adaptive_profile_engine import engine_status as ape_status

        live = ape_status() or {}
        return _from_live_active("adaptive_profile_engine", "Adaptive Profile Engine", live)
    except Exception as exc:
        return _row(
            "adaptive_profile_engine",
            "Adaptive Profile Engine",
            implementation_status=IMPLEMENTATION_IMPLEMENTED,
            runtime_status=RUNTIME_NOT_VERIFIABLE,
            error_message=str(exc)[:300],
        )


def _probe_cloud_shield() -> Dict[str, Any]:
    try:
        from services.shield_platform_registry import list_shields

        cloud = next((s for s in list_shields() if s.get("id") == "cloud_shield"), {})
        if cloud.get("status") == "planned":
            return _row(
                "cloud_shield",
                "Cloud Shield",
                implementation_status=IMPLEMENTATION_PLANNED,
                runtime_status=RUNTIME_NOT_IMPLEMENTED,
                detail=cloud.get("description"),
            )
        return _row(
            "cloud_shield",
            "Cloud Shield",
            implementation_status=IMPLEMENTATION_IMPLEMENTED,
            runtime_status=RUNTIME_STOPPED,
        )
    except Exception as exc:
        return _row(
            "cloud_shield",
            "Cloud Shield",
            implementation_status=IMPLEMENTATION_PLANNED,
            runtime_status=RUNTIME_NOT_IMPLEMENTED,
            error_message=str(exc)[:300],
        )


def collect_engine_runtime_rows(
    *,
    user_id: Optional[int] = None,
    implemented_ids: Optional[Set[str]] = None,
    include_catalog_stubs: bool = True,
) -> List[Dict[str, Any]]:
    """Recopila estado runtime de motores principales."""
    rows = [
        _probe_network_monitor(),
        _probe_web_shield(),
        _probe_mail_shield(),
        _probe_threat_scanner(),
        _probe_vulnerability_scanner(),
        _probe_ai_kernel(),
        _probe_swarm(),
        _probe_adaptive_profile(),
        _probe_cloud_shield(),
        _probe_lazy("endpoint_realtime", "Endpoint Realtime Monitor"),
        _probe_lazy("endpoint_enterprise", "Endpoint Enterprise"),
        _probe_lazy("network_endpoint_enterprise", "Network Endpoint Enterprise"),
        _probe_lazy("btde", "Behavioral Threat Detection"),
        _probe_lazy("zdde", "Zero-Day Detection"),
        _probe_lazy("health_engine", "Health Engine"),
    ]
    if not include_catalog_stubs and implemented_ids is None:
        return rows
    try:
        if implemented_ids is None:
            from services.manual_defense_catalog import audit_capabilities

            audit = audit_capabilities(user_id)
            impl_ids = set(audit.get("implemented_mechanisms") or [])
        else:
            impl_ids = set(implemented_ids)
        if not include_catalog_stubs:
            # Solo cuenta implementados vía caller; no materializa 60+ stubs en hot path
            return rows
        probed = {r["engine_id"] for r in rows}
        for mid in impl_ids:
            if mid in probed:
                continue
            rows.append(
                _row(
                    mid,
                    mid.replace("_", " ").title(),
                    implementation_status=IMPLEMENTATION_IMPLEMENTED,
                    runtime_status=RUNTIME_NOT_VERIFIABLE,
                    detail="Catálogo manual — sin probe runtime dedicado",
                )
            )
    except Exception as exc:
        logger.debug("engine_runtime catalog merge: %s", exc)
    return rows


def summarize_runtime(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {
        "implemented": 0,
        "runtime_running": 0,
        "runtime_active": 0,
        "runtime_idle": 0,
        "runtime_paused": 0,
        "runtime_stopped": 0,
        "runtime_error": 0,
        "runtime_not_configured": 0,
        "runtime_not_implemented": 0,
        "runtime_not_verifiable": 0,
    }
    for r in rows:
        if r.get("implementation_status") in (
            IMPLEMENTATION_IMPLEMENTED,
            IMPLEMENTATION_NEEDS_INTEGRATION,
        ):
            counts["implemented"] += 1
        rt = r.get("runtime_status")
        if rt == RUNTIME_RUNNING:
            counts["runtime_running"] += 1
            counts["runtime_active"] += 1
        elif rt == RUNTIME_ACTIVE:
            counts["runtime_active"] += 1
        elif rt == RUNTIME_IDLE:
            counts["runtime_idle"] += 1
        elif rt == RUNTIME_PAUSED:
            counts["runtime_paused"] += 1
        elif rt == RUNTIME_STOPPED:
            counts["runtime_stopped"] += 1
        elif rt == RUNTIME_ERROR:
            counts["runtime_error"] += 1
        elif rt == RUNTIME_NOT_CONFIGURED:
            counts["runtime_not_configured"] += 1
        elif rt == RUNTIME_NOT_IMPLEMENTED:
            counts["runtime_not_implemented"] += 1
        elif rt == RUNTIME_NOT_VERIFIABLE:
            counts["runtime_not_verifiable"] += 1
    return counts


def get_engine_runtime_summary(
    *,
    user_id: Optional[int] = None,
    implemented_ids: Optional[Set[str]] = None,
    include_catalog_stubs: bool = True,
) -> Dict[str, Any]:
    global _runtime_summary_cache
    ttl = float(os.environ.get("NOVUS_ENGINE_RUNTIME_CACHE_TTL", "12"))
    cache_key_uid = (
        user_id,
        include_catalog_stubs,
        None if implemented_ids is None else tuple(sorted(implemented_ids)),
    )
    now = time.time()
    with _runtime_summary_lock:
        cached_at, cached, key = _runtime_summary_cache
        if cached and key == cache_key_uid and (now - cached_at) <= ttl:
            out = dict(cached)
            out["cache_age_sec"] = round(now - cached_at, 2)
            return out
        building = _runtime_summary_inflight.get(cache_key_uid)
        if building is None:
            building = threading.Event()
            _runtime_summary_inflight[cache_key_uid] = building
            leader = True
        else:
            leader = False

    if not leader:
        building.wait(timeout=20.0)
        with _runtime_summary_lock:
            cached_at, cached, key = _runtime_summary_cache
            if cached and key == cache_key_uid:
                out = dict(cached)
                out["cache_age_sec"] = round(time.time() - cached_at, 2)
                return out
            # stale any
            if cached:
                return dict(cached)

    try:
        rows = collect_engine_runtime_rows(
            user_id=user_id,
            implemented_ids=implemented_ids,
            include_catalog_stubs=include_catalog_stubs,
        )
        counts = summarize_runtime(rows)
        if implemented_ids is not None and not include_catalog_stubs:
            counts["implemented"] = max(counts["implemented"], len(implemented_ids))
            counts["runtime_not_verifiable"] = max(
                0, len(implemented_ids) - (counts["runtime_running"] + counts["runtime_active"]
                + counts["runtime_idle"] + counts["runtime_stopped"] + counts["runtime_error"]
                + counts["runtime_not_configured"] + counts["runtime_paused"])
            )
        result = {
            "observed_at": _utc_now(),
            "engines": rows,
            "counts": counts,
            "active_motors_count": counts["runtime_active"],
            "running_motors_count": counts["runtime_running"],
            "source": "services.engine_runtime_registry",
            "catalog_stubs_included": include_catalog_stubs,
        }
        with _runtime_summary_lock:
            _runtime_summary_cache = (time.time(), result, cache_key_uid)
        return result
    finally:
        with _runtime_summary_lock:
            ev = _runtime_summary_inflight.pop(cache_key_uid, None)
        if ev:
            ev.set()
