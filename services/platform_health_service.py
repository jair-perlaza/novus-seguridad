"""
Platform Health Center — telemetría operativa real de motores NOVUS.
Cada motor se consulta en su fuente canónica; sin estados simulados.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import psutil

from utils.logger import logger

_NOVUS_BOOT = time.time()
_PROCESS = psutil.Process(os.getpid())

ENGINE_IDS = (
    "network_monitor_engine",
    "asset_intelligence_engine",
    "ai_kernel",
    "adaptive_defense_engine",
    "universal_compatibility_engine",
    "cryptovault",
    "threat_intelligence",
    "api_protection",
    "topology_engine",
    "report_engine",
)

ENGINE_LABELS = {
    "network_monitor_engine": "Network Monitor Engine",
    "asset_intelligence_engine": "Asset Intelligence Engine",
    "ai_kernel": "Kernel IA",
    "adaptive_defense_engine": "Adaptive Defense Engine",
    "universal_compatibility_engine": "Universal Compatibility Engine",
    "cryptovault": "CryptoVault",
    "threat_intelligence": "Threat Intelligence",
    "api_protection": "API Protection",
    "topology_engine": "Topology Engine",
    "report_engine": "Report Engine",
}

STATUS_ACTIVE = "activo"
STATUS_DEGRADED = "degradado"
STATUS_STOPPED = "detenido"


def _format_uptime(sec: Optional[float]) -> str:
    if sec is None:
        return "—"
    sec = int(max(0, sec))
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(str(value)[:19], fmt)
        except ValueError:
            continue
    return None


def _process_resources() -> Tuple[Optional[float], Optional[float]]:
    """CPU/RAM del proceso NOVUS — telemetría real compartida entre hilos."""
    try:
        cpu = _PROCESS.cpu_percent(interval=0)
        mem_mb = _PROCESS.memory_info().rss / (1024 * 1024)
        return round(cpu, 1), round(mem_mb, 1)
    except Exception:
        return None, None


def _compute_health_score(
    status: str,
    *,
    error_count: int = 0,
    stale_sec: Optional[int] = None,
    stale_threshold: int = 300,
) -> int:
    base = {"activo": 92, "degradado": 55, "detenido": 10}.get(status, 40)
    score = base
    score -= min(30, error_count * 5)
    if stale_sec is not None and stale_sec > stale_threshold:
        overdue = min(25, (stale_sec - stale_threshold) // 60)
        score -= overdue
    return max(0, min(100, score))


def _status_from_flags(active: bool, degraded: bool = False) -> str:
    if not active:
        return STATUS_STOPPED
    if degraded:
        return STATUS_DEGRADED
    return STATUS_ACTIVE


def _probe_network_monitor() -> Dict[str, Any]:
    from services.network_monitor_engine import get_monitor_status

    st = get_monitor_status()
    active = bool(st.get("active"))
    error_count = int(st.get("error_count") or 0)
    last_error = st.get("last_error")
    stale = st.get("seconds_since_last_scan")
    degraded = error_count > 0 or (active and stale is not None and stale > 120)
    status = _status_from_flags(active, degraded)
    return {
        "engine_id": "network_monitor_engine",
        "label": ENGINE_LABELS["network_monitor_engine"],
        "status": status,
        "status_label": status.capitalize(),
        "uptime_sec": st.get("uptime_sec"),
        "uptime_label": st.get("uptime_label") or _format_uptime(st.get("uptime_sec")),
        "last_execution": st.get("last_scan_at"),
        "last_sync": st.get("last_scan_at"),
        "cpu_percent": st.get("cpu_percent"),
        "memory_mb": st.get("memory_mb"),
        "events_processed": int(st.get("scan_count") or 0),
        "last_error": last_error,
        "health_score": _compute_health_score(status, error_count=error_count, stale_sec=stale, stale_threshold=60),
        "details": {
            "mode": st.get("mode_label"),
            "devices_monitored": st.get("devices_monitored"),
            "revision": st.get("revision"),
        },
    }


def _probe_asset_intelligence() -> Dict[str, Any]:
    from services.asset_intelligence_engine import get_inventory_summary
    from database import SessionLocal, NetworkDeviceInventory

    summary = get_inventory_summary()
    last_seen = None
    db = SessionLocal()
    try:
        row = (
            db.query(NetworkDeviceInventory.last_seen)
            .filter(NetworkDeviceInventory.last_seen.isnot(None))
            .order_by(NetworkDeviceInventory.last_seen.desc())
            .first()
        )
        if row:
            last_seen = row[0]
        event_count = db.query(NetworkDeviceInventory).count()
    finally:
        db.close()

    cpu, mem = _process_resources()
    stale = None
    ts = _parse_ts(last_seen)
    if ts:
        stale = int((datetime.now() - ts).total_seconds())
    active = event_count > 0 or summary.get("total", 0) >= 0
    degraded = stale is not None and stale > 600
    status = STATUS_ACTIVE if active else STATUS_DEGRADED
    if degraded:
        status = STATUS_DEGRADED

    return {
        "engine_id": "asset_intelligence_engine",
        "label": ENGINE_LABELS["asset_intelligence_engine"],
        "status": status,
        "status_label": status.capitalize(),
        "uptime_sec": int(time.time() - _NOVUS_BOOT),
        "uptime_label": _format_uptime(time.time() - _NOVUS_BOOT),
        "last_execution": last_seen,
        "last_sync": last_seen,
        "cpu_percent": cpu,
        "memory_mb": mem,
        "events_processed": event_count,
        "last_error": None,
        "health_score": _compute_health_score(status, stale_sec=stale, stale_threshold=600),
        "details": summary,
    }


def _probe_ai_kernel() -> Dict[str, Any]:
    from services.ai_kernel import ai_kernel

    st = ai_kernel.get_status()
    running = bool(st.get("running"))
    logs_raw = st.get("logs")
    last_error = None
    last_sync = None
    if isinstance(logs_raw, str):
        if "error" in logs_raw.lower():
            last_error = logs_raw[:300]
        last_sync = logs_raw[:80] if logs_raw else None
    elif isinstance(logs_raw, list):
        for entry in reversed(logs_raw[-20:]):
            if not isinstance(entry, dict):
                continue
            msg = str(entry.get("message") or entry.get("content") or "")
            if "error" in msg.lower() or entry.get("level") == "error":
                last_error = msg[:300]
                break
        if logs_raw:
            tail = logs_raw[-1]
            last_sync = tail.get("time") if isinstance(tail, dict) else str(tail)[:80]

    cpu, mem = _process_resources()
    degraded = not st.get("guardia") and running
    status = _status_from_flags(running, degraded)
    return {
        "engine_id": "ai_kernel",
        "label": ENGINE_LABELS["ai_kernel"],
        "status": status,
        "status_label": status.capitalize(),
        "uptime_sec": int(time.time() - _NOVUS_BOOT) if running else 0,
        "uptime_label": _format_uptime(time.time() - _NOVUS_BOOT) if running else "—",
        "last_execution": st.get("activity"),
        "last_sync": last_sync,
        "cpu_percent": cpu if running else None,
        "memory_mb": mem if running else None,
        "events_processed": int(st.get("sessions_active") or 0),
        "last_error": last_error,
        "health_score": _compute_health_score(status, error_count=1 if last_error else 0),
        "details": {"activity": st.get("activity"), "guardia": st.get("guardia")},
    }


def _probe_adaptive_defense() -> Dict[str, Any]:
    from services.adaptive_defense_engine import _load_state, _read_actions

    state = _load_state()
    actions = _read_actions(200)
    response_actions = [a for a in actions if a.get("event") == "adaptive_response"]
    last_ts = None
    if response_actions:
        last_ts = response_actions[-1].get("timestamp")
    elif state.get("updated_at"):
        last_ts = state.get("updated_at")

    failed = sum(1 for a in actions if any(
        act.get("status") == "failed" for act in (a.get("actions") or [])
    ))
    last_error = None
    for a in reversed(actions):
        for act in a.get("actions") or []:
            if act.get("status") == "failed":
                last_error = act.get("detail") or act.get("action")
                break
        if last_error:
            break

    containments = state.get("active_containments") or []
    active = bool(response_actions or containments or state.get("last_level"))
    degraded = failed > 0 or bool(containments)
    status = _status_from_flags(active or True, degraded)
    cpu, mem = _process_resources()

    return {
        "engine_id": "adaptive_defense_engine",
        "label": ENGINE_LABELS["adaptive_defense_engine"],
        "status": status,
        "status_label": status.capitalize(),
        "uptime_sec": int(time.time() - _NOVUS_BOOT),
        "uptime_label": _format_uptime(time.time() - _NOVUS_BOOT),
        "last_execution": last_ts,
        "last_sync": last_ts,
        "cpu_percent": cpu,
        "memory_mb": mem,
        "events_processed": len(actions),
        "last_error": last_error,
        "health_score": _compute_health_score(status, error_count=failed),
        "details": {
            "contenciones_activas": len(containments),
            "ultimo_nivel": state.get("last_level"),
        },
    }


def _probe_uce() -> Dict[str, Any]:
    from services.universal_compatibility_engine import get_infrastructure_panel

    panel = get_infrastructure_panel()
    detected_at = panel.get("detected_at")
    items = panel.get("detected_items") or panel.get("technologies") or []
    cpu, mem = _process_resources()
    stale = None
    ts = _parse_ts(detected_at)
    if ts:
        stale = int((datetime.now() - ts).total_seconds())
    active = bool(detected_at)
    degraded = stale is not None and stale > 3600
    status = _status_from_flags(active, degraded)

    return {
        "engine_id": "universal_compatibility_engine",
        "label": ENGINE_LABELS["universal_compatibility_engine"],
        "status": status,
        "status_label": status.capitalize(),
        "uptime_sec": int(time.time() - _NOVUS_BOOT),
        "uptime_label": _format_uptime(time.time() - _NOVUS_BOOT),
        "last_execution": detected_at,
        "last_sync": detected_at,
        "cpu_percent": cpu,
        "memory_mb": mem,
        "events_processed": len(items),
        "last_error": panel.get("error"),
        "health_score": _compute_health_score(status, stale_sec=stale, stale_threshold=3600),
        "details": {"technologies": len(items), "modules": panel.get("compatible_modules") or []},
    }


def _probe_cryptovault() -> Dict[str, Any]:
    result: Dict[str, Any] = {"last_error": None}
    active = False
    degraded = False
    last_exec = None
    events = 0

    boot_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "defense_boot_report.json")
    if os.path.isfile(boot_path):
        try:
            with open(boot_path, "r", encoding="utf-8") as fh:
                boot = json.load(fh)
            cv = (boot.get("components") or {}).get("cryptovault") or {}
            last_exec = boot.get("generated_at") or boot.get("timestamp")
            active = cv.get("status") == "success"
            degraded = cv.get("status") == "failed"
            if cv.get("error"):
                result["last_error"] = cv.get("error")
            events = 1 if active else 0
        except Exception as exc:
            result["last_error"] = str(exc)
            degraded = True

    if not last_exec:
        try:
            from crypto_vault import CryptoVault

            vault = CryptoVault()
            health = vault.verify_health() if hasattr(vault, "verify_health") else {}
            if health:
                last_exec = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                active = health.get("status") == "success"
                degraded = not active
                if health.get("error"):
                    result["last_error"] = health.get("error")
                events = 1
        except Exception as exc:
            result["last_error"] = str(exc)
            degraded = True

    status = _status_from_flags(active, degraded)
    cpu, mem = _process_resources()
    result.update({
        "engine_id": "cryptovault",
        "label": ENGINE_LABELS["cryptovault"],
        "status": status,
        "status_label": status.capitalize(),
        "uptime_sec": int(time.time() - _NOVUS_BOOT) if active else 0,
        "uptime_label": _format_uptime(time.time() - _NOVUS_BOOT) if active else "—",
        "last_execution": last_exec,
        "last_sync": last_exec,
        "cpu_percent": cpu if active else None,
        "memory_mb": mem if active else None,
        "events_processed": events,
        "health_score": _compute_health_score(status, error_count=1 if result.get("last_error") else 0),
        "details": {"aes_key": os.path.isfile("master_aes.key")},
    })
    return result


def _probe_threat_intelligence() -> Dict[str, Any]:
    from services.threat_intelligence_service import threat_intelligence
    from database import SessionLocal, InteligenciaCaso

    stats = threat_intelligence.stats()
    last_case = None
    db = SessionLocal()
    try:
        row = db.query(InteligenciaCaso.fecha).order_by(InteligenciaCaso.fecha.desc()).first()
        if row:
            last_case = row[0]
    finally:
        db.close()

    cpu, mem = _process_resources()
    total = int(stats.get("total") or 0)
    active = True
    status = STATUS_ACTIVE
    return {
        "engine_id": "threat_intelligence",
        "label": ENGINE_LABELS["threat_intelligence"],
        "status": status,
        "status_label": status.capitalize(),
        "uptime_sec": int(time.time() - _NOVUS_BOOT),
        "uptime_label": _format_uptime(time.time() - _NOVUS_BOOT),
        "last_execution": last_case,
        "last_sync": last_case,
        "cpu_percent": cpu,
        "memory_mb": mem,
        "events_processed": total,
        "last_error": None,
        "health_score": _compute_health_score(status),
        "details": stats,
    }


def _probe_api_protection() -> Dict[str, Any]:
    from services.defense_evidence_registry import list_recent_events

    events = [e for e in list_recent_events(limit=2000) if e.get("motor") == "api_security_service"]
    blocked = [e for e in events if e.get("outcome") in ("blocked", "failed")]
    last_ts = events[-1].get("timestamp") if events else None
    last_error = None
    for e in reversed(blocked):
        if e.get("outcome") == "failed":
            last_error = e.get("detail")
            break

    cpu, mem = _process_resources()
    active = True
    status = STATUS_ACTIVE
    return {
        "engine_id": "api_protection",
        "label": ENGINE_LABELS["api_protection"],
        "status": status,
        "status_label": status.capitalize(),
        "uptime_sec": int(time.time() - _NOVUS_BOOT),
        "uptime_label": _format_uptime(time.time() - _NOVUS_BOOT),
        "last_execution": last_ts,
        "last_sync": last_ts,
        "cpu_percent": cpu,
        "memory_mb": mem,
        "events_processed": len(events),
        "last_error": last_error,
        "health_score": _compute_health_score(status, error_count=len([e for e in blocked if e.get("outcome") == "failed"])),
        "details": {"blocked_requests": len(blocked), "total_api_events": len(events)},
    }


def _probe_topology() -> Dict[str, Any]:
    """Usa caché ARP/topology existente — no dispara escaneo completo en health check."""
    from services.network_scanner import network_scanner
    from services.network_monitor_engine import get_monitor_status
    from services.performance_cache import peek_cached

    nme = get_monitor_status()
    nodes = network_scanner.get_cached_nodes() or []
    payload = peek_cached("topology_payload") or {}
    meta = payload.get("meta") or {}
    generated = meta.get("generated_at") or meta.get("refreshed_at") or nme.get("last_scan_at")
    connections = payload.get("connections") or []
    if payload.get("nodes"):
        nodes = payload.get("nodes") or nodes

    stale = None
    ts = _parse_ts(generated)
    if ts:
        stale = int((datetime.now() - ts).total_seconds())

    active = bool(nodes)
    degraded = stale is not None and stale > 300
    status = _status_from_flags(active, degraded)
    cpu, mem = _process_resources()

    return {
        "engine_id": "topology_engine",
        "label": ENGINE_LABELS["topology_engine"],
        "status": status,
        "status_label": status.capitalize(),
        "uptime_sec": int(time.time() - _NOVUS_BOOT),
        "uptime_label": _format_uptime(time.time() - _NOVUS_BOOT),
        "last_execution": generated,
        "last_sync": generated,
        "cpu_percent": cpu,
        "memory_mb": mem,
        "events_processed": len(nodes) + len(connections),
        "last_error": payload.get("error"),
        "health_score": _compute_health_score(status, stale_sec=stale, stale_threshold=300),
        "details": {"nodes": len(nodes), "connections": len(connections)},
    }


def _probe_report_engine() -> Dict[str, Any]:
    from services.security_report_service import list_reports

    reports = list_reports(limit=500)
    last_ts = reports[0].get("generated_at") if reports else None
    cpu, mem = _process_resources()
    active = True
    status = STATUS_ACTIVE
    return {
        "engine_id": "report_engine",
        "label": ENGINE_LABELS["report_engine"],
        "status": status,
        "status_label": status.capitalize(),
        "uptime_sec": int(time.time() - _NOVUS_BOOT),
        "uptime_label": _format_uptime(time.time() - _NOVUS_BOOT),
        "last_execution": last_ts,
        "last_sync": last_ts,
        "cpu_percent": cpu,
        "memory_mb": mem,
        "events_processed": len(reports),
        "last_error": None,
        "health_score": _compute_health_score(status),
        "details": {"reports_total": len(reports)},
    }


_PROBES = {
    "network_monitor_engine": _probe_network_monitor,
    "asset_intelligence_engine": _probe_asset_intelligence,
    "ai_kernel": _probe_ai_kernel,
    "adaptive_defense_engine": _probe_adaptive_defense,
    "universal_compatibility_engine": _probe_uce,
    "cryptovault": _probe_cryptovault,
    "threat_intelligence": _probe_threat_intelligence,
    "api_protection": _probe_api_protection,
    "topology_engine": _probe_topology,
    "report_engine": _probe_report_engine,
}


def probe_engine(engine_id: str) -> Dict[str, Any]:
    fn = _PROBES.get(engine_id)
    if not fn:
        return {"engine_id": engine_id, "status": STATUS_STOPPED, "health_score": 0, "error": "motor desconocido"}
    try:
        return fn()
    except Exception as exc:
        logger.error("platform_health probe %s: %s", engine_id, exc)
        return {
            "engine_id": engine_id,
            "label": ENGINE_LABELS.get(engine_id, engine_id),
            "status": STATUS_DEGRADED,
            "status_label": "Degradado",
            "uptime_sec": None,
            "uptime_label": "—",
            "last_execution": None,
            "last_sync": None,
            "cpu_percent": None,
            "memory_mb": None,
            "events_processed": 0,
            "last_error": str(exc),
            "health_score": 25,
            "details": {},
        }


def get_platform_health() -> Dict[str, Any]:
    """Estado operativo de todos los motores supervisados."""
    engines = [probe_engine(eid) for eid in ENGINE_IDS]
    scores = [e.get("health_score") or 0 for e in engines]
    avg_score = round(sum(scores) / max(len(scores), 1), 1)

    stopped = sum(1 for e in engines if e.get("status") == STATUS_STOPPED)
    degraded = sum(1 for e in engines if e.get("status") == STATUS_DEGRADED)
    active = sum(1 for e in engines if e.get("status") == STATUS_ACTIVE)

    if stopped > len(engines) // 2:
        overall = STATUS_DEGRADED
    elif degraded > 0 or avg_score < 70:
        overall = STATUS_DEGRADED if avg_score >= 40 else STATUS_STOPPED
    else:
        overall = STATUS_ACTIVE

    cpu, mem = _process_resources()
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "platform_uptime_sec": int(time.time() - _NOVUS_BOOT),
        "platform_uptime_label": _format_uptime(time.time() - _NOVUS_BOOT),
        "overall_status": overall,
        "overall_status_label": overall.capitalize(),
        "overall_health_score": avg_score,
        "engines_active": active,
        "engines_degraded": degraded,
        "engines_stopped": stopped,
        "process_cpu_percent": cpu,
        "process_memory_mb": mem,
        "engines": engines,
    }
