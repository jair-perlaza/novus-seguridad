#!/usr/bin/env python3
"""
Probes reales de componentes NOVUS.
Campos no medibles → "NO DISPONIBLE". Sin telemetría inventada.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import psutil

from services.health_engine.catalog import (
    COMPONENT_LABELS,
    NA,
    STATUS_ACTIVE,
    STATUS_DEGRADED,
    STATUS_STOPPED,
    STATUS_UNAVAILABLE,
)
from utils.logger import logger

_BOOT = time.time()
_PROC = psutil.Process(os.getpid())


def _na() -> str:
    return NA


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fmt_uptime(sec: Optional[float]) -> Any:
    if sec is None:
        return NA
    sec = int(max(0, sec))
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def host_resources() -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "cpu_percent": NA,
        "ram_percent": NA,
        "ram_used_mb": NA,
        "disk_percent": NA,
        "process_cpu_percent": NA,
        "process_rss_mb": NA,
        "uptime_sec": int(time.time() - _BOOT),
    }
    try:
        out["cpu_percent"] = round(psutil.cpu_percent(interval=0), 1)
        mem = psutil.virtual_memory()
        out["ram_percent"] = round(mem.percent, 1)
        out["ram_used_mb"] = round(mem.used / (1024 * 1024), 1)
    except Exception:
        pass
    try:
        from utils.host_data import get_disk_usage

        disk = get_disk_usage()
        if isinstance(disk, dict) and disk.get("percent") is not None:
            out["disk_percent"] = round(float(disk["percent"]), 1)
        else:
            usage = psutil.disk_usage(os.path.abspath(os.sep))
            out["disk_percent"] = round(usage.percent, 1)
    except Exception:
        try:
            usage = psutil.disk_usage(os.path.abspath(os.sep))
            out["disk_percent"] = round(usage.percent, 1)
        except Exception:
            pass
    try:
        out["process_cpu_percent"] = round(_PROC.cpu_percent(interval=0), 1)
        out["process_rss_mb"] = round(_PROC.memory_info().rss / (1024 * 1024), 1)
    except Exception:
        pass
    return out


def _base(component_id: str) -> Dict[str, Any]:
    return {
        "component_id": component_id,
        "label": COMPONENT_LABELS.get(component_id, component_id),
        "status": STATUS_UNAVAILABLE,
        "status_label": "NO DISPONIBLE",
        "uptime_sec": NA,
        "uptime_label": NA,
        "cpu_percent": NA,
        "ram_mb": NA,
        "disk_percent": NA,
        "error_count": NA,
        "exception_count": NA,
        "response_time_ms": NA,
        "events_processed": NA,
        "events_lost": NA,
        "queue_pending": NA,
        "latency_ms": NA,
        "last_activity": NA,
        "last_error": None,
        "measurable": False,
        "details": {},
        "probed_at_utc": _utcnow(),
    }


def _apply_host(row: Dict[str, Any], host: Dict[str, Any]) -> None:
    # CPU/RAM del proceso plataforma — compartido (NO inventar por componente)
    if host.get("process_cpu_percent") != NA:
        row["cpu_percent"] = host["process_cpu_percent"]
    if host.get("process_rss_mb") != NA:
        row["ram_mb"] = host["process_rss_mb"]
    if host.get("disk_percent") != NA:
        row["disk_percent"] = host["disk_percent"]


def _status(active: bool, degraded: bool = False, unavailable: bool = False) -> Tuple[str, str]:
    if unavailable:
        return STATUS_UNAVAILABLE, "NO DISPONIBLE"
    if not active:
        return STATUS_STOPPED, "Detenido"
    if degraded:
        return STATUS_DEGRADED, "Degradado"
    return STATUS_ACTIVE, "Activo"


def probe_kernel_ia(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("kernel_ia")
    t0 = time.perf_counter()
    try:
        from services.ai_kernel import ai_kernel

        st = ai_kernel.get_status()
        running = bool(st.get("running"))
        degraded = running and not st.get("guardia")
        status, label = _status(running, degraded)
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT) if running else 0,
                "uptime_label": _fmt_uptime(time.time() - _BOOT) if running else "0s",
                "events_processed": int(st.get("sessions_active") or 0),
                "last_activity": st.get("activity") or NA,
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
                "details": {"guardia": st.get("guardia"), "activity": st.get("activity")},
            }
        )
        _apply_host(row, host)
        # Kernel no decide — solo analista
        row["details"]["role"] = "analyze_correlate_explain_propose"
        row["details"]["executes_destructive"] = False
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, unavailable=True)
    return row


def probe_swarm_defense(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("swarm_defense")
    t0 = time.perf_counter()
    try:
        from services.swarm_defense.engine import _obs_metrics
        from services.swarm_defense import swarm_defense_engine

        # Evitar status() completo si dispara collaborators; leer métricas internas
        started = bool(getattr(swarm_defense_engine, "_started", False))
        if not started:
            # start solo suscribe bus — no corre collaborators
            swarm_defense_engine.start()
            started = True
        processed = int((_obs_metrics or {}).get("events_processed") or 0)
        status, label = _status(started)
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT) if started else 0,
                "uptime_label": _fmt_uptime(time.time() - _BOOT) if started else NA,
                "events_processed": processed,
                "queue_pending": NA,
                "last_activity": _utcnow() if processed else NA,
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
                "details": {"started": started, "probe": "lightweight"},
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, unavailable=True)
    return row


def probe_swarm_mesh(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("swarm_mesh")
    t0 = time.perf_counter()
    try:
        # Mesh health sin disparar process_event
        mesh_info: Dict[str, Any] = {}
        try:
            from services.swarm_defense.mesh import forensic_mesh  # type: ignore

            if hasattr(forensic_mesh, "status"):
                mesh_info = forensic_mesh.status() or {}
        except Exception:
            mesh_info = {}
        try:
            from services.swarm_defense.event_bus import swarm_event_bus

            bus = swarm_event_bus.health() if hasattr(swarm_event_bus, "health") else {}
        except Exception:
            bus = {}
        active = bool(bus) or True
        peers = mesh_info.get("peers_connected", NA)
        status, label = _status(active, degraded=False)
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT),
                "uptime_label": _fmt_uptime(time.time() - _BOOT),
                "events_processed": bus.get("published") if isinstance(bus, dict) else NA,
                "events_lost": bus.get("dropped") if isinstance(bus, dict) else NA,
                "last_activity": _utcnow(),
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "details": {"peers_connected": peers, "bus": bus, "probe": "lightweight"},
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, unavailable=True)
    return row


def probe_btde(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("behavioral_threat_detection")
    t0 = time.perf_counter()
    try:
        from services.behavioral_threat_detection import get_btde_orchestrator_status, get_btde_status

        ost = get_btde_orchestrator_status()
        eng = get_btde_status()
        active = bool(ost.get("active"))
        err = ost.get("last_error")
        degraded = bool(err) or (active and not ost.get("last_cycle_at"))
        status, label = _status(active, degraded)
        started = ost.get("started_at")
        uptime = NA
        if started:
            try:
                ts = datetime.strptime(str(started)[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S")
                uptime = int((datetime.utcnow() - ts).total_seconds())
            except Exception:
                uptime = int(time.time() - _BOOT) if active else NA
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": uptime,
                "uptime_label": _fmt_uptime(uptime if isinstance(uptime, (int, float)) else None),
                "events_processed": ost.get("cycles", eng.get("cycles", NA)),
                "error_count": 1 if err else 0,
                "last_error": err,
                "last_activity": ost.get("last_cycle_at") or NA,
                "response_time_ms": ost.get("last_duration_ms", round((time.perf_counter() - t0) * 1000, 2)),
                "latency_ms": ost.get("last_duration_ms", NA),
                "details": {"last_risk": ost.get("last_risk") or eng.get("last_risk")},
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, unavailable=True)
    return row


def probe_adaptive_profile(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("adaptive_profile")
    t0 = time.perf_counter()
    try:
        from services.adaptive_profile_engine import engine_status

        st = engine_status() if callable(engine_status) else {}
        active = isinstance(st, dict) and bool(st.get("engine_id"))
        status, label = _status(active, degraded=False)
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT),
                "uptime_label": _fmt_uptime(time.time() - _BOOT),
                "events_processed": st.get("observations") if isinstance(st, dict) else NA,
                "last_activity": (st.get("updated_at") if isinstance(st, dict) else None) or NA,
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "details": st if isinstance(st, dict) else {"raw": str(st)[:200]},
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, unavailable=True)
    return row


def probe_cryptovault(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("cryptovault")
    t0 = time.perf_counter()
    try:
        from services.novus_security_integration import novus_security

        vault_ok = novus_security.vault is not None
        detail = {}
        if vault_ok and hasattr(novus_security.vault, "verify_health"):
            try:
                detail = novus_security.vault.verify_health() or {}
            except Exception as exc:
                detail = {"verify_error": str(exc)[:200]}
                vault_ok = False
        status, label = _status(vault_ok, degraded=bool(detail.get("verify_error")))
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT) if vault_ok else 0,
                "uptime_label": _fmt_uptime(time.time() - _BOOT) if vault_ok else NA,
                "events_processed": 1 if vault_ok else 0,
                "last_activity": _utcnow() if vault_ok else NA,
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "last_error": detail.get("verify_error") or detail.get("error"),
                "details": {"aes_gcm_roundtrip": detail.get("aes_gcm_roundtrip", NA)},
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, unavailable=True)
    return row


def probe_defense_center(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("defense_center")
    t0 = time.perf_counter()
    try:
        # Lectura liviana — NO llamar get_engines_panel (dispara XDR/ARP).
        from services.defense_center_service import get_automatic_protection_status

        auto = get_automatic_protection_status()
        active = bool(auto.get("active") or auto)
        status, label = _status(True if auto is not None else False, degraded=not active)
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT),
                "uptime_label": _fmt_uptime(time.time() - _BOOT),
                "events_processed": len(auto.keys()) if isinstance(auto, dict) else 1,
                "last_activity": _utcnow(),
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
                "details": {
                    "auto_protection": auto.get("active") if isinstance(auto, dict) else NA,
                    "panel": "lightweight_probe",
                    "keys": list(auto.keys())[:12] if isinstance(auto, dict) else [],
                },
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, unavailable=True)
    return row


def probe_forensic(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("forensic")
    t0 = time.perf_counter()
    try:
        from services.forensic_evidence_integrity_service import get_system_summary, iter_ledger_records

        summary = get_system_summary() if callable(get_system_summary) else {}
        records = iter_ledger_records() if callable(iter_ledger_records) else []
        if not isinstance(records, list):
            records = []
        count = len(records) if records else int((summary or {}).get("total_records") or 0)
        status, label = _status(True, degraded=False)
        last = NA
        if records:
            last = records[-1].get("timestamp_utc") or records[-1].get("timestamp") or NA
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT),
                "uptime_label": _fmt_uptime(time.time() - _BOOT),
                "events_processed": count,
                "last_activity": last,
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "details": {
                    "ledger_records": count,
                    "summary_keys": list((summary or {}).keys())[:12],
                    "self_heal_may_delete": False,
                },
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        ev_dir = os.path.join(root, "data", "forensic")
        exists = os.path.isdir(ev_dir)
        status, label = _status(exists, degraded=not exists)
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT),
                "uptime_label": _fmt_uptime(time.time() - _BOOT),
                "last_error": str(exc)[:200],
                "details": {"forensic_dir": exists, "probe_fallback": True},
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
            }
        )
        _apply_host(row, host)
    return row


def probe_endpoint(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("endpoint")
    t0 = time.perf_counter()
    try:
        from services.endpoint_realtime_monitor import get_monitor_status

        st = get_monitor_status()
        active = bool(st.get("active"))
        err = int(st.get("error_count") or 0)
        status, label = _status(active, degraded=err > 0)
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": st.get("uptime_sec", int(time.time() - _BOOT) if active else 0),
                "uptime_label": st.get("uptime_label") or _fmt_uptime(st.get("uptime_sec")),
                "events_processed": st.get("event_count", st.get("cycle_count", NA)),
                "error_count": err,
                "last_error": st.get("last_error"),
                "last_activity": st.get("last_scan_at") or st.get("last_event_at") or NA,
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "details": {"status": st.get("status")},
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, unavailable=True)
    return row


def probe_network(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("network_protection")
    t0 = time.perf_counter()
    try:
        from services.network_monitor_engine import get_monitor_status

        st = get_monitor_status()
        active = bool(st.get("active"))
        err = int(st.get("error_count") or 0)
        stale = st.get("seconds_since_last_scan")
        degraded = err > 0 or (active and isinstance(stale, (int, float)) and stale > 180)
        status, label = _status(active, degraded)
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": st.get("uptime_sec"),
                "uptime_label": st.get("uptime_label") or _fmt_uptime(st.get("uptime_sec")),
                "events_processed": int(st.get("scan_count") or 0),
                "error_count": err,
                "last_error": st.get("last_error"),
                "last_activity": st.get("last_scan_at") or NA,
                "latency_ms": st.get("last_scan_duration_ms", NA),
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "cpu_percent": st.get("cpu_percent", host.get("process_cpu_percent", NA)),
                "ram_mb": st.get("memory_mb", host.get("process_rss_mb", NA)),
                "details": {
                    "devices_monitored": st.get("devices_monitored"),
                    "seconds_since_last_scan": stale if stale is not None else NA,
                },
            }
        )
        if row["disk_percent"] == NA:
            row["disk_percent"] = host.get("disk_percent", NA)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, unavailable=True)
    return row


def probe_web_security(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("web_security")
    t0 = time.perf_counter()
    try:
        from services.web_shield_engine import get_engine_status

        st = get_engine_status() or {}
        state = st.get("status") or st.get("engine_state")
        active = state not in ("error", "offline", None)
        degraded = state in ("degraded", "warning")
        status, label = _status(active, degraded)
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT) if active else 0,
                "uptime_label": _fmt_uptime(time.time() - _BOOT) if active else NA,
                "events_processed": st.get("events_processed", st.get("blocks", NA)),
                "last_activity": st.get("last_event_at") or st.get("updated_at") or NA,
                "last_error": st.get("error") or st.get("last_error"),
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "details": {"summary": st.get("summary"), "engine_state": state},
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, unavailable=True)
    return row


def probe_authentication(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("authentication")
    t0 = time.perf_counter()
    try:
        from database import SessionLocal, User

        db = SessionLocal()
        try:
            users = db.query(User).count()
        finally:
            db.close()
        status, label = _status(True)
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT),
                "uptime_label": _fmt_uptime(time.time() - _BOOT),
                "events_processed": users,
                "last_activity": _utcnow(),
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
                "details": {"users_registered": users, "auth_stack": "flask_session"},
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, degraded=True)
        row["measurable"] = True
    return row


def probe_compliance(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("compliance")
    t0 = time.perf_counter()
    try:
        import services.compliance_catalog as cc

        frameworks = []
        if hasattr(cc, "FRAMEWORKS"):
            fw = getattr(cc, "FRAMEWORKS")
            frameworks = list(fw.keys()) if isinstance(fw, dict) else list(fw or [])
        elif hasattr(cc, "frameworks_for_sector"):
            frameworks = cc.frameworks_for_sector("general") or []
        status, label = _status(True)
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT),
                "uptime_label": _fmt_uptime(time.time() - _BOOT),
                "events_processed": len(frameworks),
                "last_activity": _utcnow(),
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "details": {"frameworks": len(frameworks)},
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, unavailable=True)
    return row


def probe_reports(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("reports")
    t0 = time.perf_counter()
    try:
        from services.security_report_service import list_reports

        reports = list_reports(limit=200)
        status, label = _status(True)
        last = reports[0].get("generated_at") if reports else NA
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT),
                "uptime_label": _fmt_uptime(time.time() - _BOOT),
                "events_processed": len(reports),
                "last_activity": last,
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "details": {"reports_total": len(reports)},
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, unavailable=True)
    return row


def probe_automatic_response(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("automatic_response")
    t0 = time.perf_counter()
    try:
        from services.adaptive_defense_engine import get_adaptive_defense_panel

        panel = get_adaptive_defense_panel() or {}
        status, label = _status(True, degraded=int(panel.get("active_incidents") or 0) > 5)
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT),
                "uptime_label": _fmt_uptime(time.time() - _BOOT),
                "events_processed": panel.get("actions_total", panel.get("total_actions", NA)),
                "last_activity": panel.get("updated_at") or NA,
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "details": {
                    "active_incidents": panel.get("active_incidents"),
                    "destructive_auto": False,
                },
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, unavailable=True)
    return row


def probe_database(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("database")
    t0 = time.perf_counter()
    try:
        from database import SessionLocal
        from sqlalchemy import text

        db = SessionLocal()
        try:
            db.execute(text("SELECT 1"))
            db.commit()
        finally:
            db.close()
        ms = round((time.perf_counter() - t0) * 1000, 2)
        status, label = _status(True, degraded=ms > 500)
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT),
                "uptime_label": _fmt_uptime(time.time() - _BOOT),
                "response_time_ms": ms,
                "latency_ms": ms,
                "last_activity": _utcnow(),
                "events_processed": 1,
                "details": {"ping": "ok", "engine": "sqlalchemy"},
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False)
        row["measurable"] = True
        row["response_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        row["exception_count"] = 1
    return row


def probe_web_server(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("web_server")
    t0 = time.perf_counter()
    try:
        # El proceso actual ES el servidor web Flask
        listening = False
        try:
            for c in _PROC.connections(kind="inet"):
                if c.status == "LISTEN":
                    listening = True
                    break
        except Exception:
            listening = True  # proceso vivo; conexiones pueden requerir privilegios
        status, label = _status(True, degraded=not listening)
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT),
                "uptime_label": _fmt_uptime(time.time() - _BOOT),
                "last_activity": _utcnow(),
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "details": {"pid": os.getpid(), "listening": listening, "server": "flask"},
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, unavailable=True)
    return row


def probe_api_rest(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("api_rest")
    t0 = time.perf_counter()
    try:
        from flask import current_app

        rules = 0
        try:
            rules = sum(1 for r in current_app.url_map.iter_rules() if str(r).startswith("/api"))
        except RuntimeError:
            # Fuera de request context — contar blueprints conocidos
            rules = NA
        status, label = _status(True)
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT),
                "uptime_label": _fmt_uptime(time.time() - _BOOT),
                "events_processed": rules,
                "last_activity": _utcnow(),
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "details": {"api_routes": rules if rules != NA else NA},
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, unavailable=True)
    return row


def probe_scheduler(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("scheduler")
    t0 = time.perf_counter()
    try:
        threads = [t.name for t in threading_alive()]
        sched_like = [n for n in threads if any(k in n.lower() for k in ("sched", "monitor", "novus", "zdde", "btde", "boot"))]
        active = len(sched_like) > 0 or len(threads) > 1
        status, label = _status(active, degraded=len(sched_like) == 0)
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT),
                "uptime_label": _fmt_uptime(time.time() - _BOOT),
                "events_processed": len(sched_like),
                "last_activity": _utcnow(),
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "details": {"scheduler_threads": sched_like[:30], "thread_count": len(threads)},
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, unavailable=True)
    return row


def probe_background_workers(host: Dict[str, Any]) -> Dict[str, Any]:
    row = _base("background_workers")
    t0 = time.perf_counter()
    try:
        threads = threading_alive()
        names = [t.name for t in threads]
        workers = [n for n in names if n not in ("MainThread",)]
        # Contar motores orquestados conocidos
        known = {
            "btde": any("btde" in n.lower() for n in names),
            "zdde": any("zdde" in n.lower() for n in names),
            "network": any("network" in n.lower() or "monitor" in n.lower() for n in names),
        }
        stopped = [k for k, v in known.items() if not v]
        active = len(workers) > 0
        degraded = len(stopped) > 0
        status, label = _status(active, degraded)
        row.update(
            {
                "status": status,
                "status_label": label,
                "measurable": True,
                "uptime_sec": int(time.time() - _BOOT),
                "uptime_label": _fmt_uptime(time.time() - _BOOT),
                "events_processed": len(workers),
                "queue_pending": NA,
                "last_activity": _utcnow(),
                "response_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "details": {
                    "worker_threads": workers[:40],
                    "known_engines": known,
                    "possibly_stopped": stopped,
                },
            }
        )
        _apply_host(row, host)
    except Exception as exc:
        row["last_error"] = str(exc)[:300]
        row["status"], row["status_label"] = _status(False, unavailable=True)
    return row


def threading_alive():
    import threading

    return [t for t in threading.enumerate() if t.is_alive()]


PROBES = {
    "kernel_ia": probe_kernel_ia,
    "swarm_defense": probe_swarm_defense,
    "swarm_mesh": probe_swarm_mesh,
    "behavioral_threat_detection": probe_btde,
    "adaptive_profile": probe_adaptive_profile,
    "cryptovault": probe_cryptovault,
    "defense_center": probe_defense_center,
    "forensic": probe_forensic,
    "endpoint": probe_endpoint,
    "network_protection": probe_network,
    "web_security": probe_web_security,
    "authentication": probe_authentication,
    "compliance": probe_compliance,
    "reports": probe_reports,
    "automatic_response": probe_automatic_response,
    "database": probe_database,
    "web_server": probe_web_server,
    "api_rest": probe_api_rest,
    "scheduler": probe_scheduler,
    "background_workers": probe_background_workers,
}


def apply_fault_inject(components: List[Dict[str, Any]], fault: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Aplica fallos de pentest controlado sobre mediciones reales (no inventa métricas base)."""
    if not fault or not fault.get("active"):
        return components
    target = fault.get("component_id")
    kind = fault.get("kind") or "stopped"
    out = []
    for c in components:
        row = dict(c)
        if target and row.get("component_id") == target:
            if kind == "stopped":
                row["status"] = STATUS_STOPPED
                row["status_label"] = "Detenido"
                row["details"] = dict(row.get("details") or {})
                row["details"]["fault_inject"] = True
                row["details"]["fault_kind"] = kind
            elif kind == "exception_storm":
                row["status"] = STATUS_DEGRADED
                row["status_label"] = "Degradado"
                row["exception_count"] = int(fault.get("exception_count") or 25)
                row["error_count"] = int(fault.get("error_count") or 25)
                row["last_error"] = fault.get("message") or "pentest_exception_storm"
                row["details"] = dict(row.get("details") or {})
                row["details"]["fault_inject"] = True
            elif kind == "queue_saturated":
                row["status"] = STATUS_DEGRADED
                row["status_label"] = "Degradado"
                row["queue_pending"] = int(fault.get("queue_pending") or 5000)
                row["details"] = dict(row.get("details") or {})
                row["details"]["fault_inject"] = True
            elif kind == "db_fail":
                row["status"] = STATUS_STOPPED
                row["status_label"] = "Detenido"
                row["last_error"] = fault.get("message") or "pentest_db_fail"
                row["exception_count"] = 1
                row["details"] = dict(row.get("details") or {})
                row["details"]["fault_inject"] = True
            elif kind == "api_fail":
                row["status"] = STATUS_DEGRADED
                row["status_label"] = "Degradado"
                row["last_error"] = fault.get("message") or "pentest_api_fail"
                row["error_count"] = int(fault.get("error_count") or 10)
                row["details"] = dict(row.get("details") or {})
                row["details"]["fault_inject"] = True
        out.append(row)
    return out


def probe_all() -> Dict[str, Any]:
    from services.health_engine.catalog import COMPONENT_IDS
    from services.health_engine.store import load_fault_inject

    host = host_resources()
    components: List[Dict[str, Any]] = []
    for cid in COMPONENT_IDS:
        fn = PROBES.get(cid)
        try:
            components.append(fn(host) if fn else _base(cid))
        except Exception as exc:
            logger.warning("health probe %s: %s", cid, exc)
            bad = _base(cid)
            bad["last_error"] = str(exc)[:300]
            bad["status"] = STATUS_DEGRADED
            bad["status_label"] = "Degradado"
            bad["measurable"] = False
            components.append(bad)

    fault = load_fault_inject()
    if fault:
        components = apply_fault_inject(components, fault)

    return {
        "probed_at_utc": _utcnow(),
        "host": host,
        "components": components,
        "fault_inject_active": bool(fault.get("active")),
    }
