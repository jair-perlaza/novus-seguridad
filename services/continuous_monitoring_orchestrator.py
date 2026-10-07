"""
Orquestación de monitoreo continuo post-login — fase rápida, escaneo profundo y reportes reales.
"""
from __future__ import annotations

import json
import os
import platform
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

import psutil

from utils.host_data import format_ip_or_unavailable, get_local_ip
from utils.logger import logger

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_DIR = os.path.join(ROOT, "data", "continuous_monitoring")
ACTIVE_USER_STATE = os.path.join(STATE_DIR, "active_by_email.json")

_lock = threading.Lock()
_running_sessions: Dict[str, dict] = {}

_motors_cache: Dict[str, Any] = {"at": 0.0, "data": {}}
MOTORS_CACHE_TTL_SEC = 30.0
STALE_MONITORING_SEC = 1200


def _parse_state_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def release_user_monitoring_session(user_email: Optional[str]) -> None:
    """Libera bloqueo en memoria tras logout — permite nuevo escaneo en el siguiente login."""
    if not user_email:
        return
    with _lock:
        _running_sessions.pop(user_email, None)


def _supersede_prior_monitoring(user_email: str, new_session_audit_id: str) -> None:
    """Marca escaneos anteriores del mismo usuario como reemplazados por una sesión nueva."""
    prior_id = None
    if os.path.isfile(ACTIVE_USER_STATE):
        try:
            with open(ACTIVE_USER_STATE, encoding="utf-8") as fh:
                idx = json.load(fh)
            prior_id = (idx.get(user_email) or {}).get("session_audit_id")
        except Exception:
            prior_id = None
    if not prior_id or prior_id == new_session_audit_id:
        return
    prior = _load_state(prior_id)
    if not prior:
        return
    if prior.get("status") in ("phase1_running", "phase2_running"):
        prior["status"] = "superseded"
        prior["superseded_by"] = new_session_audit_id
        prior["updated_at"] = _now()
        _save_state(prior_id, prior)


def _monitoring_already_running(user_email: str, session_audit_id: str) -> bool:
    """True solo si el mismo audit_id sigue en curso y no está obsoleto."""
    with _lock:
        entry = _running_sessions.get(user_email)
    if not entry:
        return False
    if entry.get("session_audit_id") != session_audit_id:
        return False
    state = _load_state(session_audit_id)
    if not state:
        return False
    st = state.get("status")
    if st in ("completed", "partial", "error", "superseded"):
        return False
    ts = _parse_state_ts(state.get("updated_at") or state.get("started_at"))
    if ts and (datetime.now() - ts).total_seconds() > STALE_MONITORING_SEC:
        logger.warning("Monitoreo stale (>=%ss) para %s — se permite reinicio", STALE_MONITORING_SEC, user_email)
        return False
    return st in ("phase1_running", "phase2_running")

DASHBOARD_STAGE_DEFS: List[tuple] = [
    ("kernel_ia", "Inicializando Kernel IA"),
    ("defense_motors", "Inicializando motores de defensa"),
    ("files", "Analizando archivos"),
    ("processes", "Analizando procesos"),
    ("memory", "Analizando memoria"),
    ("services", "Analizando servicios"),
    ("autostart", "Analizando inicio automático"),
    ("registry", "Analizando registro (Windows)"),
    ("network", "Analizando red"),
    ("devices", "Analizando dispositivos"),
    ("ports", "Analizando puertos"),
    ("vulnerabilities", "Analizando vulnerabilidades"),
    ("integrity", "Analizando integridad"),
    ("report", "Generando informe"),
]

_DEEP_PHASE_TO_DASHBOARD: Dict[str, str] = {
    "init": "defense_motors",
    "system_metrics": "memory",
    "processes": "processes",
    "memory_scan": "memory",
    "services": "services",
    "connections": "network",
    "ports": "ports",
    "network_adapters": "network",
    "firewall": "integrity",
    "defender_status": "integrity",
    "startup": "autostart",
    "scheduled_tasks": "autostart",
    "installed_programs": "files",
    "user_files": "files",
    "registry": "registry",
    "browser_extensions": "files",
    "threats": "vulnerabilities",
    "vulnerabilities": "vulnerabilities",
    "network_arp": "devices",
    "security_engine": "integrity",
    "finalize": "report",
}


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _save_state(session_audit_id: str, state: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    path = os.path.join(STATE_DIR, f"{session_audit_id}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2)


def _load_state(session_audit_id: str) -> Optional[dict]:
    path = os.path.join(STATE_DIR, f"{session_audit_id}.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read().strip()
        if not raw:
            return None
        return json.loads(raw)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("monitoring state corrupt %s: %s", session_audit_id, exc)
        return None


def _init_stage_status() -> Dict[str, str]:
    return {key: "pending" for key, _ in DASHBOARD_STAGE_DEFS}


def _complete_dashboard_stage(state: dict, stage_key: str) -> None:
    stages = state.setdefault("stage_status", _init_stage_status())
    if stage_key in stages and stages.get(stage_key) != "completed":
        stages[stage_key] = "completed"


def _set_current_dashboard_stage(state: dict, stage_key: str) -> None:
    state["current_stage"] = stage_key
    stages = state.setdefault("stage_status", _init_stage_status())
    if stages.get(stage_key) == "pending":
        stages[stage_key] = "running"


def _fail_dashboard_stage(state: dict, stage_key: str) -> None:
    stages = state.setdefault("stage_status", _init_stage_status())
    if stage_key in stages and stages.get(stage_key) != "completed":
        stages[stage_key] = "failed"


def _apply_deep_scan_phases(
    state: dict,
    phase_id: Optional[str],
    *,
    scan_completed: bool = False,
) -> None:
    """Sincroniza etapas dashboard con fases del deep scan.

    Importante: cuando el motor termina, `phase` pasa a ``done`` (fuera del
    perfil). Sin `scan_completed=True` la etapa ``report`` nunca se marcaba
    completed → 13/14 ≈ 93% eterno aunque el informe ya existiera.
    """
    from services.deep_scan_engine import PROFILE_PHASES

    profile = PROFILE_PHASES.get("login_session") or []
    stages = state.setdefault("stage_status", _init_stage_status())
    if scan_completed or phase_id in ("done", "finalize"):
        for pid in profile:
            dkey = _DEEP_PHASE_TO_DASHBOARD.get(pid)
            if dkey and stages.get(dkey) not in ("failed", "completed"):
                stages[dkey] = "completed"
        if stages.get("report") != "failed":
            stages["report"] = "completed"
        state["current_stage"] = "report"
        return
    if not phase_id or phase_id not in profile:
        return
    idx = profile.index(phase_id)
    for pid in profile[: idx + 1]:
        dkey = _DEEP_PHASE_TO_DASHBOARD.get(pid)
        if dkey and stages.get(dkey) != "failed":
            stages[dkey] = "completed"
    current = _DEEP_PHASE_TO_DASHBOARD.get(phase_id)
    if current:
        state["current_stage"] = current


def _dashboard_stage_view(state: dict) -> Dict[str, Any]:
    stages = state.setdefault("stage_status", _init_stage_status())
    items = []
    completed_n = 0
    failed_n = 0
    skipped_n = 0
    current_label = ""
    for key, label in DASHBOARD_STAGE_DEFS:
        st = stages.get(key, "pending")
        if st == "completed":
            completed_n += 1
        elif st == "failed":
            failed_n += 1
        elif st == "skipped":
            skipped_n += 1
        elif st == "running" and not current_label:
            # Solo mostrar "Analizando X" si esa etapa está realmente running
            current_label = label
        items.append({"key": key, "label": label, "status": st})
    # NUNCA inventar label desde la primera pending (causa de "Analizando archivos" zombie)
    total = len(DASHBOARD_STAGE_DEFS) or 1
    # 100% = todos los motores requeridos TERMINARON (ok | failed | skipped terminal)
    finished_n = completed_n + failed_n + skipped_n
    if not current_label:
        st_status = state.get("status")
        err = state.get("error")
        if st_status == "error":
            if isinstance(err, dict):
                current_label = str(err.get("motivo") or err.get("codigo") or "Error de motor")
            elif err:
                current_label = str(err)[:160]
            else:
                current_label = "Error de motor"
        elif st_status in ("completed", "partial"):
            if failed_n:
                current_label = (
                    f"Escaneo finalizado — {completed_n} de {total} OK"
                    f" ({failed_n} con error)"
                )
            else:
                current_label = "Escaneo finalizado"
        elif st_status in ("phase1_running", "phase2_running") and finished_n > 0:
            current_label = f"{finished_n}/{total} motores finalizados"
        else:
            current_label = "Monitoreo: IDLE / sin motores finalizados"
    # Progreso por motores que ya terminaron — no por tiempo
    pct = int(round(100.0 * finished_n / total))
    waiting = (
        finished_n == 0
        and state.get("status") in ("phase1_running", "phase2_running", None)
        and not any(stages.get(k) == "running" for k, _ in DASHBOARD_STAGE_DEFS)
    )
    return {
        "stages": items,
        "progress_pct": pct,
        "current_label": current_label,
        "completed_count": completed_n,
        "failed_count": failed_n,
        "skipped_count": skipped_n,
        "finished_count": finished_n,
        "total_stages": total,
        "progress_source": "finished_motors_only",
        "waiting_for_engines": waiting and pct == 0,
        "verifiable": True,
        "scan_outcome": (
            f"{completed_n} de {total} motores completados"
            + (f" ({failed_n} con error)" if failed_n else "")
        ),
    }


def _is_stale_running_state(state: dict) -> bool:
    if state.get("status") not in ("phase1_running", "phase2_running"):
        return False
    ts = _parse_state_ts(state.get("updated_at") or state.get("started_at"))
    if not ts:
        return True
    return (datetime.now() - ts).total_seconds() > STALE_MONITORING_SEC


def _register_monitoring_fault(session_audit_id: str, state: dict, err: Dict[str, Any]) -> None:
    """Registra fallo de monitoreo en logs, telemetría, defensa, kernel y forense."""
    logger.error(
        "MONITORING_FAULT session=%s motor=%s codigo=%s motivo=%s",
        session_audit_id,
        err.get("motor"),
        err.get("codigo"),
        err.get("motivo"),
    )
    try:
        from services.motor_telemetry_service import motor_fail

        motor_fail(
            session_id=session_audit_id,
            motor_id=str(err.get("motor") or "continuous_monitoring"),
            motor_label=str(err.get("motor") or "Monitoreo continuo"),
            error=str(err.get("motivo") or err.get("codigo") or "error"),
            evidence={"fault": err, "verifiable": True},
            progress_pct=state.get("last_progress_pct"),
        )
    except Exception as exc:
        logger.debug("motor_fail telemetry: %s", exc)
    try:
        from services.defense_evidence_registry import record_defense_event

        record_defense_event(
            phase="detect",
            action="monitoring_stale_worker",
            motor=str(err.get("motor") or "continuous_monitoring"),
            outcome="failed",
            evidence={"fault": err, "session_audit_id": session_audit_id, "verifiable": True},
            user_email=state.get("user_email"),
            detail=str(err.get("motivo") or "")[:500],
        )
    except Exception as exc:
        logger.debug("defense_evidence fault: %s", exc)
    try:
        from services.forensic_evidence_integrity_service import append_evidence_version

        append_evidence_version(
            source_id=f"monitoring-fault:{session_audit_id}",
            motor=str(err.get("motor") or "continuous_monitoring"),
            evidence_type="monitoring_fault",
            payload={
                "session_audit_id": session_audit_id,
                "error": err,
                "user_email": state.get("user_email"),
            },
            user_email=state.get("user_email"),
            tenant_id=None,
            equipment=None,
            reason=str(err.get("codigo") or "MONITORING_STALE_WORKER"),
        )
    except Exception as exc:
        logger.debug("forensic fault: %s", exc)
    try:
        kernel_dir = os.path.join(ROOT, "data", "kernel_ia", "faults")
        os.makedirs(kernel_dir, exist_ok=True)
        path = os.path.join(kernel_dir, "monitoring_faults.jsonl")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"at": _now(), "session": session_audit_id, "error": err}, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.debug("kernel fault log: %s", exc)
    try:
        reports_dir = os.path.join(ROOT, "data", "security_reports", "monitoring_faults")
        os.makedirs(reports_dir, exist_ok=True)
        path = os.path.join(reports_dir, f"{session_audit_id}_fault.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"session_audit_id": session_audit_id, "error": err, "state_status": state.get("status")}, fh, ensure_ascii=False, indent=2)
    except Exception as exc:
        logger.debug("reports fault: %s", exc)


def _heal_stale_monitoring_state(session_audit_id: str, state: dict) -> dict:
    """Si el worker murió dejando phase*_running, marca error real (no inventa %)."""
    if not _is_stale_running_state(state):
        return state
    stages = state.setdefault("stage_status", _init_stage_status())
    for key, st in list(stages.items()):
        if st == "running":
            stages[key] = "failed"
    last_ts = state.get("updated_at") or state.get("started_at")
    err = {
        "motor": state.get("current_stage") or "continuous_monitoring",
        "estado": "detenido_sin_telemetria",
        "motivo": (
            f"Sin telemetría del motor durante >= {STALE_MONITORING_SEC}s "
            f"(última actualización: {last_ts}). Worker detenido o sesión zombie."
        ),
        "codigo": "MONITORING_STALE_WORKER",
        "tiempo": last_ts,
        "detected_at": _now(),
        "session_audit_id": session_audit_id,
    }
    state["status"] = "error"
    state["error"] = err
    state["updated_at"] = _now()
    _save_state(session_audit_id, state)
    email = state.get("user_email")
    if email:
        release_user_monitoring_session(email)
    _register_monitoring_fault(session_audit_id, state, err)
    logger.warning(
        "Sesión monitoreo saneada por stale: %s → error MONITORING_STALE_WORKER",
        session_audit_id,
    )
    return state


def _heal_terminal_progress_gap(session_audit_id: str, state: dict) -> dict:
    """Corrige sesiones completed/partial con report=skipped (bug del 93%)."""
    if state.get("status") not in ("completed", "partial"):
        return state
    stages = state.setdefault("stage_status", _init_stage_status())
    changed = False
    if state.get("report_id") and stages.get("report") in ("skipped", "pending", "running", None):
        stages["report"] = "completed"
        changed = True
    for key, _ in DASHBOARD_STAGE_DEFS:
        if stages.get(key) in ("pending", "running"):
            stages[key] = "failed"
            changed = True
        elif stages.get(key) == "skipped" and key == "report" and state.get("report_id"):
            stages[key] = "completed"
            changed = True
    if changed:
        state["updated_at"] = _now()
        _save_state(session_audit_id, state)
        logger.info(
            "Heal terminal progress gap session=%s report=%s → 100%% stages",
            session_audit_id,
            state.get("report_id"),
        )
    return state


def _build_dashboard_executive_summary(state: dict) -> Optional[Dict[str, Any]]:
    p1 = state.get("phase1") or {}
    if not p1 and state.get("status") not in ("completed", "partial"):
        return None
    p2 = state.get("phase2") or {}
    stats = p2.get("stats") or {}
    counts = p1.get("counts") or {}
    evidence = p1.get("evidence") or {}
    findings = p1.get("findings") or []
    vulns = p1.get("vulnerabilities") or []
    malware_n = sum(
        1
        for f in findings
        if isinstance(f, dict)
        and any(
            t in str(f.get("title", "") + str(f.get("category", ""))).lower()
            for t in ("malware", "ransom", "trojan")
        )
    )
    ransomware_n = sum(
        1
        for f in findings
        if isinstance(f, dict) and "ransom" in str(f.get("title", "") + str(f.get("category", ""))).lower()
    )
    fw = evidence.get("firewall") or {}
    av = evidence.get("antivirus") or {}
    kernel_rec = ""
    if state.get("status") in ("completed", "partial") and state.get("report_id"):
        try:
            from services.security_report_service import get_report

            rep = get_report(state["report_id"])
            if rep:
                tech = rep.get("technical") or {}
                exec_block = tech.get("executive_auto_monitoring") or {}
                kb = exec_block.get("kernel_ia") or {}
                kernel_rec = kb.get("recomendaciones") or kb.get("recommendation") or ""
                if isinstance(kernel_rec, list):
                    kernel_rec = "; ".join(str(x) for x in kernel_rec[:5])
        except Exception as exc:
            logger.debug("dashboard summary kernel: %s", exc)

    duration = None
    if p1.get("duration_sec") is not None:
        duration = float(p1.get("duration_sec") or 0)
        if p2.get("duration_sec"):
            duration += float(p2.get("duration_sec") or 0)
    risk = None
    try:
        if state.get("report_id"):
            from services.security_report_service import get_report

            rep = get_report(state["report_id"])
            if rep:
                risk = rep.get("riesgo") or rep.get("nivel_riesgo") or (rep.get("technical") or {}).get("risk_level")
    except Exception:
        pass

    return {
        "archivos_analizados": stats.get("files_analyzed"),
        "carpetas_analizadas": stats.get("folders_analyzed"),
        "procesos_inspeccionados": stats.get("processes_analyzed", counts.get("processes")),
        "servicios_inspeccionados": stats.get("services_analyzed"),
        "memoria_analizada": stats.get("memory_rss_mb") or evidence.get("system", {}).get("ram_percent"),
        "dispositivos_encontrados": p1.get("network", {}).get("devices_detected"),
        "vulnerabilidades_detectadas": len(vulns) if isinstance(vulns, list) else counts.get("vulnerabilities"),
        "malware_detectado": malware_n,
        "ransomware_detectado": ransomware_n,
        "estado_firewall": fw.get("status"),
        "estado_antivirus": av.get("status"),
        "integridad_sistema": (evidence.get("novus_integrity") or {}).get("status"),
        "recomendaciones_kernel_ia": kernel_rec or None,
        "resumen_texto": p1.get("executive_summary"),
        "report_id": state.get("report_id"),
        "tiempo_empleado_sec": round(duration, 1) if duration is not None else None,
        "nivel_riesgo": risk,
        "amenazas_detectadas": malware_n + ransomware_n + (stats.get("threats_found") or 0),
    }


def get_defense_motors_dashboard_status(*, force_refresh: bool = False) -> Dict[str, Any]:
    """Estados reales de motores para el panel permanente del dashboard."""

    def _telemetry_for(motor_id: str) -> Dict[str, Any]:
        try:
            from services.motor_telemetry_service import recent_events

            for ev in reversed(recent_events(limit=300)):
                if str(ev.get("motor_id") or "") == motor_id:
                    return {
                        "telemetry_verifiable": True,
                        "last_event_at": ev.get("recorded_at")
                        or ev.get("finished_at")
                        or ev.get("started_at"),
                        "last_status": ev.get("status"),
                        "last_result": ev.get("result"),
                    }
        except Exception:
            pass
        return {"telemetry_verifiable": False}

    def _motor_status(label_on: str, label_off: str, on: bool, telemetry: Dict[str, Any], **extra) -> Dict[str, Any]:
        if on and not telemetry.get("telemetry_verifiable"):
            status = "NOT_VERIFIABLE"
        elif on:
            status = label_on
        else:
            status = label_off
        return {"status": status, "telemetry": telemetry, **extra}

    now = time.time()
    if not force_refresh and (now - float(_motors_cache.get("at") or 0)) < MOTORS_CACHE_TTL_SEC:
        cached = _motors_cache.get("data")
        if cached:
            return dict(cached)

    out: Dict[str, Any] = {
        "kernel_ia": {"status": "No disponible"},
        "proteccion_automatica": {"status": "No disponible"},
        "escaneo_continuo": {"status": "No disponible"},
        "web_shield": {"status": "No disponible"},
        "mail_shield": {"status": "No disponible"},
        "endpoint_protection": {"status": "No disponible"},
        "network_defense": {"status": "No disponible"},
        "motores_activos": 0,
        "ultima_actualizacion": _now(),
        "estado_general": "No disponible",
    }
    active = 0
    try:
        from services.ai_kernel import ai_kernel

        st = ai_kernel.get_status()
        running = st.get("running", False)
        op = st.get("operational_status", "STOPPED")
        tel = {
            "telemetry_verifiable": bool(st.get("last_execution_at")),
            "last_event_at": st.get("last_execution_at"),
            "last_status": op,
            "last_result": st.get("activity"),
        }
        out["kernel_ia"] = {
            "status": op,
            "running": running,
            "capabilities": st.get("capabilities"),
            "note": st.get("note"),
            "telemetry": tel,
        }
        if op == "ACTIVE" and tel.get("telemetry_verifiable"):
            active += 1
    except Exception as exc:
        out["kernel_ia"] = {"status": "Error", "detail": str(exc)[:120]}

    try:
        from services.defense_center_service import get_automatic_protection_status

        ap = get_automatic_protection_status() or {}
        enabled = ap.get("enabled") or ap.get("active")
        tel = _telemetry_for("automatic_protection")
        out["proteccion_automatica"] = _motor_status("Activo", "Inactivo", bool(enabled), tel, **ap)
        if enabled and tel.get("telemetry_verifiable"):
            active += 1
    except Exception as exc:
        out["proteccion_automatica"] = {"status": "Error", "detail": str(exc)[:120]}

    try:
        from services.network_monitor_engine import get_monitor_status

        st = get_monitor_status() or {}
        on = st.get("active") or st.get("running")
        tel = _telemetry_for("network_monitor_engine")
        out["escaneo_continuo"] = _motor_status("Activo", "Inactivo", bool(on), tel, **st)
        out["network_defense"] = _motor_status(
            "Activo", "Inactivo", bool(on), tel, source="network_monitor_engine"
        )
        if on and tel.get("telemetry_verifiable"):
            active += 1
    except Exception as exc:
        out["escaneo_continuo"] = {"status": "Error", "detail": str(exc)[:120]}

    try:
        from services.web_shield_engine import get_engine_status

        st = get_engine_status() or {}
        on = st.get("active") or st.get("running")
        tel = _telemetry_for("web_shield_engine")
        out["web_shield"] = _motor_status("Activo", "Inactivo", bool(on), tel, **st)
        if on and tel.get("telemetry_verifiable"):
            active += 1
    except Exception as exc:
        out["web_shield"] = {"status": "Error", "detail": str(exc)[:120]}

    try:
        from services.mail_shield_engine import get_engine_status

        st = get_engine_status() or {}
        state_inner = st.get("state") or st
        on = state_inner.get("active")
        tel = _telemetry_for("mail_shield_engine")
        status = "Activo" if on else ("Omitido" if st.get("status") == "skipped" else "Inactivo")
        if on and not tel.get("telemetry_verifiable"):
            status = "NOT_VERIFIABLE"
        out["mail_shield"] = {"status": status, "telemetry": tel, **st}
        if on and tel.get("telemetry_verifiable"):
            active += 1
    except Exception as exc:
        out["mail_shield"] = {"status": "No configurado", "detail": str(exc)[:120]}

    try:
        from services.endpoint_realtime_monitor import get_monitor_status

        st = get_monitor_status() or {}
        on = st.get("active") or st.get("running")
        tel = _telemetry_for("endpoint_realtime_monitor")
        out["endpoint_protection"] = _motor_status("Activo", "Inactivo", bool(on), tel, **st)
        if on and tel.get("telemetry_verifiable"):
            active += 1
    except Exception as exc:
        out["endpoint_protection"] = {"status": "Error", "detail": str(exc)[:120]}

    out["motores_activos"] = active
    if active >= 5:
        out["estado_general"] = "Protección operativa"
    elif active >= 2:
        out["estado_general"] = "Protección parcial"
    elif active >= 1:
        out["estado_general"] = "Protección limitada"
    else:
        out["estado_general"] = "Sin motores activos"
    _motors_cache["at"] = time.time()
    _motors_cache["data"] = dict(out)
    return out


def ensure_continuous_monitors(*, start_if_inactive: bool = True) -> Dict[str, Any]:
    """Verifica monitores — P2b solo bajo demanda (lazy_engine_manager)."""
    result: Dict[str, Any] = {"motors": []}
    try:
        from services.network_monitor_engine import get_monitor_status, start_network_monitor_engine

        st = get_monitor_status()
        if start_if_inactive and not st.get("active"):
            start_network_monitor_engine()
            st = get_monitor_status()
        result["motors"].append("network_monitor_engine")
        result["network_monitor"] = st
    except Exception as exc:
        result["network_monitor_error"] = str(exc)[:200]

    from services.lazy_engine_manager import engine_status

    for key, engine_name in [
        ("endpoint_monitor", "endpoint_realtime"),
        ("endpoint_enterprise", "endpoint_enterprise"),
        ("network_endpoint_enterprise", "network_endpoint_enterprise"),
    ]:
        try:
            st = engine_status(engine_name)
            result["motors"].append(engine_name)
            result[key] = st
        except Exception as exc:
            result[f"{key}_error"] = str(exc)[:200]

    if start_if_inactive:
        try:
            from services.network_scanner import start_background_scanner

            start_background_scanner()
            result["motors"].append("network_scanner_background")
        except Exception as exc:
            result["network_scanner_error"] = str(exc)[:200]
    return result


def activate_all_defense_motors_on_login(
    user_email: Optional[str] = None,
    *,
    verify_only: bool = False,
) -> Dict[str, Any]:
    """Activa o verifica motores de defensa tras login — sin datos simulados."""
    start_motors = not verify_only
    result = ensure_continuous_monitors(start_if_inactive=start_motors)
    motors: List[str] = list(result.get("motors") or [])
    shields: Dict[str, Any] = {}

    try:
        from services.web_shield_engine import get_engine_status, start_web_shield_engine

        if not (get_engine_status() or {}).get("active"):
            if start_motors:
                start_web_shield_engine()
        shields["web_shield"] = get_engine_status()
        if "web_shield_engine" not in motors:
            motors.append("web_shield_engine")
    except Exception as exc:
        shields["web_shield_error"] = str(exc)[:200]

    try:
        from services.gmail_oauth_service import is_oauth_configured
        from services.microsoft365_oauth_service import is_oauth_configured as m365_oauth

        mail_authorized = is_oauth_configured() or m365_oauth()
        shields["mail_shield_authorized"] = mail_authorized
        if mail_authorized:
            from services.mail_shield_engine import get_engine_status, start_mail_shield_engine

            if not (get_engine_status() or {}).get("state", {}).get("active"):
                if start_motors:
                    start_mail_shield_engine()
            shields["mail_shield"] = get_engine_status()
            motors.append("mail_shield_engine")
        else:
            shields["mail_shield"] = {"status": "skipped", "reason": "sin_integracion_oauth_autorizada"}
    except Exception as exc:
        shields["mail_shield_error"] = str(exc)[:200]

    try:
        from services.ai_kernel import ai_kernel, start_ai_kernel

        if not getattr(ai_kernel, "_running", False):
            if start_motors:
                start_ai_kernel()
        motors.append("ai_kernel")
        shields["ai_kernel"] = {"running": getattr(ai_kernel, "_running", True)}
    except Exception as exc:
        shields["ai_kernel_error"] = str(exc)[:200]

    if not verify_only:
        try:
            from services.network_ndr_service import build_ndr_payload

            ndr = build_ndr_payload()
            result["ndr"] = {
                "events_count": len(ndr.get("events") or []),
                "devices_count": len(ndr.get("devices") or []),
                "source": "network_ndr_service.build_ndr_payload",
            }
            motors.append("network_ndr_service")
        except Exception as exc:
            result["ndr_error"] = str(exc)[:200]

    try:
        from services.defense_center_service import get_automatic_protection_status

        result["automatic_protection"] = get_automatic_protection_status()
    except Exception as exc:
        result["automatic_protection_error"] = str(exc)[:200]

    if not verify_only and user_email:
        try:
            from services.network_security_history_service import (
                ensure_network_monitoring_started,
                get_connected_network_context,
                append_network_security_event,
            )

            ctx = get_connected_network_context()
            hist = ensure_network_monitoring_started(ctx)
            result["network_history"] = {
                "scope_id": hist.get("scope_id"),
                "created": hist.get("created"),
                "disclaimer": (hist.get("meta") or {}).get("disclaimer"),
            }
            if hist.get("created"):
                append_network_security_event(
                    "novus_auto_action",
                    title="Monitoreo continuo activado tras inicio de sesión",
                    evidence={"user_email": user_email, "motors": motors, "verified": True},
                    motor="continuous_monitoring_orchestrator",
                    user_email=user_email,
                    severity="info",
                )
        except Exception as exc:
            result["network_history_error"] = str(exc)[:200]

    result["motors"] = motors
    result["shields"] = shields
    return result


def _record_phase1_network_history(phase1: Dict[str, Any], user_email: str) -> None:
    try:
        from services.network_security_history_service import append_network_security_event

        network = phase1.get("network") or {}
        for dev in (network.get("new_devices") or [])[:20]:
            append_network_security_event(
                "device_new",
                title=f"Dispositivo nuevo observado: {dev.get('ip') or dev.get('mac')}",
                evidence={"device": dev, "source": "network_baseline", "verified": True},
                motor="network_baseline_service",
                user_email=user_email,
                severity="medium",
            )
        for v in (phase1.get("vulnerabilities") or [])[:15]:
            if not isinstance(v, dict):
                continue
            append_network_security_event(
                "vulnerability_found",
                title=str(v.get("title") or v.get("name") or "Vulnerabilidad local"),
                evidence={"finding": v, "verified": True},
                motor="novus_security_integration",
                user_email=user_email,
                severity=str(v.get("severity") or "medium"),
            )
    except Exception as exc:
        logger.debug("phase1 network history: %s", exc)


def run_phase1_immediate_analysis(
    user_email: str,
    ip: str,
    stage_hook: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Análisis rápido (< ~15s objetivo) con motores reales."""
    t0 = time.perf_counter()
    started = _now()
    evidence: Dict[str, Any] = {"user_email": user_email, "client_ip": ip}
    findings: List[Dict[str, Any]] = []
    risks: List[Dict[str, Any]] = []
    counts: Dict[str, Any] = {}

    # Sistema
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage(os.environ.get("SystemDrive", "C:") + "\\" if platform.system() == "Windows" else "/")
        evidence["system"] = {
            "cpu_percent": cpu,
            "ram_percent": mem.percent,
            "disk_percent": disk.percent,
            "os": f"{platform.system()} {platform.release()}",
            "hostname": platform.node(),
        }
        if stage_hook:
            stage_hook("memory")
    except Exception as exc:
        evidence["system_error"] = str(exc)[:200]

    # Integridad NOVUS / CryptoVault
    try:
        from crypto_vault import CryptoVault

        evidence["novus_integrity"] = CryptoVault().verify_health()
    except Exception as exc:
        evidence["novus_integrity"] = {"status": "error", "error": str(exc)[:200]}

    try:
        from services.startup_defense_service import initialize_defense_stack

        evidence["defense_stack_note"] = "Boot report en data/defense_boot_report.json"
        evidence["defense_stack_available"] = callable(initialize_defense_stack)
    except Exception as exc:
        evidence["defense_stack_error"] = str(exc)[:200]

    # Servicios de seguridad / monitores
    try:
        from services.defense_center_service import get_automatic_protection_status

        evidence["automatic_protection"] = get_automatic_protection_status()
    except Exception as exc:
        evidence["automatic_protection_error"] = str(exc)[:200]

    monitors = ensure_continuous_monitors(start_if_inactive=False)
    evidence["monitors_started"] = monitors

    # Firewall / Defender (Windows best-effort) — antes de XDR para acotar tiempo fase 1
    fw = {"status": "No analizado"}
    av = {"status": "No analizado"}
    if platform.system() == "Windows":
        try:
            import subprocess

            r = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=0x08000000,
            )
            fw = {"status": "consultado", "output_tail": (r.stdout or r.stderr or "")[-400:]}
        except Exception as exc:
            fw = {"status": "No disponible", "error": str(exc)[:120]}
        try:
            r2 = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled | ConvertTo-Json"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=0x08000000,
            )
            av = {"status": "consultado" if r2.returncode == 0 else "No disponible", "output": (r2.stdout or "")[:500]}
        except Exception as exc:
            av = {"status": "No disponible", "error": str(exc)[:120]}
    evidence["firewall"] = fw
    evidence["antivirus"] = av
    if stage_hook and (fw.get("status") == "consultado" or av.get("status") == "consultado"):
        stage_hook("integrity")

    processes: List[dict] = []
    try:
        from services.advanced_detector_service import advanced_detector

        processes = advanced_detector.scan_running_processes() or []
        counts["processes"] = len(processes)
        for p in processes[:20]:
            findings.append({
                "title": p.get("name") or "proceso",
                "description": p.get("description") or p.get("command_line"),
                "risk": p.get("risk") or "high",
                "motor": p.get("motor") or "advanced_detector_service",
                "verified": True,
            })
    except Exception as exc:
        evidence["processes_error"] = str(exc)[:200]
    if stage_hook:
        stage_hook("processes")

    connections: List[dict] = []
    try:
        for c in psutil.net_connections(kind="inet")[:80]:
            connections.append({
                "local": f"{getattr(c.laddr, 'ip', '')}:{getattr(c.laddr, 'port', '')}",
                "remote": f"{getattr(c.raddr, 'ip', '')}:{getattr(c.raddr, 'port', '')}" if c.raddr else "",
                "status": c.status,
                "pid": c.pid,
            })
        counts["connections"] = len(connections)
    except Exception as exc:
        evidence["connections_error"] = str(exc)[:200]

    ports: List[dict] = []
    try:
        from services.advanced_detector_service import advanced_detector

        ports = advanced_detector.scan_open_ports() or []
        counts["ports"] = len(ports)
    except Exception as exc:
        evidence["ports_error"] = str(exc)[:200]
    if stage_hook:
        stage_hook("ports")

    network: Dict[str, Any] = {
        "local_ip": format_ip_or_unavailable(get_local_ip()),
        "status": "No disponible",
        "devices_detected": 0,
        "new_devices": [],
        "unknown_devices": [],
    }
    try:
        from services.network_scanner import network_scanner

        cache = network_scanner.get_cache_info()
        nodes = network_scanner.get_cached_nodes() or []
        network["status"] = "cache" if cache.get("valid") else "escaneo_pendiente"
        network["devices_detected"] = len(nodes)
        network["cache"] = cache
        try:
            from services.network_baseline_service import compare_to_baseline

            bl = compare_to_baseline(nodes)
            network["baseline"] = bl
            network["new_devices"] = bl.get("new_devices") or []
        except Exception:
            pass
        attention = [n for n in nodes if n.get("requires_attention") or n.get("is_pending_approval")]
        network["unknown_devices"] = [{"ip": n.get("ip"), "mac": n.get("mac")} for n in attention[:15]]
    except Exception as exc:
        network["error"] = str(exc)[:200]
    if stage_hook:
        stage_hook("network")
        stage_hook("devices")

    try:
        from services.auth_protection_service import auth_protection

        evidence["auth_protection"] = auth_protection.get_protection_status()
    except Exception as exc:
        evidence["auth_protection_error"] = str(exc)[:200]

    try:
        from database import SessionLocal, AuthAccessEvent
        from datetime import timedelta

        since = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
        db = SessionLocal()
        try:
            fails = db.query(AuthAccessEvent).filter(
                AuthAccessEvent.success.is_(False),
                AuthAccessEvent.timestamp >= since,
            ).count()
            evidence["unauthorized_attempts_24h"] = fails
            if fails > 0:
                risks.append({
                    "severity": "medium" if fails >= 5 else "low",
                    "type": "auth_failures",
                    "detail": f"{fails} intento(s) fallido(s) en 24h",
                    "source": "AuthAccessEvent",
                })
        finally:
            db.close()
    except Exception as exc:
        evidence["auth_events_error"] = str(exc)[:200]

    iocs: List[dict] = []
    vulns: List = []
    try:
        from services.novus_security_integration import novus_security

        rt = novus_security.detect_threats_realtime(force=False) or {}
        evidence["threats_realtime"] = {
            "keys": list(rt.keys())[:12],
            "suspicious_count": len(rt.get("suspicious_processes") or []),
        }
        for sp in (rt.get("suspicious_processes") or [])[:10]:
            iocs.append({"type": "process", "detail": sp, "source": "detect_threats_realtime"})
    except Exception as exc:
        evidence["threats_error"] = str(exc)[:200]

    try:
        from services.novus_security_integration import novus_security

        vulns = novus_security.scan_vulnerabilities() or []
        counts["vulnerabilities"] = len(vulns)
    except Exception as exc:
        evidence["vulnerabilities_error"] = str(exc)[:200]
    if stage_hook:
        stage_hook("vulnerabilities")

    try:
        from services.defense_evidence_registry import list_recent_events

        recent = list_recent_events(limit=10)
        evidence["critical_events_recent"] = [
            e for e in recent if str(e.get("severity", "")).lower() in ("high", "critical", "critico", "alto")
        ][:5]
    except Exception as exc:
        evidence["defense_events_error"] = str(exc)[:200]

    duration = round(time.perf_counter() - t0, 2)
    executive_summary = (
        f"Fase 1 completada en {duration}s: {counts.get('processes', 0)} procesos revisados, "
        f"{network.get('devices_detected', 0)} dispositivos en inventario de red, "
        f"{len(findings)} hallazgo(s) de procesos, {len(vulns)} vulnerabilidad(es) en motor local."
    )

    return {
        "phase": 1,
        "started_at": started,
        "finished_at": _now(),
        "duration_sec": duration,
        "system": evidence.get("system"),
        "memory": evidence.get("system"),
        "network": network,
        "processes": processes,
        "connections": connections,
        "ports": ports,
        "findings": findings,
        "vulnerabilities": vulns,
        "indicators_of_compromise": iocs,
        "risks": risks,
        "evidence": evidence,
        "counts": counts,
        "executive_summary": executive_summary,
    }


def _auto_respond(findings: List[dict], user_email: str) -> List[Dict[str, Any]]:
    """Registra y contiene solo con evidencia verificada — sin simular alertas."""
    actions: List[Dict[str, Any]] = []
    for f in findings[:5]:
        if str(f.get("risk", "")).lower() not in ("high", "critical", "alto", "critico"):
            continue
        try:
            from services.defense_coordinator import defense_coordinator

            defense_coordinator.record_detection(
                f.get("motor") or "continuous_monitoring",
                f.get("title") or "process_anomaly",
                f,
                phase="detect",
                outcome="logged",
                user_email=user_email,
                detail=f.get("description") or "",
                confidence="Media",
            )
            actions.append({
                "action": "record_detection",
                "motor": "defense_coordinator",
                "target": f.get("title"),
                "status": "logged",
            })
        except Exception as exc:
            logger.debug("auto_respond: %s", exc)
    return actions


def _persist_report(report: dict, *, trigger_user_email: Optional[str] = None) -> str:
    from services.security_report_service import save_report

    save_report(report)
    try:
        from services.email_delivery_service import deliver_report_to_ceo

        deliver_report_to_ceo(
            report,
            category="auto_monitoring",
            trigger_user_email=trigger_user_email,
        )
    except Exception as exc:
        logger.debug("CEO auto_monitoring report: %s", exc)
    return report["id"]


def _run_phase2_and_finalize(
    user_email: str,
    user_id: Optional[int],
    session_audit_id: str,
    phase1: dict,
    motors: List[str],
    actions: List[dict],
) -> None:
    from services.deep_scan_engine import deep_scan_engine

    scan_id = deep_scan_engine.start_scan(
        session_id=session_audit_id,
        user_id=user_id,
        profile="login_session",
    )
    state = _load_state(session_audit_id) or {}
    state["phase2"] = {"scan_id": scan_id, "status": "running", "progress_pct": 0}
    state["updated_at"] = _now()
    _save_state(session_audit_id, state)

    deadline = time.time() + 3600
    _seen_phase_motors = set()
    while time.time() < deadline:
        st = deep_scan_engine.get_status(scan_id)
        if not st:
            break
        state["phase2"] = {
            "scan_id": scan_id,
            "status": st.get("status"),
            "progress_pct": st.get("progress_pct"),
            "phase_label": st.get("phase_label"),
            "phase": st.get("phase"),
            "stats": st.get("stats"),
        }
        prev_stages = dict(state.get("stage_status") or {})
        scan_done = st.get("status") in ("completed", "failed", "error")
        _apply_deep_scan_phases(
            state,
            st.get("phase"),
            scan_completed=scan_done,
        )
        # Telemetría por etapa dashboard recién completada vía deep scan
        try:
            from services.motor_telemetry_service import motor_complete, motor_start, motor_heartbeat

            phase_id = st.get("phase")
            dkey = _DEEP_PHASE_TO_DASHBOARD.get(phase_id or "")
            if dkey and dkey not in _seen_phase_motors and (state.get("stage_status") or {}).get(dkey) == "completed":
                if prev_stages.get(dkey) != "completed":
                    motor_complete(
                        session_id=session_audit_id,
                        motor_id=dkey,
                        motor_label=dict(DASHBOARD_STAGE_DEFS).get(dkey, dkey),
                        elements_analyzed=st.get("stats") or {},
                        result="ok",
                        evidence={
                            "verifiable": True,
                            "source": "deep_scan_engine",
                            "phase": phase_id,
                            "phase_label": st.get("phase_label"),
                        },
                        progress_pct=_dashboard_stage_view(state).get("progress_pct"),
                    )
                    _seen_phase_motors.add(dkey)
            if dkey and (state.get("stage_status") or {}).get(dkey) not in ("completed", "failed"):
                from services.motor_telemetry_service import active_motors as _am

                already = any(m.get("motor_id") == dkey for m in _am(session_audit_id))
                if not already:
                    motor_start(
                        session_id=session_audit_id,
                        motor_id=dkey,
                        motor_label=dict(DASHBOARD_STAGE_DEFS).get(dkey, dkey),
                        activity=st.get("phase_label") or f"Fase {phase_id}",
                        evidence={"verifiable": True, "phase": phase_id},
                    )
                stats = st.get("stats") or {}
                processed = stats.get("files_analyzed") or stats.get("processes_analyzed")
                motor_heartbeat(
                    session_id=session_audit_id,
                    motor_id=dkey,
                    elements_processed=processed,
                    activity=st.get("phase_label"),
                )
        except Exception as tel_exc:
            logger.debug("phase2 motor telemetry: %s", tel_exc)
        state["updated_at"] = _now()
        _save_state(session_audit_id, state)
        if st.get("status") in ("completed", "failed", "error"):
            if st.get("status") in ("failed", "error"):
                fail_key = _DEEP_PHASE_TO_DASHBOARD.get(st.get("phase") or "") or "report"
                if fail_key in dict(DASHBOARD_STAGE_DEFS):
                    _fail_dashboard_stage(state, fail_key)
                try:
                    from services.motor_telemetry_service import motor_fail

                    motor_fail(
                        session_id=session_audit_id,
                        motor_id=st.get("phase") or "deep_scan",
                        motor_label=st.get("phase_label") or "Deep Scan",
                        error=str(st.get("error") or st.get("status")),
                        elements_analyzed=st.get("stats") or {},
                        evidence={"verifiable": True, "scan_id": scan_id},
                        progress_pct=_dashboard_stage_view(state).get("progress_pct"),
                    )
                except Exception:
                    pass
            break
        time.sleep(2)

    deep_report = deep_scan_engine.get_report(scan_id)
    st = deep_scan_engine.get_status(scan_id) or {}
    phase2 = {
        "scan_id": scan_id,
        "status": st.get("status", "unknown"),
        "duration_sec": st.get("elapsed_sec"),
        "stats": st.get("stats"),
    }
    if deep_report:
        for f in deep_report.get("findings") or []:
            if isinstance(f, dict) and str(f.get("risk", "")).lower() in ("high", "critical"):
                actions.extend(_auto_respond([f], user_email))

    from services.auto_monitoring_report_builder import build_executive_auto_report

    report = build_executive_auto_report(
        user_email=user_email,
        session_audit_id=session_audit_id,
        phase1=phase1,
        phase2=phase2,
        deep_scan_report=deep_report,
        motors_activated=motors,
        auto_actions=actions,
    )
    rid = _persist_report(report, trigger_user_email=user_email)

    state["phase1"] = phase1
    state["phase2"] = phase2
    state["report_id"] = rid
    state["status"] = "completed" if phase2.get("status") == "completed" else "partial"
    # Cerrar etapas: informe persistido → report completed (evita 93% eterno)
    _apply_deep_scan_phases(state, st.get("phase"), scan_completed=True)
    _complete_dashboard_stage(state, "report")
    stages = state.setdefault("stage_status", _init_stage_status())
    for key, _ in DASHBOARD_STAGE_DEFS:
        stg = stages.get(key)
        if stg in ("pending", "running"):
            # Fallido + continuar: no dejar pending que bloquee el 100%
            stages[key] = "failed"
            try:
                from services.motor_telemetry_service import motor_fail

                motor_fail(
                    session_id=session_audit_id,
                    motor_id=key,
                    motor_label=dict(DASHBOARD_STAGE_DEFS).get(key, key),
                    error="Etapa no finalizó antes del cierre del escaneo",
                    evidence={"verifiable": True, "codigo": "STAGE_NOT_FINISHED"},
                    progress_pct=_dashboard_stage_view(state).get("progress_pct"),
                )
            except Exception:
                pass
    state["updated_at"] = _now()
    state["last_progress_pct"] = _dashboard_stage_view(state).get("progress_pct")
    _save_state(session_audit_id, state)

    try:
        from services.motor_telemetry_service import motor_complete

        motor_complete(
            session_id=session_audit_id,
            motor_id="report",
            motor_label="Generando informe",
            elements_analyzed={"report_id": rid},
            result="ok",
            evidence={"verifiable": True, "source": "auto_monitoring_report"},
            progress_pct=100,
        )
    except Exception:
        pass

    try:
        from services.behavior_baseline_service import record_scan_activity_async

        dur = None
        if phase1.get("duration_sec") is not None:
            dur = float(phase1.get("duration_sec") or 0)
            if phase2.get("duration_sec"):
                dur += float(phase2.get("duration_sec") or 0)
        record_scan_activity_async(
            user_email,
            session_audit_id,
            risk_level=None,
            mechanisms=list(motors or []) or ["continuous_monitoring"],
            duration_sec=dur,
            report_id=rid,
        )
    except Exception as bae_exc:
        logger.debug("behavior scan hook: %s", bae_exc)

    with _lock:
        _running_sessions.pop(user_email, None)

    try:
        from services.network_security_history_service import complete_analysis_session

        duration = None
        if phase1.get("duration_sec") is not None:
            duration = float(phase1.get("duration_sec"))
            if phase2.get("duration_sec"):
                duration += float(phase2.get("duration_sec"))
        complete_analysis_session(
            session_audit_id,
            motors_used=motors,
            duration_sec=duration,
            status=state.get("status") or "completed",
        )
    except Exception as exc:
        logger.debug("complete analysis session: %s", exc)

    try:
        from services.defense_evidence_registry import record_defense_event

        record_defense_event(
            phase="audit",
            action="auto_monitoring_report",
            motor="continuous_monitoring_orchestrator",
            outcome="success",
            user_email=user_email,
            detail=f"report={rid} scan={scan_id}",
            evidence={"report_id": rid, "phase1_sec": phase1.get("duration_sec")},
        )
    except Exception:
        pass


def ensure_post_login_monitoring_for_session(
    user_email: str,
    user_id: Optional[int],
    ip: str,
    session_audit_id: str,
) -> Dict[str, Any]:
    """
    Garantiza que el escaneo automático exista para esta sesión de login.
    Si el worker no arrancó (o no hay estado), lo inicia. No reinicia un escaneo
    ya completed/partial/running de la misma session_audit_id.
    """
    if not user_email or not session_audit_id:
        return {"started": False, "reason": "missing_ids"}
    state = _load_state(session_audit_id)
    if state:
        st = state.get("status")
        if st in ("phase1_running", "phase2_running", "completed", "partial"):
            return {"started": False, "reason": "already_active_or_done", "status": st}
        if st == "error":
            # Permitir reintento en el mismo login tras error
            pass
    start_post_login_monitoring(user_email, user_id, ip, session_audit_id)
    return {"started": True, "reason": "started", "session_audit_id": session_audit_id}


def start_post_login_monitoring(
    user_email: str,
    user_id: Optional[int],
    ip: str,
    session_audit_id: str,
) -> None:
    """Punto de entrada tras login — no bloquea HTTP."""
    if _monitoring_already_running(user_email, session_audit_id):
        logger.info("Monitoreo post-login ya activo para %s (%s)", user_email, session_audit_id[:8])
        return

    _supersede_prior_monitoring(user_email, session_audit_id)
    _update_active_index(user_email, session_audit_id)

    with _lock:
        _running_sessions[user_email] = {"session_audit_id": session_audit_id, "started": _now()}

    def _worker():
        state = {
            "user_email": user_email,
            "user_id": user_id,
            "session_audit_id": session_audit_id,
            "ip": ip,
            "status": "phase1_running",
            "started_at": _now(),
            "stage_status": _init_stage_status(),
        }
        _save_state(session_audit_id, state)

        try:
            from services.resource_backpressure_service import (
                CAT_HEAVY_AGG,
                get_backpressure_status,
                should_run_background,
            )

            if not should_run_background(CAT_HEAVY_AGG):
                state["status"] = "deferred_backpressure"
                state["deferred_reason"] = get_backpressure_status()
                state["message"] = (
                    "Monitoreo post-login diferido — recursos del sistema bajo presión."
                )
                _save_state(session_audit_id, state)
                logger.warning(
                    "post_login_monitoring deferred for %s: %s",
                    user_email,
                    state.get("deferred_reason"),
                )
                return
        except Exception as bp_exc:
            logger.debug("post_login backpressure check: %s", bp_exc)

        try:
            from services.network_security_history_service import bootstrap_network_history_on_login
            from services.login_session_audit_service import parse_client_from_user_agent
            from database import SessionLocal, LoginSessionAudit

            client = {}
            db = SessionLocal()
            try:
                row = db.query(LoginSessionAudit).filter(LoginSessionAudit.id == session_audit_id).first()
                if row:
                    client = {
                        "os_name": row.os_name,
                        "browser": row.browser,
                        "device_type": row.device_type,
                    }
            finally:
                db.close()
            if not client:
                client = parse_client_from_user_agent("")
            nh = bootstrap_network_history_on_login(
                user_email,
                session_audit_id,
                client=client,
                ip=ip,
            )
            state["network_history"] = nh
            _save_state(session_audit_id, state)
        except Exception as exc:
            logger.error("network history bootstrap: %s", exc, exc_info=True)

        def _persist_stage(stage_key: str) -> None:
            label = dict(DASHBOARD_STAGE_DEFS).get(stage_key, stage_key)
            _complete_dashboard_stage(state, stage_key)
            view = _dashboard_stage_view(state)
            try:
                from services.motor_telemetry_service import motor_complete

                motor_complete(
                    session_id=session_audit_id,
                    motor_id=stage_key,
                    motor_label=label,
                    elements_analyzed={"stage": stage_key},
                    result="ok",
                    evidence={"verifiable": True, "source": "phase1_stage_hook"},
                    progress_pct=view.get("progress_pct"),
                )
            except Exception as tel_exc:
                logger.debug("motor telemetry complete: %s", tel_exc)
            state["last_progress_pct"] = view.get("progress_pct")
            state["updated_at"] = _now()
            _save_state(session_audit_id, state)

        try:
            _set_current_dashboard_stage(state, "kernel_ia")
            try:
                from services.motor_telemetry_service import motor_start

                motor_start(
                    session_id=session_audit_id,
                    motor_id="kernel_ia",
                    motor_label="Inicializando Kernel IA",
                    activity="Activación / verificación de Kernel IA",
                    evidence={"verifiable": True},
                )
                motor_start(
                    session_id=session_audit_id,
                    motor_id="defense_motors",
                    motor_label="Inicializando motores de defensa",
                    activity="Verificación de motores de defensa",
                    evidence={"verifiable": True},
                )
            except Exception:
                pass
            _save_state(session_audit_id, state)
            monitor_info = activate_all_defense_motors_on_login(user_email, verify_only=True)
            motors = list(monitor_info.get("motors") or [])
            _persist_stage("kernel_ia")
            _persist_stage("defense_motors")
            _set_current_dashboard_stage(state, "processes")
            try:
                from services.motor_telemetry_service import motor_start

                motor_start(
                    session_id=session_audit_id,
                    motor_id="processes",
                    motor_label="Analizando procesos",
                    activity="Inspección de procesos activos",
                    evidence={"verifiable": True},
                )
            except Exception:
                pass
            _save_state(session_audit_id, state)

            phase1 = run_phase1_immediate_analysis(user_email, ip, stage_hook=_persist_stage)
            _record_phase1_network_history(phase1, user_email)
            try:
                from services.network_security_history_service import update_network_state_from_analysis

                update_network_state_from_analysis(phase1)
            except Exception as exc:
                logger.debug("network state update: %s", exc)
            actions = _auto_respond(phase1.get("findings") or [], user_email)

            from services.auto_monitoring_report_builder import build_executive_auto_report

            partial = build_executive_auto_report(
                user_email=user_email,
                session_audit_id=session_audit_id,
                phase1=phase1,
                motors_activated=motors,
                auto_actions=actions,
                analysis_type="Monitoreo automático — Fase 1",
            )
            partial["estado"] = "Parcial"
            rid = _persist_report(partial, trigger_user_email=user_email)

            state["phase1"] = phase1
            state["report_id"] = rid
            state["status"] = "phase2_running"
            state["motors"] = motors
            state["actions"] = actions
            _save_state(session_audit_id, state)

            _update_active_index(user_email, session_audit_id)

            _run_phase2_and_finalize(user_email, user_id, session_audit_id, phase1, motors, actions)
        except Exception as exc:
            logger.error("post_login_monitoring: %s", exc, exc_info=True)
            state["status"] = "error"
            state["error"] = str(exc)[:500]
            _save_state(session_audit_id, state)
            with _lock:
                _running_sessions.pop(user_email, None)

    from services.bounded_background import submit_background

    submit_background(_worker, name=f"NovusMonitor-{session_audit_id[:8]}")


def _update_active_index(user_email: str, session_audit_id: str) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    idx: dict = {}
    if os.path.isfile(ACTIVE_USER_STATE):
        try:
            with open(ACTIVE_USER_STATE, encoding="utf-8") as fh:
                idx = json.load(fh)
        except Exception:
            idx = {}
    idx[user_email] = {"session_audit_id": session_audit_id, "updated_at": _now()}
    with open(ACTIVE_USER_STATE, "w", encoding="utf-8") as fh:
        json.dump(idx, fh, indent=2)


def get_monitoring_status_for_user(user_email: str, *, lightweight: bool = False) -> Dict[str, Any]:
    idx_path = ACTIVE_USER_STATE
    session_audit_id = None
    if os.path.isfile(idx_path):
        try:
            with open(idx_path, encoding="utf-8") as fh:
                idx = json.load(fh)
            session_audit_id = (idx.get(user_email) or {}).get("session_audit_id")
        except Exception:
            pass
    if not session_audit_id:
        motors = get_defense_motors_dashboard_status(force_refresh=not lightweight)
        return {
            "active": False,
            "message": "Sin sesión de monitoreo registrada",
            "waiting_message": "Monitoreo continuo: NOT_CONFIGURED (sin sesión activa)",
            "engine_status": "NOT_CONFIGURED",
            "waiting_for_engines": False,
            "progress_pct": None,
            "progress_source": "none",
            "defense_motors": motors,
        }
    state = _load_state(session_audit_id)
    if not state:
        motors = get_defense_motors_dashboard_status(force_refresh=not lightweight)
        return {
            "active": False,
            "session_audit_id": session_audit_id,
            "defense_motors": motors,
            "waiting_message": "Monitoreo continuo: IDLE (sesión sin estado persistido)",
            "engine_status": "IDLE",
            "waiting_for_engines": False,
            "progress_pct": None,
            "progress_source": "none",
        }
    # Sanea sesiones zombie (phase*_running sin telemetría reciente)
    state = _heal_stale_monitoring_state(session_audit_id, state)
    # Corrige completed con report=skipped (93% fantasma)
    state = _heal_terminal_progress_gap(session_audit_id, state)
    out = {
        "active": state.get("status") in ("phase1_running", "phase2_running", "completed", "partial"),
        "session_audit_id": session_audit_id,
        "status": state.get("status"),
        "report_id": state.get("report_id"),
        "phase1": {
            "duration_sec": (state.get("phase1") or {}).get("duration_sec"),
            "finished_at": (state.get("phase1") or {}).get("finished_at"),
        },
        "phase2": state.get("phase2"),
        "motors": state.get("motors"),
        "updated_at": state.get("updated_at"),
    }
    stage_view = _dashboard_stage_view(state)
    out.update(stage_view)
    out["scan_running"] = state.get("status") in ("phase1_running", "phase2_running")
    if state.get("status") in ("completed", "partial"):
        out["executive_summary"] = _build_dashboard_executive_summary(state)
    elif not lightweight:
        out["executive_summary"] = _build_dashboard_executive_summary(state)
    out["defense_motors"] = get_defense_motors_dashboard_status(force_refresh=not lightweight)
    if state.get("started_at") and state.get("updated_at"):
        out["elapsed_sec"] = _elapsed_sec(state.get("started_at"), state.get("updated_at"))
    p2 = state.get("phase2") or {}
    if p2.get("stats"):
        out["elements_analyzed"] = p2.get("stats")
    if p2.get("phase_label") and out["scan_running"]:
        out["current_mechanism"] = p2.get("phase_label")
    # Telemetría verificable de motores (sin inventar)
    try:
        from services.motor_telemetry_service import list_session_events, active_motors

        out["motor_events"] = list_session_events(session_audit_id, limit=40)
        out["active_motor_telemetry"] = active_motors(session_audit_id)
    except Exception:
        out["motor_events"] = []
        out["active_motor_telemetry"] = []
    if out.get("waiting_for_engines") or (
        out.get("scan_running") and out.get("progress_pct") in (None, 0) and not out.get("completed_count")
    ):
        out["waiting_message"] = (
            "ANÁLISIS EN CURSO — sin motores finalizados aún (no inventar progreso)"
        )
        out["engine_status"] = "ACTIVE" if out.get("scan_running") else "IDLE"
    if state.get("error"):
        out["error"] = state.get("error")
        out["motor_error"] = state.get("error")
    # Compat: UI antigua esperaba completed_motors_only
    if out.get("progress_source") == "finished_motors_only" and out.get("finished_count"):
        out["completed_motors_alias"] = out.get("completed_count")
    return out


def _elapsed_sec(started: str, updated: str) -> Optional[int]:
    a, b = _parse_state_ts(started), _parse_state_ts(updated)
    if not a or not b:
        return None
    return max(0, int((b - a).total_seconds()))
