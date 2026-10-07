"""
Centro de Defensa — resumen para Dashboard, panel de motores y protección automática.
Solo telemetría verificable; reutiliza manual_defense y escudos existentes.
"""
from __future__ import annotations

import socket
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _engine_state(
    engine_id: str,
    label: str,
    *,
    active: bool = False,
    analyzing: bool = False,
    attention: bool = False,
    unavailable: bool = False,
    detail: str = "",
) -> Dict[str, Any]:
    if unavailable:
        state = "no_disponible"
    elif analyzing:
        state = "analizando"
    elif attention:
        state = "requiere_atencion"
    elif active:
        state = "activo"
    else:
        state = "inactivo"
    return {
        "id": engine_id,
        "label": label,
        "state": state,
        "detail": detail or None,
    }


def get_automatic_protection_status() -> Dict[str, Any]:
    """Protección en segundo plano: monitores reales del proceso NOVUS."""
    network_active = False
    endpoint_active = False
    errors: List[str] = []
    try:
        from services.network_monitor_engine import get_monitor_status
        network_active = bool(get_monitor_status().get("active"))
    except Exception as exc:
        errors.append(f"network_monitor: {exc}")
    try:
        from services.endpoint_realtime_monitor import get_monitor_status
        endpoint_active = bool(get_monitor_status().get("active"))
    except Exception as exc:
        errors.append(f"endpoint_monitor: {exc}")
    active = network_active or endpoint_active
    return {
        "active": active,
        "label": "Activa" if active else "Inactiva",
        "network_monitor": network_active,
        "endpoint_monitor": endpoint_active,
        "errors": errors or None,
    }


def get_engines_panel(user_id: Optional[int] = None) -> List[Dict[str, Any]]:
    engines: List[Dict[str, Any]] = []

    # Kernel IA — ACTIVE only with runtime evidence
    try:
        from services.ai_kernel import ai_kernel
        st = ai_kernel.get_status() or {}
        running = bool(st.get("running") or st.get("sessions_active"))
        analyzing = st.get("activity") == "analyzing" or bool(st.get("running"))
        engines.append(
            _engine_state(
                "kernel_ia",
                "Kernel IA",
                active=running,
                analyzing=bool(analyzing),
                unavailable=not running and st.get("guardia") in (None, "offline", "unavailable"),
                detail=f"sessions={st.get('sessions_active', 0)} guardia={st.get('guardia')} status={st.get('status') or 'IDLE'}",
            )
        )
    except Exception as exc:
        engines.append(_engine_state("kernel_ia", "Kernel IA", unavailable=True, detail=str(exc)))

    # Network Shield
    try:
        from services.network_monitor_engine import get_monitor_status
        mon = get_monitor_status()
        active = bool(mon.get("active"))
        attention = int(mon.get("error_count") or 0) > 3
        engines.append(
            _engine_state(
                "network_shield",
                "Network Shield",
                active=active,
                analyzing=bool(mon.get("last_scan_at") and not mon.get("stable_cycles")),
                attention=attention,
                detail=f"devices={mon.get('devices_monitored')} errors={mon.get('error_count')}",
            )
        )
    except Exception as exc:
        engines.append(_engine_state("network_shield", "Network Shield", unavailable=True, detail=str(exc)))

    # Endpoint Shield
    try:
        from services.endpoint_scan_engine import endpoint_scan_engine
        from services.endpoint_realtime_monitor import get_monitor_status as ep_mon

        ep = ep_mon()
        es = endpoint_scan_engine.engine_status()
        engines.append(
            _engine_state(
                "endpoint_shield",
                "Endpoint Shield",
                active=bool(ep.get("active")),
                analyzing=False,
                detail=f"host={es.get('host')} monitor={ep.get('status')}",
            )
        )
    except Exception as exc:
        engines.append(_engine_state("endpoint_shield", "Endpoint Shield", unavailable=True, detail=str(exc)))

    # Web Shield — status payload is a dict; do not treat object as ACTIVE
    try:
        from services.web_shield_engine import get_engine_status
        ws = get_engine_status() or {}
        st = ws.get("status")
        if isinstance(st, dict):
            loop_active = bool(st.get("active") or st.get("running") or ws.get("active"))
            detail = st.get("summary") or ws.get("summary") or ws.get("engine_state") or str(st.get("state") or "")
        else:
            loop_active = st not in ("error", "offline", None, "stopped", "idle") and bool(
                ws.get("enabled") or ws.get("active")
            )
            # Prefer explicit active flag when present
            if "active" in ws:
                loop_active = bool(ws.get("active"))
            detail = ws.get("summary") or ws.get("engine_state") or (str(st) if st else None)
        engines.append(
            _engine_state(
                "web_shield",
                "Web Shield",
                active=loop_active,
                unavailable=st in ("error", "offline") if not isinstance(st, dict) else False,
                detail=detail or ("ACTIVE" if loop_active else "IDLE"),
            )
        )
    except Exception as exc:
        engines.append(_engine_state("web_shield", "Web Shield", unavailable=True, detail=str(exc)))

    # Mail Shield
    try:
        from services.mail_shield_engine import get_engine_status
        ms = get_engine_status(user_id)
        integ = (ms.get("integrations") or {}).get("summary_message") or ""
        connected = (ms.get("integrations") or {}).get("any_connected")
        engines.append(
            _engine_state(
                "mail_shield",
                "Mail Shield",
                active=bool(connected),
                unavailable=not connected and "no configurada" in integ.lower(),
                attention=not connected,
                detail=integ or ("Conectado" if connected else "Requiere OAuth"),
            )
        )
    except Exception as exc:
        engines.append(_engine_state("mail_shield", "Mail Shield", unavailable=True, detail=str(exc)))

    # Cloud Shield (registro arquitectura)
    try:
        from services.shield_platform_registry import list_shields
        cloud = next((s for s in list_shields() if s.get("id") == "cloud_shield"), {})
        planned = cloud.get("status") == "planned"
        engines.append(
            _engine_state(
                "cloud_shield",
                "Cloud Shield",
                unavailable=planned,
                detail=cloud.get("description") or "Arquitectura reservada",
            )
        )
    except Exception as exc:
        engines.append(_engine_state("cloud_shield", "Cloud Shield", unavailable=True, detail=str(exc)))

    # CryptoVault
    try:
        from services.novus_security_integration import novus_security
        vault_ok = novus_security.vault is not None
        engines.append(
            _engine_state(
                "cryptovault",
                "CryptoVault",
                active=vault_ok,
                unavailable=not vault_ok,
                detail="Vault activo" if vault_ok else "Vault no inicializado",
            )
        )
    except Exception as exc:
        engines.append(_engine_state("cryptovault", "CryptoVault", unavailable=True, detail=str(exc)))

    # Adaptive Defense — use real panel keys (estado_actual / contenciones_activas)
    try:
        from services.adaptive_defense_engine import get_adaptive_defense_panel
        panel = get_adaptive_defense_panel() or {}
        active_inc = int(
            panel.get("active_incidents")
            or panel.get("contenciones_activas")
            or 0
        )
        estado = str(panel.get("estado_actual") or panel.get("status") or "").lower()
        engine_on = bool(
            panel.get("active")
            or panel.get("enabled")
            or estado in ("activo", "active", "armed", "idle", "listo", "ready")
        )
        # Module available + zero incidents = IDLE (not NOT_CONFIGURED)
        unavailable = estado in ("unavailable", "error", "offline") and not engine_on
        engines.append(
            _engine_state(
                "adaptive_defense",
                "Adaptive Defense",
                active=engine_on and active_inc > 0,
                attention=active_inc > 0,
                unavailable=unavailable,
                detail=(
                    f"status={panel.get('estado_actual') or panel.get('status') or ('IDLE' if engine_on else 'NOT_AVAILABLE')}"
                    f" incidentes_activos={active_inc}"
                ),
            )
        )
    except Exception as exc:
        engines.append(_engine_state("adaptive_defense", "Adaptive Defense", unavailable=True, detail=str(exc)))

    # XDR — cache only (never call detect_threats_realtime from panel GET)
    try:
        from services.http_shell_service import get_threat_cache_snapshot

        cache = get_threat_cache_snapshot() or {}
        last_scan = cache.get("last_scan")
        proc = len(cache.get("suspicious_processes") or [])
        engines.append(
            _engine_state(
                "xdr",
                "XDR",
                active=bool(last_scan),
                attention=proc > 0,
                unavailable=not last_scan,
                detail=(
                    f"last_scan={last_scan or 'NOT_AVAILABLE'} procesos_sospechosos={proc}"
                    if last_scan
                    else "Sin escaneo en caché (IDLE / NOT_AVAILABLE)"
                ),
            )
        )
    except Exception as exc:
        engines.append(_engine_state("xdr", "XDR", unavailable=True, detail=str(exc)))

    # NDR
    try:
        from services.network_monitor_engine import get_monitor_status
        mon = get_monitor_status()
        engines.append(
            _engine_state(
                "ndr",
                "NDR",
                active=bool(mon.get("active")),
                detail=f"scan_count={mon.get('scan_count')}",
            )
        )
    except Exception as exc:
        engines.append(_engine_state("ndr", "NDR", unavailable=True, detail=str(exc)))

    # Behavioral Threat Detection
    try:
        from services.behavioral_threat_detection import get_btde_orchestrator_status, get_btde_status

        bst = get_btde_orchestrator_status()
        eng = get_btde_status()
        engines.append(
            _engine_state(
                "btde",
                "Behavioral Threat Detection",
                active=bool(bst.get("active")),
                analyzing=bool(bst.get("last_cycle_at")),
                detail=f"cycles={bst.get('cycles')} risk={(bst.get('last_risk') or eng.get('last_risk') or {}).get('level')}",
            )
        )
    except Exception as exc:
        engines.append(
            _engine_state("btde", "Behavioral Threat Detection", unavailable=True, detail=str(exc))
        )

    # Zero-Day Detection Engine Enterprise (ZDDE)
    try:
        from services.zero_day_detection import get_zdde_orchestrator_status, get_zdde_status

        zst = get_zdde_orchestrator_status()
        zeng = get_zdde_status()
        last = zeng.get("last") or {}
        cls = last.get("classification") or zst.get("last_classification") or "sin_ciclo"
        attention = cls == "CANDIDATO_AMENAZA_DESCONOCIDA"
        engines.append(
            _engine_state(
                "zdde",
                "Zero-Day Detection (ZDDE)",
                active=bool(zst.get("active")),
                analyzing=bool(zst.get("last_cycle_at")),
                attention=attention,
                detail=f"class={cls} motors={last.get('signal_motors')} conf={last.get('confidence_level')}",
            )
        )
    except Exception as exc:
        engines.append(
            _engine_state("zdde", "Zero-Day Detection (ZDDE)", unavailable=True, detail=str(exc))
        )

    # Swarm Mesh
    try:
        from services.swarm_defense import swarm_defense_engine

        sst = swarm_defense_engine.status()
        mesh = sst.get("mesh") or {}
        engines.append(
            _engine_state(
                "swarm_mesh",
                "Swarm Mesh",
                active=bool(sst.get("ok")),
                detail=f"peers={mesh.get('peers_connected')} inbound={(mesh.get('sync') or {}).get('inbound_events')}",
            )
        )
    except Exception as exc:
        engines.append(_engine_state("swarm_mesh", "Swarm Mesh", unavailable=True, detail=str(exc)))

    # Health Monitoring & Self-Healing Engine
    try:
        from services.health_engine import get_health_orchestrator_status, get_health_status

        hst = get_health_orchestrator_status()
        heng = get_health_status()
        engines.append(
            _engine_state(
                "health_engine",
                "Health Engine",
                active=bool(hst.get("active")),
                analyzing=bool(hst.get("last_cycle_at")),
                attention=hst.get("last_overall") in ("detenido", "degradado"),
                detail=f"cycles={hst.get('cycles')} overall={hst.get('last_overall') or heng.get('last_overall')}",
            )
        )
    except Exception as exc:
        engines.append(_engine_state("health_engine", "Health Engine", unavailable=True, detail=str(exc)))

    return engines


def get_dashboard_summary(user_id: Optional[int] = None) -> Dict[str, Any]:
    from services.manual_defense_catalog import MECHANISMS
    from services.manual_defense_service import list_history
    from services.system_monitor import system_monitor
    from services.engine_runtime_registry import get_engine_runtime_summary

    auto = get_automatic_protection_status()
    # Hot path: no materializar 60+ stubs not_verifiable ni rebuild completo del catálogo
    # user_id=None: probes de plataforma compartidos (evita N caches/probes por tenant)
    impl_count = len(MECHANISMS)
    runtime = get_engine_runtime_summary(
        user_id=None,
        implemented_ids=set(),
        include_catalog_stubs=False,
    )
    runtime_counts = dict(runtime.get("counts") or {})
    runtime_counts["implemented"] = impl_count
    runtime_counts["runtime_not_verifiable"] = max(
        0,
        impl_count
        - (
            runtime_counts.get("runtime_running", 0)
            + runtime_counts.get("runtime_active", 0)
            + runtime_counts.get("runtime_idle", 0)
            + runtime_counts.get("runtime_stopped", 0)
            + runtime_counts.get("runtime_error", 0)
            + runtime_counts.get("runtime_not_configured", 0)
            + runtime_counts.get("runtime_paused", 0)
            + runtime_counts.get("runtime_not_implemented", 0)
        ),
    )
    # engines en respuesta: solo probes con telemetría (no stubs de catálogo)
    runtime_light = {
        "observed_at": runtime.get("observed_at"),
        "engines": runtime.get("engines") or [],
        "counts": runtime_counts,
        "active_motors_count": runtime_counts.get("runtime_active", 0),
        "running_motors_count": runtime_counts.get("runtime_running", 0),
        "source": runtime.get("source"),
        "catalog_stubs_included": False,
    }

    history = list_history(limit=1)
    last_manual = history[0] if history else None

    protection_state = "Operativa"
    if runtime_counts.get("runtime_active", 0) == 0:
        protection_state = "Limitada"
    elif not auto.get("active"):
        protection_state = "Manual predominante"

    system_health = "Sin datos disponibles"
    try:
        st = system_monitor.get_system_status()
        cpu = st.get("cpu")
        if isinstance(cpu, (int, float)):
            if cpu > 90:
                system_health = "Carga crítica"
            elif cpu > 75:
                system_health = "Carga elevada"
            else:
                system_health = "Estable"
        else:
            system_health = "Telemetría parcial"
    except Exception as exc:
        system_health = f"Error: {exc}"

    deep_scan_running = False
    try:
        from services.deep_scan_engine import deep_scan_engine
        with deep_scan_engine._lock:
            deep_scan_running = any(
                s.get("status") == "running" for s in (deep_scan_engine._scans or {}).values()
            )
    except Exception:
        pass

    return {
        "protection_overview": protection_state,
        "automatic_protection": auto,
        "active_motors_count": runtime_counts.get("runtime_active", 0),
        "running_motors_count": runtime_counts.get("runtime_running", 0),
        "implemented_mechanisms_count": impl_count,
        "runtime_motors": runtime_light,
        "total_mechanisms": impl_count,
        "last_manual_run": last_manual,
        "last_updated": _now(),
        "system_health": system_health,
        "hostname": socket.gethostname(),
        "scan_in_progress": deep_scan_running,
        "module_url": "/centro-defensa",
    }


def get_playbooks_defense_payload(user_id: Optional[int] = None) -> Dict[str, Any]:
    from services.manual_defense_catalog import CATEGORIES, build_catalog

    catalog = build_catalog(user_id)
    by_cat: Dict[str, List[dict]] = {}
    for m in catalog:
        by_cat.setdefault(m["category"], []).append(m)
    return {
        "categories": [{"key": k, "label": lbl} for k, lbl in CATEGORIES],
        "mechanisms_by_category": by_cat,
    }
