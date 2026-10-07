"""
Historial de seguridad de la red — solo eventos y metadatos obtenidos por análisis reales de NOVUS.
Persistencia en data/network_security_history/{scope_id}/.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import logger
from utils.network_identity import UNAVAILABLE, fetch_public_ip_and_isp, get_wifi_association

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HISTORY_ROOT = os.path.join(ROOT, "data", "network_security_history")
INDEX_PATH = os.path.join(HISTORY_ROOT, "_scope_index.json")

_EVENT_TYPES = frozenset({
    "brute_force",
    "malware",
    "virus",
    "ransomware",
    "mitm",
    "arp_spoofing",
    "dns_spoofing",
    "rogue_dhcp",
    "port_scan",
    "anomalous_traffic",
    "intrusion_detected",
    "vulnerability_found",
    "vulnerability_remediated",
    "device_new",
    "device_disconnect",
    "device_connect",
    "unauthorized_access",
    "novus_auto_action",
    "network_alert",
    "monitoring_started",
    "analysis_session",
})


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _now_date_display() -> str:
    return datetime.now().strftime("%d/%m/%Y")


def _now_time_display() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _label_unavailable(value: Any) -> Any:
    if value is None or value == "" or value == "Sin datos disponibles":
        return UNAVAILABLE
    return value


def _dns_from_context(meta: dict, audit_dns: Any = None) -> str:
    from services.network_dns_service import dns_display

    iface = meta.get("interface") or meta.get("adapter")
    raw = audit_dns or meta.get("dns_servers") or meta.get("dns")
    return dns_display(raw, preferred_interface=iface)


def get_connected_network_context(*, include_public_lookup: bool = True, schedule_discovery: bool = True) -> Dict[str, Any]:
    """Contexto de la red local conectada al host NOVUS (sin inventar histórico)."""
    ctx: Dict[str, Any] = {
        "collected_at": _now(),
        "source": "network_scanner",
    }
    try:
        from services.network_scanner import network_scanner
        from services.network_scan_coordinator import discovery_recommended, schedule_network_discovery

        if schedule_discovery and discovery_recommended():
            schedule_network_discovery(consumer="network_history_context", force=False)
        meta = network_scanner.get_network_meta() or {}
        ctx.update({
            "gateway": meta.get("gateway"),
            "subnet": meta.get("network_range") or meta.get("cidr"),
            "ip_range": meta.get("network_range") or meta.get("cidr"),
            "local_ip": meta.get("local_ip"),
            "interface": meta.get("adapter") or meta.get("interface"),
            "dns_servers": meta.get("dns_servers"),
            "connection_type": meta.get("connection_type"),
            "host_mac": meta.get("mac"),
        })
        cache = network_scanner.get_cache_info()
        ctx["scan_cache"] = cache
        nodes = network_scanner.get_cached_nodes() or []
        ctx["visible_devices_count"] = len(nodes)
        ctx["visible_devices"] = [
            {"ip": n.get("ip"), "mac": n.get("mac"), "hostname": n.get("name") or n.get("hostname")}
            for n in nodes[:50]
        ]
    except Exception as exc:
        ctx["error"] = str(exc)[:300]

    try:
        from services.network_dns_service import get_live_dns_info

        dns_info = get_live_dns_info(preferred_interface=ctx.get("interface"))
        ctx["dns_servers"] = dns_info
        ctx["dns_source"] = dns_info.get("source")
    except Exception as exc:
        logger.debug("dns live query: %s", exc)

    wifi = get_wifi_association()
    ctx["ssid"] = wifi.get("ssid")
    ctx["bssid"] = wifi.get("bssid")
    ctx["encryption_type"] = wifi.get("encryption_type")
    if wifi.get("connection_medium"):
        ctx["connection_type"] = wifi.get("connection_medium")
    ctx["wifi_probe"] = {
        "source": wifi.get("source"),
        "note": wifi.get("note"),
    }

    if include_public_lookup:
        pub = fetch_public_ip_and_isp()
        ctx["public_ip"] = pub.get("public_ip")
        ctx["isp"] = pub.get("isp")
        ctx["public_ip_source"] = pub.get("source")
        if pub.get("note") and not pub.get("public_ip"):
            ctx["public_ip_note"] = pub.get("note")

    for key in ("gateway", "subnet", "ssid", "bssid", "public_ip", "isp", "dns_servers"):
        if key not in ctx or ctx.get(key) in (None, "", "Sin datos disponibles"):
            if key in ("ssid", "bssid", "public_ip", "isp"):
                ctx.setdefault(key, None)
            elif key == "dns_servers":
                ctx[key] = ctx.get("dns_servers") or UNAVAILABLE

    return ctx


def network_lookup_key(context: Optional[Dict[str, Any]] = None) -> str:
    ctx = context or get_connected_network_context(include_public_lookup=False)
    key = "|".join([
        str(ctx.get("subnet") or "unknown_subnet"),
        str(ctx.get("gateway") or "unknown_gw"),
    ])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def network_scope_id(context: Optional[Dict[str, Any]] = None) -> str:
    """Identificador estable por subred + gateway (misma LAN entre sesiones)."""
    ctx = context or get_connected_network_context(include_public_lookup=False)
    lk = network_lookup_key(ctx)
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", (ctx.get("subnet") or "lan"))[:40]
    return f"{safe}_{lk}"


def _scope_dir(scope_id: str) -> str:
    return os.path.join(HISTORY_ROOT, scope_id)


def _load_index() -> Dict[str, str]:
    if not os.path.isfile(INDEX_PATH):
        return {}
    try:
        with open(INDEX_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_index(index: Dict[str, str]) -> None:
    os.makedirs(HISTORY_ROOT, exist_ok=True)
    with open(INDEX_PATH, "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2, ensure_ascii=False)


def _find_legacy_scope_id(ctx: Dict[str, Any]) -> Optional[str]:
    """Reutiliza perfil existente si gateway+subred coinciden (p. ej. scope_id antiguo con local_ip)."""
    gw = str(ctx.get("gateway") or "")
    sn = str(ctx.get("subnet") or "")
    if not os.path.isdir(HISTORY_ROOT):
        return None
    for name in os.listdir(HISTORY_ROOT):
        if name.startswith("_"):
            continue
        meta_path = os.path.join(HISTORY_ROOT, name, "meta.json")
        if not os.path.isfile(meta_path):
            continue
        try:
            with open(meta_path, encoding="utf-8") as fh:
                meta = json.load(fh)
            nc = meta.get("network_context") or meta.get("identification") or {}
            if str(nc.get("gateway") or "") == gw and str(nc.get("subnet") or nc.get("ip_range") or "") == sn:
                return meta.get("scope_id") or name
        except Exception:
            continue
    return None


def resolve_network_scope(ctx: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
    ctx = ctx or get_connected_network_context(include_public_lookup=False)
    lk = network_lookup_key(ctx)
    index = _load_index()
    if lk in index and os.path.isdir(_scope_dir(index[lk])):
        return index[lk], lk
    legacy = _find_legacy_scope_id(ctx)
    if legacy:
        index[lk] = legacy
        _save_index(index)
        return legacy, lk
    sid = network_scope_id(ctx)
    index[lk] = sid
    _save_index(index)
    return sid, lk


def _build_identification(ctx: Dict[str, Any]) -> Dict[str, Any]:
    from services.network_dns_service import client_dns_struct, sanitize_identification_for_client

    base = {
        "ssid": ctx.get("ssid"),
        "bssid": ctx.get("bssid"),
        "gateway": _label_unavailable(ctx.get("gateway")),
        "dns": _dns_from_context(ctx, ctx.get("dns_servers")),
        "ip_range": _label_unavailable(ctx.get("subnet") or ctx.get("ip_range")),
        "public_ip": ctx.get("public_ip") if ctx.get("public_ip") else UNAVAILABLE,
        "isp": ctx.get("isp") if ctx.get("isp") else UNAVAILABLE,
        "local_ip": ctx.get("local_ip"),
        "connection_type": ctx.get("connection_type"),
        "encryption_type": ctx.get("encryption_type") or UNAVAILABLE,
        "collected_at": ctx.get("collected_at"),
        "dns_structured": client_dns_struct(ctx.get("dns_servers"), preferred_interface=ctx.get("interface")),
    }
    return sanitize_identification_for_client(base)


def _default_state() -> Dict[str, Any]:
    return {
        "risk_level": UNAVAILABLE,
        "confidence_level": UNAVAILABLE,
        "encryption_type": UNAVAILABLE,
        "firewall_detected": UNAVAILABLE,
        "segmentation": UNAVAILABLE,
        "overall_status": UNAVAILABLE,
        "updated_at": None,
        "source": None,
    }


def _read_json(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def ensure_network_monitoring_started(context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return ensure_network_profile(context)


def ensure_network_profile(context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    ctx = context or get_connected_network_context()
    sid, lk = resolve_network_scope(ctx)
    scope_path = _scope_dir(sid)
    os.makedirs(scope_path, exist_ok=True)
    meta_path = os.path.join(scope_path, "meta.json")
    state_path = os.path.join(scope_path, "state.json")

    if os.path.isfile(meta_path):
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
        meta["lookup_key"] = lk
        meta["last_analysis_at"] = _now()
        meta["last_analysis_display"] = _now_date_display()
        meta["identification"] = _merge_identification(meta.get("identification") or {}, _build_identification(ctx))
        meta["network_context"] = ctx
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2, ensure_ascii=False)
        try:
            from services.enterprise_data_service import sync_network_profile_to_history
            from services.tenant_scope_service import get_platform_tenant_id

            sync_network_profile_to_history(
                scope_id=sid,
                tenant_id=get_platform_tenant_id(),
                lookup_key=lk,
                identification=meta.get("identification") or {},
                state=_read_json(state_path) or _default_state(),
                first_analysis_at=meta.get("first_analysis_at"),
                last_analysis_at=meta.get("last_analysis_at"),
            )
        except Exception as exc:
            logger.debug("history DB sync profile: %s", exc)
        return {"scope_id": sid, "meta": meta, "created": False, "loaded": True}

    started = _now()
    meta = {
        "scope_id": sid,
        "lookup_key": lk,
        "first_analysis_at": started,
        "first_analysis_display": _now_date_display(),
        "last_analysis_at": started,
        "last_analysis_display": _now_date_display(),
        "monitoring_started_at": started,
        "monitoring_started_display": _now_date_display(),
        "identification": _build_identification(ctx),
        "network_context": ctx,
        "disclaimer": (
            f"NOVUS comenzó a monitorear esta red el día {_now_date_display()}. "
            "No existen registros anteriores a ese momento."
        ),
    }
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2, ensure_ascii=False)
    if not os.path.isfile(state_path):
        with open(state_path, "w", encoding="utf-8") as fh:
            json.dump(_default_state(), fh, indent=2, ensure_ascii=False)

    append_network_security_event(
        "monitoring_started",
        title="Inicio de monitoreo de red",
        evidence={"network_context": ctx, "identification": meta["identification"], "verified": True},
        motor="network_security_history_service",
        scope_id=sid,
    )
    try:
        from services.enterprise_data_service import sync_network_profile_to_history
        from services.tenant_scope_service import get_platform_tenant_id

        sync_network_profile_to_history(
            scope_id=sid,
            tenant_id=get_platform_tenant_id(),
            lookup_key=lk,
            identification=meta["identification"],
            state=_default_state(),
            first_analysis_at=started,
            last_analysis_at=started,
        )
    except Exception as exc:
        logger.debug("history DB sync new profile: %s", exc)
    return {"scope_id": sid, "meta": meta, "created": True, "loaded": False}


def _merge_identification(existing: Dict[str, Any], fresh: Dict[str, Any]) -> Dict[str, Any]:
    from services.network_dns_service import sanitize_identification_for_client

    out = dict(existing)
    for k, v in fresh.items():
        if k in ("dns", "dns_structured"):
            continue
        if v is None or v == UNAVAILABLE:
            continue
        if k in ("public_ip", "isp") and v == UNAVAILABLE:
            continue
        out[k] = v
    for k, v in fresh.items():
        if k in ("dns", "dns_structured"):
            continue
        if k not in out:
            out[k] = v
    if fresh.get("dns"):
        out["dns"] = fresh["dns"]
    if fresh.get("dns_structured"):
        out["dns_structured"] = fresh["dns_structured"]
    return sanitize_identification_for_client(out)


def bootstrap_network_history_on_login(
    user_email: str,
    session_audit_id: str,
    *,
    client: Optional[Dict[str, Any]] = None,
    ip: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Tras login: detectar red, cargar o crear perfil, abrir sesión de análisis.
    No inventa historial previo al primer análisis.
    """
    ctx = get_connected_network_context()
    profile = ensure_network_profile(ctx)
    sid = profile["scope_id"]
    equip = client or {}
    hostname = None
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = UNAVAILABLE

    session_row = {
        "session_id": session_audit_id,
        "started_at": _now(),
        "started_time": _now_time_display(),
        "user_email": user_email,
        "client_ip": ip,
        "equipment": {
            "hostname": hostname,
            "os_name": equip.get("os_name") or UNAVAILABLE,
            "browser": equip.get("browser") or UNAVAILABLE,
            "device_type": equip.get("device_type") or UNAVAILABLE,
        },
        "duration_sec": None,
        "motors_used": [],
        "status": "running",
        "scope_id": sid,
    }
    _append_session_log(sid, session_row)

    return {
        "scope_id": sid,
        "profile_created": profile.get("created"),
        "profile_loaded": profile.get("loaded"),
        "identification": profile.get("meta", {}).get("identification"),
        "disclaimer": profile.get("meta", {}).get("disclaimer"),
        "analysis_session_id": session_audit_id,
    }


def _append_session_log(scope_id: str, row: Dict[str, Any]) -> None:
    path = os.path.join(_scope_dir(scope_id), "sessions.jsonl")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def complete_analysis_session(
    session_audit_id: str,
    *,
    motors_used: Optional[List[str]] = None,
    duration_sec: Optional[float] = None,
    status: str = "completed",
    scope_id: Optional[str] = None,
) -> None:
    sid = scope_id or resolve_network_scope()[0]
    path = os.path.join(_scope_dir(sid), "sessions.jsonl")
    if not os.path.isfile(path):
        return
    lines: List[str] = []
    updated = False
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                lines.append(line)
                continue
            if row.get("session_id") == session_audit_id and row.get("status") == "running":
                row["status"] = status
                row["finished_at"] = _now()
                if duration_sec is not None:
                    row["duration_sec"] = round(float(duration_sec), 2)
                if motors_used:
                    row["motors_used"] = sorted(set(row.get("motors_used") or []) | set(motors_used))
                line = json.dumps(row, ensure_ascii=False)
                updated = True
            lines.append(line)
    if updated:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

    try:
        from services.enterprise_data_service import sync_analysis_session_to_history
        from services.tenant_scope_service import get_platform_tenant_id

        for line in lines:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("session_id") == session_audit_id:
                sync_analysis_session_to_history(row, get_platform_tenant_id())
                break
    except Exception as exc:
        logger.debug("history session sync: %s", exc)

    append_network_security_event(
        "analysis_session",
        title=f"Sesión de análisis {status}: {session_audit_id}",
        evidence={
            "session_audit_id": session_audit_id,
            "motors": motors_used or [],
            "duration_sec": duration_sec,
            "verified": True,
        },
        motor="network_security_history_service",
        scope_id=sid,
        user_email=None,
        severity="info",
    )


def update_network_state_from_analysis(
    phase1: Optional[Dict[str, Any]] = None,
    *,
    scope_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Actualiza state.json solo con hallazgos verificables de motores."""
    sid = scope_id or resolve_network_scope()[0]
    state_path = os.path.join(_scope_dir(sid), "state.json")
    state = _read_json(state_path) or _default_state()
    ctx = get_connected_network_context(include_public_lookup=False)
    wifi = ctx.get("encryption_type")
    if wifi:
        state["encryption_type"] = wifi

    p1 = phase1 or {}
    evidence = p1.get("evidence") if isinstance(p1.get("evidence"), dict) else {}
    fw = evidence.get("firewall") or {}
    if isinstance(fw, dict) and fw.get("status") == "consultado":
        out = (fw.get("output_tail") or "").lower()
        if "on" in out:
            state["firewall_detected"] = "Activo (netsh advfirewall)"
        elif "off" in out:
            state["firewall_detected"] = "Inactivo en uno o más perfiles (netsh)"
        else:
            state["firewall_detected"] = "Consultado — ver evidencia en análisis"
    elif fw:
        state["firewall_detected"] = fw.get("status") or UNAVAILABLE

    net = p1.get("network") if isinstance(p1.get("network"), dict) else {}
    dev_count = net.get("devices_detected")
    if dev_count is not None:
        state["segmentation"] = (
            f"{dev_count} dispositivo(s) visibles en el segmento ARP local"
        )

    risks = p1.get("risks") or p1.get("findings") or []
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    max_sev = "info"
    for r in risks:
        if not isinstance(r, dict):
            continue
        s = str(r.get("severity") or "info").lower()
        if sev_rank.get(s, 0) > sev_rank.get(max_sev, 0):
            max_sev = s
    if risks:
        state["risk_level"] = max_sev
        state["confidence_level"] = "Basada en motores NOVUS (fase 1)"
        state["overall_status"] = "alert" if max_sev in ("critical", "high", "medium") else "stable"
    else:
        if state.get("risk_level") == UNAVAILABLE:
            state["overall_status"] = "sin_hallazgos_fase1" if p1 else UNAVAILABLE

    state["updated_at"] = _now()
    state["source"] = "continuous_monitoring_orchestrator.run_phase1_immediate_analysis"
    with open(state_path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, ensure_ascii=False)
    try:
        from services.enterprise_data_service import sync_network_profile_to_history
        from services.tenant_scope_service import get_platform_tenant_id

        meta = _read_json(os.path.join(_scope_dir(sid), "meta.json"))
        sync_network_profile_to_history(
            scope_id=sid,
            tenant_id=get_platform_tenant_id(),
            lookup_key=meta.get("lookup_key") or network_lookup_key(),
            identification=meta.get("identification") or {},
            state=state,
            first_analysis_at=meta.get("first_analysis_at"),
            last_analysis_at=meta.get("last_analysis_at"),
        )
    except Exception as exc:
        logger.debug("history state sync: %s", exc)
    return state


def list_analysis_sessions(*, scope_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    sid = scope_id or resolve_network_scope()[0]
    path = os.path.join(_scope_dir(sid), "sessions.jsonl")
    if not os.path.isfile(path):
        return []
    out: List[Dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    out.sort(key=lambda r: r.get("started_at") or "", reverse=True)
    return out[: min(limit, 200)]


def get_network_profile(scope_id: Optional[str] = None) -> Dict[str, Any]:
    sid = scope_id or resolve_network_scope()[0]
    meta = _read_json(os.path.join(_scope_dir(sid), "meta.json"))
    state = _read_json(os.path.join(_scope_dir(sid), "state.json")) or _default_state()
    if not meta:
        boot = ensure_network_profile()
        meta = boot.get("meta") or {}
        sid = boot.get("scope_id") or sid
    from services.network_dns_service import sanitize_identification_for_client

    idn = meta.get("identification") or _build_identification(get_connected_network_context())
    return {
        "scope_id": sid,
        "identification": sanitize_identification_for_client(idn),
        "first_analysis_at": meta.get("first_analysis_at") or meta.get("monitoring_started_at"),
        "last_analysis_at": meta.get("last_analysis_at"),
        "disclaimer": meta.get("disclaimer"),
        "state": state,
    }


def append_network_security_event(
    event_type: str,
    *,
    title: str,
    evidence: Dict[str, Any],
    motor: str,
    severity: str = "info",
    scope_id: Optional[str] = None,
    user_email: Optional[str] = None,
    action_taken: Optional[str] = None,
    event_status: str = "recorded",
) -> Optional[Dict[str, Any]]:
    if event_type not in _EVENT_TYPES:
        logger.debug("network history: tipo no catalogado %s", event_type)
        event_type = "network_alert"
    if not evidence or not isinstance(evidence, dict):
        return None
    if evidence.get("verified") is False:
        return None

    sid = scope_id or resolve_network_scope()[0]
    ensure_network_profile()
    log_path = os.path.join(_scope_dir(sid), "events.jsonl")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    row = {
        "id": f"NSH-{datetime.now().strftime('%Y%m%d%H%M%S%f')}",
        "timestamp": _now(),
        "time": _now_time_display(),
        "event_type": event_type,
        "title": title[:300],
        "severity": severity,
        "motor": motor,
        "user_email": user_email,
        "evidence": evidence,
        "scope_id": sid,
        "verified": True,
        "status": event_status,
        "action_taken": action_taken,
    }
    try:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.error("network_security_history append: %s", exc)
        return None
    return row


def list_network_security_events(
    *,
    scope_id: Optional[str] = None,
    limit: int = 100,
    event_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    sid = scope_id or resolve_network_scope()[0]
    log_path = os.path.join(_scope_dir(sid), "events.jsonl")
    if not os.path.isfile(log_path):
        meta_path = os.path.join(_scope_dir(sid), "meta.json")
        if not os.path.isfile(meta_path):
            return []
    out: List[Dict[str, Any]] = []
    try:
        with open(log_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event_type and row.get("event_type") != event_type:
                    continue
                out.append(row)
    except Exception:
        return []
    out.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
    return out[: min(limit, 500)]


def list_recent(limit: int = 30) -> List[Dict[str, Any]]:
    """Alias para Swarm collaborator network_history."""
    return list_network_security_events(limit=limit)


def get_recent_events(limit: int = 30) -> List[Dict[str, Any]]:
    return list_recent(limit=limit)


def build_kernel_network_insights(scope_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Conclusiones derivadas únicamente del historial persistido.
    Sin datos suficientes → mensaje explícito, sin estadísticas inventadas.
    """
    sid = scope_id or resolve_network_scope()[0]
    events = list_network_security_events(scope_id=sid, limit=500)
    sessions = list_analysis_sessions(scope_id=sid, limit=100)
    meta = _read_json(os.path.join(_scope_dir(sid), "meta.json"))

    threat_types = frozenset({
        "malware", "virus", "ransomware", "mitm", "arp_spoofing", "dns_spoofing",
        "rogue_dhcp", "brute_force", "port_scan", "intrusion_detected",
        "unauthorized_access", "anomalous_traffic", "vulnerability_found",
    })
    threats = [e for e in events if e.get("event_type") in threat_types]

    if not meta.get("first_analysis_at") and not events:
        return {
            "scope_id": sid,
            "sufficient_data": False,
            "message": (
                "No hay historial verificable para esta red. "
                "Los análisis posteriores al primer monitoreo alimentarán el Kernel IA."
            ),
            "insights": [],
        }

    if len(events) < 2 and len(threats) == 0 and len(sessions) < 2:
        return {
            "scope_id": sid,
            "sufficient_data": False,
            "message": "Datos insuficientes para tendencias o estadísticas agregadas.",
            "event_count": len(events),
            "insights": [],
        }

    by_type: Dict[str, int] = {}
    by_hour: Dict[str, int] = {}
    device_macs: Dict[str, int] = {}
    for e in events:
        t = e.get("event_type") or "other"
        by_type[t] = by_type.get(t, 0) + 1
        ts = e.get("timestamp") or ""
        if len(ts) >= 13:
            hour = ts[11:13]
            by_hour[hour] = by_hour.get(hour, 0) + 1
        ev = e.get("evidence") if isinstance(e.get("evidence"), dict) else {}
        dev = ev.get("device") if isinstance(ev.get("device"), dict) else {}
        mac = (dev.get("mac") or "").lower()
        if mac:
            device_macs[mac] = device_macs.get(mac, 0) + 1

    insights: List[Dict[str, Any]] = []
    if threats:
        insights.append({
            "kind": "attack_frequency",
            "summary": f"{len(threats)} evento(s) de amenaza registrado(s) desde el inicio del monitoreo.",
            "by_type": {k: by_type[k] for k in sorted(by_type) if k in threat_types},
        })
    else:
        insights.append({
            "kind": "security_evolution",
            "summary": "Sin eventos de amenaza catalogados en el historial verificable hasta ahora.",
        })

    if by_hour:
        peak = max(by_hour.items(), key=lambda x: x[1])
        insights.append({
            "kind": "activity_hours",
            "summary": f"Mayor actividad registrada en historial a las {peak[0]}:00 ({peak[1]} evento(s)).",
            "distribution": dict(sorted(by_hour.items())),
        })

    recurring = sorted(device_macs.items(), key=lambda x: -x[1])[:5]
    if recurring:
        insights.append({
            "kind": "recurring_devices",
            "summary": "Dispositivos con más eventos en historial (MAC).",
            "devices": [{"mac": m, "events": c} for m, c in recurring],
        })

    if len(sessions) >= 2:
        insights.append({
            "kind": "analysis_sessions",
            "summary": f"{len(sessions)} sesión(es) de análisis documentada(s) en esta red.",
        })

    return {
        "scope_id": sid,
        "sufficient_data": True,
        "event_count": len(events),
        "threat_event_count": len(threats),
        "first_analysis_at": meta.get("first_analysis_at"),
        "last_analysis_at": meta.get("last_analysis_at"),
        "insights": insights,
    }


def _persist_kernel_insights_result(payload: dict) -> None:
    try:
        from services.enterprise_data_service import persist_kernel_insights

        persist_kernel_insights(payload)
    except Exception as exc:
        logger.debug("kernel learning DB: %s", exc)


def get_network_history_summary(scope_id: Optional[str] = None, *, schedule_discovery: bool = True) -> Dict[str, Any]:
    ctx = get_connected_network_context(schedule_discovery=schedule_discovery)
    sid = scope_id or resolve_network_scope(ctx)[0]
    profile = get_network_profile(sid)
    meta_path = os.path.join(_scope_dir(sid), "meta.json")
    meta: Dict[str, Any] = _read_json(meta_path)
    if not meta:
        meta = {
            "disclaimer": (
                "NOVUS aún no ha registrado el inicio de monitoreo en esta red. "
                "El historial se creará al primer evento o al iniciar sesión con monitoreo activo."
            ),
        }
    events = list_network_security_events(scope_id=sid, limit=200)
    by_type: Dict[str, int] = {}
    for e in events:
        t = e.get("event_type") or "other"
        by_type[t] = by_type.get(t, 0) + 1
    kernel = build_kernel_network_insights(scope_id=sid)
    _persist_kernel_insights_result(kernel)
    from services.network_dns_service import (
        sanitize_identification_for_client,
        sanitize_network_context_for_client,
    )

    def _sanitize_event(ev: Dict[str, Any]) -> Dict[str, Any]:
        row = dict(ev)
        evidence = row.get("evidence")
        if isinstance(evidence, dict):
            nc = evidence.get("network_context")
            if isinstance(nc, dict):
                evidence = {**evidence, "network_context": sanitize_network_context_for_client(nc)}
            idn = evidence.get("identification")
            if isinstance(idn, dict):
                evidence = {**evidence, "identification": sanitize_identification_for_client(idn)}
            row["evidence"] = evidence
        return row

    safe_ctx = sanitize_network_context_for_client(ctx)
    safe_idn = sanitize_identification_for_client(profile.get("identification") or {})
    safe_meta = dict(meta)
    if isinstance(safe_meta.get("network_context"), dict):
        safe_meta["network_context"] = sanitize_network_context_for_client(safe_meta["network_context"])
    if isinstance(safe_meta.get("identification"), dict):
        safe_meta["identification"] = sanitize_identification_for_client(safe_meta["identification"])

    return {
        "scope_id": sid,
        "network_context": safe_ctx,
        "identification": safe_idn,
        "state": profile.get("state"),
        "meta": safe_meta,
        "analysis_sessions": list_analysis_sessions(scope_id=sid, limit=20),
        "event_count": len(events),
        "events_by_type": by_type,
        "recent_events": [_sanitize_event(e) for e in events[:30]],
        "monitoring_started_at": meta.get("monitoring_started_at") or meta.get("first_analysis_at"),
        "first_analysis_at": meta.get("first_analysis_at"),
        "last_analysis_at": meta.get("last_analysis_at"),
        "disclaimer": meta.get("disclaimer"),
        "kernel_insights": kernel,
        "unavailable_label": UNAVAILABLE,
    }


def map_device_connection_event(event_type: str) -> Optional[str]:
    m = {
        "connect": "device_connect",
        "disconnect": "device_disconnect",
        "new_device": "device_new",
        "port_change": "port_scan",
        "traffic_change": "anomalous_traffic",
        "behavior_change": "anomalous_traffic",
        "ip_change": "network_alert",
    }
    return m.get(event_type)


def try_append_from_defense_event(event: Dict[str, Any]) -> None:
    """Deriva entrada de historial desde defense_registry si hay evidencia de red/amenaza."""
    motor = (event.get("motor") or "").lower()
    threat = (event.get("threat_type") or event.get("action") or "").lower()
    evidence = event.get("evidence") if isinstance(event.get("evidence"), dict) else {}
    if evidence and evidence.get("verified") is not False:
        evidence = {**evidence, "verified": True}
    mapping = None
    if "brute" in threat or "auth" in threat or motor == "auth_protection_service":
        mapping = "brute_force" if "brute" in threat else "unauthorized_access"
    elif "ransom" in threat:
        mapping = "ransomware"
    elif any(x in threat for x in ("malware", "virus", "trojan")):
        mapping = "malware" if "malware" in threat or "trojan" in threat else "virus"
    elif "port" in threat and "scan" in threat:
        mapping = "port_scan"
    elif "intrusion" in threat:
        mapping = "intrusion_detected"
    elif "arp" in threat or "ndr" in motor:
        mapping = "arp_spoofing" if "arp" in threat else "network_alert"
    elif "mitm" in threat:
        mapping = "mitm"
    elif "dns" in threat or "dhcp" in threat:
        mapping = "dns_spoofing" if "dns" in threat else "rogue_dhcp"
    elif "anomal" in threat or "traffic" in threat:
        mapping = "anomalous_traffic"
    elif "vuln" in threat:
        mapping = "vulnerability_found"
    elif event.get("phase") == "respond" and "remed" in (event.get("action") or ""):
        mapping = "vulnerability_remediated"
    elif event.get("phase") == "audit" and event.get("action") == "auto_monitoring_report":
        mapping = "novus_auto_action"
    if not mapping:
        return
    append_network_security_event(
        mapping,
        title=event.get("action") or event.get("detail") or mapping,
        evidence={**evidence, "defense_event": {k: event.get(k) for k in ("motor", "action", "phase", "outcome")}},
        motor=event.get("motor") or "defense_evidence_registry",
        severity=event.get("outcome") or "info",
        action_taken=event.get("detail"),
    )
    try:
        from services.enterprise_data_service import record_security_event_domain
        from services.tenant_scope_service import get_platform_tenant_id

        record_security_event_domain(
            event_type=mapping,
            tenant_id=get_platform_tenant_id(),
            severity=str(event.get("outcome") or "info"),
            motor=event.get("motor"),
            evidence=evidence,
            action_taken=event.get("detail"),
            legacy_ref=f"defense:{event.get('motor')}:{event.get('action')}",
        )
    except Exception:
        pass
