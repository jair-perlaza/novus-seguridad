"""
Monitoreo de red por tenant — provisión automática, estado y acciones admin.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from utils.logger import logger
from utils.network_identity import UNAVAILABLE

STATUS_ACTIVE = "active"
STATUS_INITIALIZING = "initializing"
STATUS_LIMITED = "limited_visibility"
STATUS_ERROR = "error"
STATUS_DISABLED_MANUAL = "disabled_manual"
STATUS_UNAVAILABLE = "unavailable"


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _local_node_id() -> str:
    from services.tenant_scope_service import _default_node_id

    return _default_node_id()


def classify_monitoring_status(record, *, discovery_meta: Optional[Dict[str, Any]] = None) -> str:
    if not record or not record.monitoring_enabled:
        if record and (record.monitoring_mode or "") == "disabled_manual":
            return STATUS_DISABLED_MANUAL
        return STATUS_UNAVAILABLE
    mode = (record.monitoring_mode or "none").strip()
    if mode == "disabled_manual":
        return STATUS_DISABLED_MANUAL
    meta = discovery_meta or {}
    if meta.get("scan_error"):
        return STATUS_ERROR
    if meta.get("status") == "pending" or meta.get("snapshot_pending"):
        return STATUS_INITIALIZING
    count = meta.get("node_count")
    if count is not None and int(count) <= 1:
        return STATUS_LIMITED
    return STATUS_ACTIVE


def build_network_monitoring_payload(user) -> Dict[str, Any]:
    from services.tenant_scope_service import (
        get_tenant_context,
        get_tenant_scope_record,
        resolve_tenant_id,
        tenant_may_read_platform_telemetry,
    )
    from services.network_dns_service import client_dns_struct, get_live_dns_info
    from services.network_scanner import network_scanner
    from services.network_scan_coordinator import get_coordinator_status
    from utils.host_data import get_primary_network_interface, format_ip_or_unavailable, get_local_ip

    ctx = get_tenant_context(user)
    tenant_id = resolve_tenant_id(user)
    record = get_tenant_scope_record(tenant_id) if tenant_id else None
    primary = get_primary_network_interface() or {}
    meta = network_scanner.get_network_meta() or {}
    cache = network_scanner.get_cache_info() or {}
    coord = get_coordinator_status(include_network_context=False)
    nodes = network_scanner.get_cached_nodes() or []
    try:
        from services.network_snapshot_service import resolve_network_device_counts

        net_counts = resolve_network_device_counts()
        observed_count = net_counts.get("observed_device_count")
        data_freshness_snap = net_counts.get("data_freshness")
        historical_count = net_counts.get("historical_device_count")
    except Exception:
        net_counts = {}
        observed_count = len(nodes) if cache.get("last_scan") else 0
        data_freshness_snap = None
        historical_count = len(nodes)
    iface = meta.get("adapter") or primary.get("adapter")
    dns = client_dns_struct(get_live_dns_info(preferred_interface=iface))
    from services.network_scan_coordinator import is_discovery_paused

    scan_status = "paused" if is_discovery_paused() else (
        "scanning" if (coord.get("scan_in_progress") or network_scanner._scanning) else "idle"
    )
    discovery = {
        "node_count": observed_count if observed_count is not None else len(nodes),
        "historical_device_count": historical_count,
        "data_freshness": data_freshness_snap,
        "last_scan": cache.get("last_scan"),
        "scan_status": scan_status,
        "scan_error": coord.get("scan_error"),
        "snapshot_pending": coord.get("snapshot_pending"),
        "discovery_paused": is_discovery_paused(),
        "status": "success" if nodes else ("pending" if not cache.get("last_scan") else "no_data"),
    }
    operational = tenant_may_read_platform_telemetry(ctx)
    status = classify_monitoring_status(record, discovery_meta=discovery)

    company = getattr(user, "email", None)
    sector = getattr(user, "sector", None)
    role = getattr(user, "role", None)

    limited_reason = None
    if status == STATUS_LIMITED:
        limited_reason = (
            "Monitoreo activo. La red actual limita la visibilidad de otros dispositivos."
        )
    elif status == STATUS_UNAVAILABLE and not operational:
        limited_reason = ctx.get("message")

    freshness = "LIVE" if operational and cache.get("last_scan") else (
        "CACHED" if cache.get("last_scan") else "UNAVAILABLE"
    )

    payload = {
        "status": "success",
        "operational": operational,
        "monitoring_status": status,
        "monitoring_enabled": bool(record and record.monitoring_enabled),
        "monitoring_mode": (record.monitoring_mode if record else "none") or "none",
        "tenant_id": tenant_id,
        "company_email": company,
        "sector": sector or UNAVAILABLE,
        "role": role or UNAVAILABLE,
        "node_id": (record.node_id if record else None) or _local_node_id(),
        "interface": iface or UNAVAILABLE,
        "ssid": meta.get("ssid") or primary.get("ssid"),
        "local_ip": format_ip_or_unavailable(meta.get("local_ip") or primary.get("local_ip") or get_local_ip()),
        "netmask": meta.get("netmask") or primary.get("netmask") or UNAVAILABLE,
        "network_cidr": meta.get("network_range") or UNAVAILABLE,
        "gateway": meta.get("gateway") or primary.get("gateway") or UNAVAILABLE,
        "dns": dns,
        "discovery_method": "arp_scapy",
        "last_scan": cache.get("last_scan") or UNAVAILABLE,
        "observed_device_count": observed_count if observed_count is not None else 0,
        "data_freshness": freshness,
        "limited_visibility_reason": limited_reason,
        "discovery_paused": is_discovery_paused(),
        "scan_status": scan_status,
        "configured_at": record.configured_at if record else None,
        "updated_at": record.updated_at if record else None,
        "timestamp": _utc(),
    }
    from utils.data_provenance import attach_provenance

    origin = "live" if freshness == "LIVE" else (
        "cached" if freshness == "CACHED" else "unavailable"
    )
    return attach_provenance(
        payload,
        data_origin=origin,
        source="network_scanner+tenant_scope",
        tenant_id=tenant_id,
        timestamp=payload["timestamp"],
        extra={"freshness_label": freshness},
    )


def run_discovery_now(user) -> Dict[str, Any]:
    from services.tenant_api_gate import check_tenant_monitoring_or_response
    from services.network_scan_coordinator import (
        is_discovery_paused,
        resume_network_discovery,
        schedule_network_discovery,
    )

    _, blocked = check_tenant_monitoring_or_response(user, scope="network")
    if blocked:
        return {"ok": False, "error": "monitoring_not_configured"}
    if is_discovery_paused():
        resume_network_discovery(reason="admin_discover_now")
    schedule_network_discovery(consumer="admin_network_config", force=True)
    return {"ok": True, "message": "Descubrimiento encolado", "timestamp": _utc()}


def stop_discovery(user) -> Dict[str, Any]:
    from services.tenant_api_gate import check_tenant_monitoring_or_response
    from services.network_scan_coordinator import stop_network_discovery

    _, blocked = check_tenant_monitoring_or_response(user, scope="network")
    if blocked:
        return {"ok": False, "error": "monitoring_not_configured"}
    result = stop_network_discovery(reason="admin_panel")
    return {"ok": True, **result}


def resume_discovery(user) -> Dict[str, Any]:
    from services.tenant_api_gate import check_tenant_monitoring_or_response
    from services.network_scan_coordinator import is_discovery_paused, resume_network_discovery

    _, blocked = check_tenant_monitoring_or_response(user, scope="network")
    if blocked:
        return {"ok": False, "error": "monitoring_not_configured"}
    if not is_discovery_paused():
        return {"ok": True, "message": "Descubrimiento ya activo", "timestamp": _utc()}
    result = resume_network_discovery(reason="admin_panel")
    return {"ok": True, **result}


def restart_monitoring(user) -> Dict[str, Any]:
    from services.tenant_scope_service import provision_tenant_network_monitoring, resolve_tenant_id
    from services.network_scan_coordinator import resume_network_discovery, schedule_network_discovery
    from services.network_security_history_service import ensure_network_profile

    tid = resolve_tenant_id(user)
    if not tid:
        return {"ok": False, "error": "tenant_missing"}
    provision_tenant_network_monitoring(tid, enabled=True, manual=False)
    resume_network_discovery(reason="admin_restart_monitoring")
    try:
        ensure_network_profile()
    except Exception as exc:
        logger.debug("restart_monitoring ensure_network_profile: %s", exc)
    schedule_network_discovery(consumer="admin_restart_monitoring", force=True)
    return {"ok": True, "message": "Monitoreo reiniciado", "timestamp": _utc()}


def set_monitoring_enabled(user, *, enabled: bool) -> Dict[str, Any]:
    from services.tenant_scope_service import provision_tenant_network_monitoring, resolve_tenant_id

    tid = resolve_tenant_id(user)
    if not tid:
        return {"ok": False, "error": "tenant_missing"}
    role = (getattr(user, "role", None) or "").lower()
    if role not in ("admin", "company_admin", "ceo", "superadmin"):
        return {"ok": False, "error": "forbidden"}
    provision_tenant_network_monitoring(tid, enabled=enabled, manual=not enabled)
    if enabled:
        from services.network_scan_coordinator import schedule_network_discovery

        schedule_network_discovery(consumer="admin_enable_monitoring", force=False)
    return {
        "ok": True,
        "monitoring_enabled": enabled,
        "message": "Monitoreo activado" if enabled else "Monitoreo desactivado manualmente",
        "timestamp": _utc(),
    }
