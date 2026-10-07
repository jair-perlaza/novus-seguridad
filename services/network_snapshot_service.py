"""
Network discovery snapshots — nodos y NDR leen snapshot; ARP solo en background.
Single-flight coordinado via network_scan_coordinator.schedule_network_discovery.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from utils.logger import logger

_lock = threading.Lock()
_mem_cache: Dict[str, tuple[float, Dict[str, Any]]] = {}
_NODES_PATH = os.path.join("data", "network", "nodes_snapshot.json")
_NDR_PATH = os.path.join("data", "network", "ndr_snapshot.json")
_TOPOLOGY_PATH = os.path.join("data", "network", "topology_snapshot.json")
_CONTEXT_PATH = os.path.join("data", "network", "context_snapshot.json")
_STALE_SEC = 90.0
_boot_ready = threading.Event()
_boot_grace_until: float = 0.0


def set_boot_grace_period(seconds: float = 60.0) -> None:
    global _boot_grace_until
    _boot_grace_until = time.time() + max(0.0, seconds)


def _in_boot_grace() -> bool:
    return time.time() < _boot_grace_until


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _path(kind: str) -> str:
    if kind == "nodes":
        rel = _NODES_PATH
    elif kind == "topology":
        rel = _TOPOLOGY_PATH
    elif kind == "context":
        rel = _CONTEXT_PATH
    else:
        rel = _NDR_PATH
    return os.path.join(_root(), rel)


def is_network_boot_ready() -> bool:
    return _boot_ready.is_set()


def mark_network_boot_ready() -> None:
    _boot_ready.set()


def read_context_snapshot() -> Optional[Dict[str, Any]]:
    return _load("context")


def _build_network_context_body(*, scan_status: str = "pending", scan_error: Optional[str] = None) -> Dict[str, Any]:
    """Información básica de interfaz — sin ARP."""
    from services.network_scan_coordinator import get_network_context, context_fingerprint, get_coordinator_status
    from services.network_scanner import network_scanner
    from utils.host_data import get_local_ip, get_primary_network_interface, format_ip_or_unavailable
    from utils.network_helpers import get_hostname

    ctx = get_network_context()
    meta = network_scanner.get_network_meta()
    primary = get_primary_network_interface() or {}
    cache_info = network_scanner.get_cache_info()
    coord = get_coordinator_status(include_network_context=False)
    nodes = network_scanner.get_cached_nodes() or []
    local_ip = meta.get("local_ip") or primary.get("local_ip") or ctx.get("local_ip") or get_local_ip()
    subnet = meta.get("network_range") or ctx.get("subnet") or "Sin datos disponibles"
    gateway = meta.get("gateway") or primary.get("gateway") or ctx.get("gateway") or "Sin datos disponibles"
    try:
        from services.network_dns_service import client_dns_struct, get_live_dns_info

        dns = client_dns_struct(get_live_dns_info(preferred_interface=meta.get("adapter") or primary.get("adapter")))
    except Exception:
        dns = {"available": False, "display": "DNS no disponible", "servers": [], "data_freshness": "NOT_AVAILABLE"}

    return {
        "interface": meta.get("adapter") or primary.get("adapter") or ctx.get("interface") or "Sin datos disponibles",
        "ssid": ctx.get("ssid"),
        "bssid": ctx.get("bssid"),
        "local_ip": format_ip_or_unavailable(local_ip),
        "gateway": gateway,
        "subnet": subnet,
        "network_cidr": subnet,
        "adapter": meta.get("adapter") or primary.get("adapter") or ctx.get("interface"),
        "hostname": get_hostname() if get_hostname() != "Unknown" else "Sin datos disponibles",
        "dns": dns,
        "connection_type": meta.get("connection_type") or primary.get("connection_type"),
        "timestamp": _utc(),
        "discovered_nodes": nodes,
        "node_count": len(nodes),
        "scan_status": scan_status,
        "scan_started_at": coord.get("scan_started_at_utc"),
        "scan_completed_at": coord.get("scan_completed_at_utc"),
        "scan_error": scan_error or coord.get("scan_error"),
        "source": "network_snapshot_service.context",
        "source_type": "network_context",
        "context_fingerprint": context_fingerprint(ctx),
    }


def bootstrap_network_context() -> Dict[str, Any]:
    """PHASE 1 — contexto de red básico sin discovery."""
    body = _build_network_context_body(scan_status="pending")
    _save("context", body, source="network_snapshot_service.bootstrap_network_context")
    return body


def bootstrap_initial_snapshots() -> None:
    """PHASE 2 — snapshots pending desde contexto; discovery en background."""
    ctx_body = _build_network_context_body(scan_status="pending")
    _save("context", ctx_body, source="network_snapshot_service.bootstrap_initial_snapshots")

    pending_nodes = {
        "status": "pending",
        "nodes": [],
        "count": 0,
        "message": "Network discovery pending",
        "source": "network_snapshot_service",
        "source_type": "snapshot_pending",
        "network_context": ctx_body,
        "updating": False,
        "snapshot_pending": True,
    }
    _save("nodes", pending_nodes, source="network_snapshot_service.bootstrap_initial_snapshots")

    pending_ndr = {
        "status": "pending",
        "nodes": [],
        "device_count": 0,
        "message": "Network discovery pending",
        "source": "network_snapshot_service",
        "source_type": "snapshot_pending",
        "snapshot_pending": True,
    }
    _save("ndr", pending_ndr, source="network_snapshot_service.bootstrap_initial_snapshots")

    pending_topo = {
        "status": "pending",
        "nodes": [],
        "connections": [],
        "message": "Network discovery pending",
        "source": "network_snapshot_service",
        "source_type": "snapshot_pending",
        "snapshot_pending": True,
    }
    _save("topology", pending_topo, source="network_snapshot_service.bootstrap_initial_snapshots")


def update_context_scan_status(
    *,
    scan_status: str,
    scan_error: Optional[str] = None,
) -> None:
    body = _build_network_context_body(scan_status=scan_status, scan_error=scan_error)
    _save("context", body, source=f"network_snapshot_service.update_context_scan_status:{scan_status}")


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


def freshness_from_generated_at(generated_at: Optional[str]) -> str:
    """LIVE / CACHED / STALE según edad del snapshot — sin promover históricos a live."""
    if _is_stale(generated_at):
        return "stale"
    age = _age_sec(generated_at)
    if age is not None and age <= 60:
        return "live"
    if age is not None:
        return "cached"
    return "unknown"


def observed_device_count_for_freshness(freshness: str, node_count: int) -> int:
    """Solo LIVE cuenta como dispositivo observado actualmente."""
    return int(node_count) if freshness == "live" else 0


def resolve_network_device_counts() -> Dict[str, Any]:
    """Conteos canónicos con procedencia — stale nunca alimenta KPIs operativos."""
    snap = _load("nodes")
    generated_at = (snap or {}).get("generated_at_utc")
    freshness = freshness_from_generated_at(generated_at) if generated_at else "not_available"
    historical = 0
    if snap and snap.get("body"):
        historical = len(snap["body"].get("nodes") or [])
    observed = observed_device_count_for_freshness(freshness, historical)
    return {
        "observed_device_count": observed,
        "historical_device_count": historical,
        "data_freshness": freshness,
        "observed_at": generated_at,
        "source": "network_snapshot_service.nodes",
        "source_engine": "network_scan_coordinator",
        "snapshot_stale": _is_stale(generated_at),
    }


def _load(kind: str) -> Optional[Dict[str, Any]]:
    path = _path(kind)
    if not os.path.isfile(path):
        return None
    try:
        mtime = os.path.getmtime(path)
        with _lock:
            cached = _mem_cache.get(kind)
            if cached and cached[0] == mtime:
                return cached[1]
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        with _lock:
            _mem_cache[kind] = (mtime, data)
        return data
    except Exception as exc:
        logger.debug("network snapshot read %s: %s", kind, exc)
        return None


def _save(kind: str, body: Dict[str, Any], *, source: str) -> None:
    path = _path(kind)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {
        "body": body,
        "generated_at_utc": _utc(),
        "source": source,
        "source_type": "snapshot",
    }
    with _lock:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2, default=str)


def refresh_nodes_snapshot(*, consumer: str = "background") -> Dict[str, Any]:
    """Persistir snapshot de nodos desde caché ARP actual — sin lanzar scan."""
    from services.network_scanner import network_scanner
    from services.network_scan_coordinator import (
        context_fingerprint,
        get_bound_context,
        get_coordinator_status,
    )
    nodes = network_scanner.get_cached_nodes() or []
    cache_info = network_scanner.get_cache_info()
    net_ctx = get_bound_context() or {}
    coord = get_coordinator_status()
    try:
        from services.network_monitor_engine import get_monitor_status

        mon = get_monitor_status()
    except Exception:
        mon = None

    from utils.host_data import get_local_ip, get_primary_network_interface, format_ip_or_unavailable
    from utils.network_helpers import get_hostname

    primary = get_primary_network_interface() or {}
    meta = network_scanner.get_network_meta()
    local_ip = meta.get("local_ip") or primary.get("local_ip") or get_local_ip()
    hostname = get_hostname()
    info = {
        "status": "success",
        "local_ip": format_ip_or_unavailable(local_ip),
        "gateway": meta.get("gateway") or primary.get("gateway") or "Sin datos disponibles",
        "network_range": meta.get("network_range") or "Sin datos disponibles",
        "adapter": meta.get("adapter") or primary.get("adapter") or "Sin datos disponibles",
        "hostname": hostname if hostname != "Unknown" else "Sin datos disponibles",
        "node_count": cache_info.get("node_count", 0),
        "last_scan": cache_info.get("last_scan") or "Sin datos disponibles",
    }
    scanning = bool(network_scanner._scanning or coord.get("scan_in_progress"))

    if nodes:
        from utils.network_helpers import assess_discovery_limitations, read_os_arp_neighbors

        os_neighbors = read_os_arp_neighbors(interface_ip=local_ip if local_ip not in ("Sin datos disponibles", None) else None)
        wifi_ctx = net_ctx or {}
        assessment = assess_discovery_limitations(
            scapy_count=len([n for n in nodes if n.get("detection_method") == "arp_scapy"]),
            os_arp_count=len(os_neighbors),
            subnet_cidr=meta.get("network_range") or wifi_ctx.get("subnet"),
            ssid=wifi_ctx.get("ssid"),
            connection_type=meta.get("connection_type") or wifi_ctx.get("connection_type"),
        )
        node_count = len(nodes)
        last_scan = cache_info.get("last_scan")
        write_freshness = "live"
        if last_scan:
            try:
                from datetime import datetime, timezone
                if isinstance(last_scan, str):
                    ts = datetime.strptime(last_scan[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    age = (datetime.now(timezone.utc) - ts).total_seconds()
                    write_freshness = "live" if age <= 60 else ("cached" if age <= 90 else "stale")
            except Exception:
                write_freshness = "cached"
        observed_count = node_count if write_freshness == "live" else 0
        body = {
            "status": "success",
            "nodes": nodes,
            "count": observed_count,
            "historical_device_count": node_count,
            "observed_device_count": observed_count,
            "cache_info": cache_info,
            "source": "network_scanner.get_cached_nodes",
            "source_type": "arp_snapshot",
            "data_origin": "live_discovery",
            "detection_source": "arp_scapy",
            "data_freshness": write_freshness,
            "observed_at": coord.get("last_scan_at_utc"),
            "discovery_assessment": assessment,
            "network_context": net_ctx,
            "context_fingerprint": context_fingerprint(net_ctx) if net_ctx else coord.get("context_fingerprint"),
            "coordinator": {
                "scan_count": coord.get("scan_count"),
                "last_scan_duration_ms": coord.get("last_scan_duration_ms"),
                "context_invalidations": coord.get("context_invalidations"),
            },
            "network_info": info,
            "monitor": mon,
            "updating": scanning,
            "scan_status": "completed" if not scanning else "scanning",
        }
    else:
        body = {
            "status": "pending" if not scanning else "scanning",
            "nodes": [],
            "count": 0,
            "cache_info": cache_info,
            "message": "Network discovery pending" if not scanning else "Network discovery running in background",
            "source": "network_snapshot_service",
            "source_type": "arp_snapshot",
            "network_context": net_ctx,
            "context_fingerprint": context_fingerprint(net_ctx) if net_ctx else None,
            "coordinator": coord,
            "network_info": info,
            "monitor": mon,
            "updating": scanning,
            "last_scan": cache_info.get("last_scan"),
            "scan_status": "scanning" if scanning else "pending",
        }
    _save("nodes", body, source=f"network_snapshot_service.refresh_nodes:{consumer}")
    return body


def refresh_ndr_snapshot(*, consumer: str = "background") -> Dict[str, Any]:
    """Construye NDR desde cache existente — sin ARP sync en HTTP."""
    from services.network_ndr_service import build_ndr_payload_from_cache

    body = build_ndr_payload_from_cache()
    _save("ndr", body, source=f"network_snapshot_service.refresh_ndr:{consumer}")
    return body


def persist_after_discovery() -> None:
    """Llamado tras ARP completado en coordinator."""
    try:
        update_context_scan_status(scan_status="completed")
        refresh_nodes_snapshot(consumer="post_discovery")
        refresh_ndr_snapshot(consumer="post_discovery")
        try:
            from services.topology_service import _build_topology_payload_from_ndr
            from services.network_ndr_service import build_ndr_payload_from_cache

            topo = _build_topology_payload_from_ndr(build_ndr_payload_from_cache())
            _save("topology", topo, source="network_snapshot_service.refresh_topology:post_discovery")
        except Exception as exc:
            logger.debug("topology snapshot persist: %s", exc)
    except Exception as exc:
        logger.warning("persist network snapshots: %s", exc)


def read_nodes_api(*, trigger_discovery: bool = True, include_context: bool = False) -> Dict[str, Any]:
    snap = _load("nodes")
    generated_at = (snap or {}).get("generated_at_utc")
    stale = _is_stale(generated_at)

    if trigger_discovery and not _in_boot_grace() and (snap is None or stale or not (snap.get("body") or {}).get("nodes")):
        from services.network_scan_coordinator import schedule_network_discovery

        schedule_network_discovery(consumer="api_nodes", force=False)

    ctx_body = None
    if include_context:
        ctx = read_context_snapshot()
        ctx_body = (ctx or {}).get("body") if ctx else None

    if snap and snap.get("body") is not None:
        body = dict(snap["body"])
        age = _age_sec(generated_at)
        freshness = freshness_from_generated_at(generated_at)
        historical_count = len(body.get("nodes") or [])
        observed = observed_device_count_for_freshness(freshness, historical_count)
        body["historical_device_count"] = historical_count
        body["observed_device_count"] = observed
        body["count"] = observed
        body["snapshot_meta"] = {
            "generated_at_utc": generated_at,
            "age_sec": age,
            "snapshot_stale": stale,
            "source_type": "snapshot",
            "data_freshness": freshness,
        }
        body["data_freshness"] = freshness
        body["snapshot_age_sec"] = age
        for node in body.get("nodes") or []:
            if isinstance(node, dict):
                node.setdefault("data_origin", "live_discovery")
                node.setdefault("detection_source", node.get("detection_method") or "arp_scapy")
                node["data_freshness"] = freshness
        body.setdefault("scan_status", body.get("scan_status") or ("completed" if body.get("nodes") else "pending"))
        coord_ts = body.get("observed_at") or generated_at
        body["scan_completed_at"] = coord_ts if body.get("nodes") else None
        if include_context and ctx_body:
            body["network_context"] = ctx_body
        return body

    from services.network_scan_coordinator import get_coordinator_status

    coord = get_coordinator_status(include_network_context=False)
    scanning = bool(coord.get("scan_in_progress"))
    return {
        "status": "pending",
        "nodes": [],
        "count": 0,
        "observed_device_count": 0,
        "message": "Network discovery pending",
        "source": "network_snapshot_service",
        "source_type": "snapshot_pending",
        "updating": scanning,
        "scan_status": "scanning" if scanning else "pending",
        "scan_completed_at": coord.get("scan_completed_at_utc"),
        "snapshot_age_sec": None,
        "last_scan": None,
        "snapshot_pending": True,
        "coordinator": {"scan_in_progress": scanning, "last_consumer": coord.get("last_consumer")},
        "network_context": ctx_body if include_context else None,
    }


def read_ndr_api(*, trigger_discovery: bool = True) -> Dict[str, Any]:
    snap = _load("ndr")
    generated_at = (snap or {}).get("generated_at_utc")
    stale = _is_stale(generated_at)

    if trigger_discovery and not _in_boot_grace() and (snap is None or stale):
        from services.network_scan_coordinator import schedule_network_discovery

        schedule_network_discovery(consumer="api_ndr", force=False)

    if snap and snap.get("body") is not None:
        body = dict(snap["body"])
        age = _age_sec(generated_at)
        freshness = freshness_from_generated_at(generated_at)
        historical_count = len(body.get("nodes") or [])
        observed = observed_device_count_for_freshness(freshness, historical_count)
        body["data_freshness"] = freshness
        body["observed_device_count"] = observed
        body["historical_device_count"] = historical_count
        body["device_count"] = observed
        body["historical_device_count"] = historical_count
        exec_sum = body.get("executive_summary") or {}
        if exec_sum:
            exec_sum = dict(exec_sum)
            exec_sum["observed_device_count"] = observed
            exec_sum["historical_device_count"] = historical_count
            exec_sum["device_count"] = observed
            body["executive_summary"] = exec_sum
        body["snapshot_meta"] = {
            "generated_at_utc": generated_at,
            "age_sec": age,
            "snapshot_stale": stale,
            "source_type": "snapshot",
            "data_freshness": freshness,
        }
        return body

    from services.network_scan_coordinator import get_coordinator_status

    coord = get_coordinator_status(include_network_context=False)
    scanning = bool(coord.get("scan_in_progress"))
    return {
        "status": "pending",
        "nodes": [],
        "device_count": 0,
        "observed_device_count": 0,
        "message": "Network discovery pending",
        "source": "network_snapshot_service",
        "source_type": "snapshot_pending",
        "snapshot_pending": True,
        "scan_status": "scanning" if scanning else "pending",
        "coordinator": coord,
    }


def read_topology_api(*, trigger_discovery: bool = True) -> Dict[str, Any]:
    snap = _load("topology")
    generated_at = (snap or {}).get("generated_at_utc")
    stale = _is_stale(generated_at)

    if trigger_discovery and not _in_boot_grace() and (snap is None or stale):
        from services.network_scan_coordinator import schedule_network_discovery

        schedule_network_discovery(consumer="api_topology", force=False)

    if snap and snap.get("body") is not None:
        from services.topology_service import sanitize_topology_connections

        body = dict(snap["body"])
        body["connections"] = sanitize_topology_connections(body.get("connections") or [])
        freshness = freshness_from_generated_at(generated_at) if generated_at else "unknown"
        body["snapshot_meta"] = {
            "generated_at_utc": generated_at,
            "age_sec": _age_sec(generated_at),
            "snapshot_stale": stale,
            "source_type": "snapshot",
            "data_freshness": freshness,
        }
        body["data_freshness"] = freshness
        return body

    from services.topology_service import _build_topology_payload_from_ndr
    from services.network_ndr_service import build_ndr_payload_from_cache

    try:
        return _build_topology_payload_from_ndr(build_ndr_payload_from_cache())
    except Exception as exc:
        logger.debug("topology fallback: %s", exc)
        return {
            "status": "pending",
            "nodes": [],
            "connections": [],
            "message": "Network discovery pending",
            "source": "network_snapshot_service",
            "source_type": "snapshot_pending",
            "snapshot_pending": True,
            "scan_status": "pending",
        }


def schedule_network_warmup() -> None:
    """Legacy alias — el arranque real se controla desde main.py."""

    def _warm() -> None:
        time.sleep(2)
        try:
            from services.network_scan_coordinator import schedule_network_discovery

            schedule_network_discovery(consumer="boot_warmup", force=False)
        except Exception as exc:
            logger.debug("network warmup: %s", exc)

    threading.Thread(target=_warm, daemon=True, name="NetworkSnapWarmup").start()
