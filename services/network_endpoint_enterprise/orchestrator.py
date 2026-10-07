"""
Orquestador Enterprise — ciclos incrementales de bajo costo.
Alimenta Swarm / APE / Forense / Kernel vía publish → defense_coordinator.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from utils.logger import logger

INTERVAL_SEC = 45
HEAVY_EVERY_N = 8  # drivers/tasks/modules cada N ciclos

_lock = threading.Lock()
_state: Dict[str, Any] = {
    "active": False,
    "started_at": None,
    "last_cycle_at": None,
    "cycles": 0,
    "last_error": None,
    "last_anomalies_n": 0,
    "last_published_n": 0,
    "last_anomaly_types": [],
    "last_duration_ms": None,
}
_thread: Optional[threading.Thread] = None
_stop: Optional[threading.Event] = None


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _device_presence_changes() -> List[Dict[str, Any]]:
    """T2 — nuevos dispositivos / cambios IP desde monitor de conexión (historial no se borra)."""
    changes: List[Dict[str, Any]] = []
    try:
        from database import SessionLocal, DeviceConnectionEvent

        db = SessionLocal()
        try:
            rows = (
                db.query(DeviceConnectionEvent)
                .order_by(DeviceConnectionEvent.id.desc())
                .limit(20)
                .all()
            )
            for r in rows:
                et = (getattr(r, "event_type", None) or "").lower()
                if et in ("connect", "connected", "ip_change", "hostname_change"):
                    changes.append(
                        {
                            "change_type": "new_device" if et in ("connect", "connected") else f"device_{et}",
                            "ip": getattr(r, "ip_address", None),
                            "mac": getattr(r, "mac_address", None),
                            "hostname": getattr(r, "hostname", None),
                            "vendor": getattr(r, "vendor", None),
                            "event_type": et,
                            "timestamp": getattr(r, "timestamp", None),
                        }
                    )
        finally:
            db.close()
    except Exception as exc:
        logger.debug("device presence: %s", exc)
    return changes[:10]


def run_enterprise_cycle(*, force_heavy: bool = False) -> Dict[str, Any]:
    """Un ciclo completo: inventario, DNS/DHCP, endpoint, anomalías, publicación."""
    t0 = time.time()
    summary: Dict[str, Any] = {"ok": False, "published": 0, "anomalies": 0}

    from services.network_endpoint_enterprise.local_inventory import snapshot_and_diff
    from services.network_endpoint_enterprise.dns_dhcp_sensors import (
        snapshot_dns_cache,
        analyze_dhcp_servers,
    )
    from services.network_endpoint_enterprise.endpoint_extended import snapshot_endpoint_and_diff
    from services.network_endpoint_enterprise.anomaly import detect_anomalies_from_cycle
    from services.network_endpoint_enterprise.publish import publish_changes, publish_alert

    with _lock:
        cycle_n = int(_state.get("cycles") or 0) + 1
        heavy = force_heavy or (cycle_n % HEAVY_EVERY_N == 0)

    try:
        inv, inv_changes = snapshot_and_diff()
        dns_snap, dns_changes = snapshot_dns_cache()
        dhcp_servers = (inv.get("dhcp") or {}).get("dhcp_servers") or []
        dhcp_result = analyze_dhcp_servers(dhcp_servers, gateway=inv.get("gateway"))
        ep_snap, ep_changes = snapshot_endpoint_and_diff(heavy=heavy)

        ndr_alerts = []
        try:
            from services.network_scanner import network_scanner
            from services.network_ndr_service import analyze_behavior

            nodes = network_scanner.get_cached_nodes() or []
            meta = network_scanner.get_network_meta() or {}
            if nodes:
                ndr_alerts = analyze_behavior(nodes, meta) or []
        except Exception as exc:
            logger.debug("nee ndr: %s", exc)

        device_changes = _device_presence_changes()
        anomalies = detect_anomalies_from_cycle(
            inventory_changes=inv_changes,
            dns_changes=dns_changes,
            dhcp_result=dhcp_result,
            endpoint_changes=ep_changes,
            new_devices=[d for d in device_changes if d.get("change_type") == "new_device"],
            ndr_alerts=ndr_alerts,
        )

        published = 0
        published += len(
            publish_changes(inv_changes, motor="network_endpoint_enterprise", category="inventory")
        )
        published += len(
            publish_changes(dns_changes, motor="network_endpoint_enterprise", category="dns")
        )
        published += len(
            publish_changes(ep_changes, motor="network_endpoint_enterprise", category="endpoint")
        )
        for alert in dhcp_result.get("alerts") or []:
            publish_alert(alert, motor="network_endpoint_enterprise")
            published += 1
        for an in anomalies:
            if an.get("category") == "ndr":
                continue  # NDR ya publica vía analyze_behavior → coordinator
            if an.get("anomaly_type") in (
                "gateway_change",
                "dhcp_change",
                "ip_change",
                "mac_change",
                "possible_dll_injection",
                "rogue_dhcp",
                "dns_resolution_burst",
                "new_device",
            ):
                # Ya publicados vía publish_changes/alert en la mayoría; evitar duplicar
                # excepto burst DNS y new_device si no estaban
                if an.get("anomaly_type") in ("dns_resolution_burst", "new_device"):
                    publish_alert(
                        {
                            "alert_id": f"NEE-{an['anomaly_type']}-{int(time.time())}",
                            "type": an["anomaly_type"],
                            "severity": an.get("severity"),
                            "evidence": an.get("evidence"),
                            "verified": True,
                        },
                        motor="network_endpoint_enterprise",
                    )
                    published += 1

        # APE host observation (señales no amenazantes)
        try:
            from services.adaptive_profile_engine import observe_async
            from services.network_endpoint_enterprise.publish import host_profile_email

            observe_async(
                host_profile_email(),
                event_type="nee_tick",
                ip=inv.get("local_ip"),
                evidence={
                    "learnable": True,
                    "gateway": inv.get("gateway"),
                    "dns": inv.get("dns_servers"),
                    "dhcp": dhcp_servers,
                    "process_count": ep_snap.get("process_count"),
                    "listening_ports": (ep_snap.get("listening_ports") or [])[:20],
                    "devices_hint_n": len(device_changes),
                },
                risk_level="info",
            )
        except Exception as exc:
            logger.debug("nee ape feed: %s", exc)

        summary.update(
            {
                "ok": True,
                "heavy": heavy,
                "inventory_fingerprint": inv.get("fingerprint"),
                "inv_changes": len(inv_changes),
                "dns_entries": dns_snap.get("count") or len(dns_snap.get("entries") or []),
                "dns_changes": len(dns_changes),
                "ep_changes": len(ep_changes),
                "dhcp_alerts": len(dhcp_result.get("alerts") or []),
                "anomalies": len(anomalies),
                "published": published,
                "anomaly_types": [a.get("anomaly_type") for a in anomalies[:12]],
            }
        )
    except Exception as exc:
        summary["error"] = str(exc)[:300]
        logger.warning("enterprise cycle: %s", exc)

    duration_ms = round((time.time() - t0) * 1000, 1)
    with _lock:
        _state["cycles"] = cycle_n
        _state["last_cycle_at"] = _utc()
        _state["last_duration_ms"] = duration_ms
        _state["last_anomalies_n"] = summary.get("anomalies") or 0
        _state["last_published_n"] = summary.get("published") or 0
        _state["last_anomaly_types"] = summary.get("anomaly_types") or []
        _state["last_error"] = summary.get("error")
    summary["duration_ms"] = duration_ms
    summary["cycle"] = cycle_n
    return summary


def _loop(stop: threading.Event) -> None:
    with _lock:
        _state["active"] = True
        _state["started_at"] = _utc()
    # Primer ciclo con heavy para baseline drivers/tasks
    run_enterprise_cycle(force_heavy=True)
    while not stop.is_set():
        stop.wait(INTERVAL_SEC)
        if stop.is_set():
            break
        run_enterprise_cycle()
    with _lock:
        _state["active"] = False


def start_enterprise_sensor() -> Dict[str, Any]:
    global _thread, _stop
    if _thread and _thread.is_alive():
        return {"status": "already_running", **get_enterprise_status()}
    _stop = threading.Event()
    _thread = threading.Thread(target=_loop, args=(_stop,), daemon=True, name="NetEndpointEnterprise")
    _thread.start()
    logger.info("Network+Endpoint Enterprise sensor iniciado (interval=%ss)", INTERVAL_SEC)
    return {"status": "started", "interval_sec": INTERVAL_SEC}


def stop_enterprise_sensor() -> Dict[str, Any]:
    global _thread, _stop
    if _stop:
        _stop.set()
    if _thread:
        _thread.join(timeout=5)
    with _lock:
        _state["active"] = False
    return {"status": "stopped"}


def get_enterprise_status() -> Dict[str, Any]:
    with _lock:
        return {
            "ok": True,
            "active": _state.get("active"),
            "started_at": _state.get("started_at"),
            "last_cycle_at": _state.get("last_cycle_at"),
            "cycles": _state.get("cycles"),
            "last_duration_ms": _state.get("last_duration_ms"),
            "last_anomalies_n": _state.get("last_anomalies_n"),
            "last_published_n": _state.get("last_published_n"),
            "last_anomaly_types": list(_state.get("last_anomaly_types") or []),
            "last_error": _state.get("last_error"),
            "interval_sec": INTERVAL_SEC,
            "version": "1.0.0-enterprise-fase1",
        }
