"""
Monitoreo de conexiones/desconexiones de dispositivos — eventos reales desde escaneo ARP/AIE.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from utils.logger import logger

_connect_sessions: Dict[str, str] = {}
_prev_scan_macs: Set[str] = set()


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _platform_tenant_id() -> str:
    from services.tenant_scope_service import get_platform_tenant_id
    return get_platform_tenant_id()


def _tenant_filter(query, tenant_id: Optional[str]):
    from database import DeviceConnectionEvent
    from services.tenant_scope_service import get_platform_tenant_id

    if not tenant_id or tenant_id != get_platform_tenant_id():
        return query.filter(DeviceConnectionEvent.id == -1)
    return query.filter(DeviceConnectionEvent.tenant_id == tenant_id)


def _parse_ts(value: str) -> Optional[datetime]:
    try:
        return datetime.strptime(value[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _node_meta(node: dict, inv=None) -> dict:
    return {
        "ip": node.get("ip"),
        "mac": (node.get("mac") or "").lower(),
        "hostname": node.get("name") or node.get("hostname") or (getattr(inv, "hostname", None) if inv else None),
        "vendor": node.get("vendor") or (getattr(inv, "vendor", None) if inv else None),
        "device_type": node.get("device_type") or (getattr(inv, "device_type", None) if inv else None),
        "asset_status": getattr(inv, "asset_status", None) if inv else node.get("asset_status"),
        "trust_score": getattr(inv, "trust_score", None) if inv else node.get("trust_score"),
        "risk_level": getattr(inv, "risk_level", None) if inv else node.get("risk_level"),
    }


def _persist_event(event_type: str, meta: dict, duration_seconds: Optional[int] = None, extra: Optional[dict] = None) -> None:
    from database import SessionLocal, DeviceConnectionEvent

    evidence = dict(extra or {})
    evidence["source"] = "arp_scan_aie"
    db = SessionLocal()
    try:
        db.add(DeviceConnectionEvent(
            event_type=event_type,
            timestamp=_now(),
            ip_address=meta.get("ip"),
            mac_address=meta.get("mac"),
            hostname=meta.get("hostname"),
            vendor=meta.get("vendor"),
            device_type=meta.get("device_type"),
            asset_status=meta.get("asset_status"),
            trust_score=meta.get("trust_score"),
            risk_level=meta.get("risk_level"),
            duration_seconds=duration_seconds,
            evidence_json=json.dumps(evidence, ensure_ascii=False),
            tenant_id=_platform_tenant_id(),
        ))
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.debug("device_connection_event: %s", exc)
    finally:
        db.close()

    try:
        from services.network_event_log import network_event_log
        label = {
            "connect": "conectado",
            "disconnect": "desconectado",
            "ip_change": "cambio de IP",
            "hostname_change": "cambio de hostname",
            "port_change": "nuevos puertos",
            "traffic_change": "variación de tráfico",
            "behavior_change": "cambio de comportamiento",
            "infrastructure_change": "cambio de infraestructura",
        }.get(event_type, event_type)
        network_event_log.record(
            f"[AIE] Dispositivo {meta.get('ip') or meta.get('mac')} {label}",
            level="alert" if event_type in ("ip_change", "behavior_change", "port_change", "traffic_change") else "info",
        )
    except Exception:
        pass

    try:
        from services.network_security_history_service import (
            append_network_security_event,
            map_device_connection_event,
        )

        mapped = map_device_connection_event(event_type)
        if mapped:
            append_network_security_event(
                mapped,
                title=f"Dispositivo {event_type}: {meta.get('ip') or meta.get('mac')}",
                evidence={"device": meta, "extra": extra or {}, "verified": True},
                motor="device_connection_monitor",
                severity="info" if event_type == "connect" else "medium",
            )
    except Exception as exc:
        logger.debug("network history device event: %s", exc)

    try:
        from services.evidence_center_service import record_evidence, infer_category
        anomaly_types = {
            "ip_change", "hostname_change", "port_change",
            "traffic_change", "behavior_change", "infrastructure_change",
        }
        if event_type in anomaly_types:
            cat = "comportamiento_anomalo"
        elif event_type == "connect":
            cat = "dispositivo_autorizado"
        elif event_type == "disconnect":
            cat = "comportamiento_anomalo"
        else:
            cat = infer_category("device_connection_monitor", event_type)
        record_evidence(
            motor="device_connection_monitor",
            description=f"Dispositivo {meta.get('ip') or meta.get('mac')} — {event_type}",
            categoria=cat,
            nivel_riesgo=meta.get("risk_level") or "medio",
            nivel_confianza="Alta",
            estado="registrado",
            accion_ejecutada=event_type,
            resultado="detected",
            evidence={"meta": meta, "duration_seconds": duration_seconds, **(extra or {})},
        )
    except Exception as ev_exc:
        logger.debug("device_connection evidence: %s", ev_exc)


def record_monitor_event(
    event_type: str,
    meta: dict,
    *,
    duration_seconds: Optional[int] = None,
    extra: Optional[dict] = None,
) -> None:
    """Registro genérico de eventos del Network Monitor Engine."""
    payload = dict(extra or {})
    payload["source"] = "network_monitor_engine"
    _persist_event(event_type, meta, duration_seconds=duration_seconds, extra=payload)


def process_scan_presence(
    current_nodes: List[dict],
    previous_macs: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Detecta conexiones/desconexiones comparando escaneos ARP consecutivos."""
    global _connect_sessions, _prev_scan_macs

    if previous_macs is None:
        previous_macs = set(_prev_scan_macs)

    current_macs = {(n.get("mac") or "").lower() for n in current_nodes if n.get("mac")}
    nodes_by_mac = {(n.get("mac") or "").lower(): n for n in current_nodes if n.get("mac")}

    if not previous_macs and current_macs:
        _prev_scan_macs = current_macs
        return {"connected": 0, "disconnected": 0, "ip_changes": 0, "hostname_changes": 0, "baseline": True}

    from database import SessionLocal, NetworkDeviceInventory

    db = SessionLocal()
    inventory = {}
    try:
        for row in db.query(NetworkDeviceInventory).all():
            inventory[(row.mac or "").lower()] = row
    finally:
        db.close()

    connected = current_macs - previous_macs
    disconnected = previous_macs - current_macs
    stats = {"connected": 0, "disconnected": 0, "ip_changes": 0, "hostname_changes": 0}

    for mac in connected:
        node = nodes_by_mac.get(mac, {})
        inv = inventory.get(mac)
        meta = _node_meta(node, inv)
        _connect_sessions[mac] = _now()
        _persist_event("connect", meta)
        stats["connected"] += 1

    for mac in disconnected:
        inv = inventory.get(mac)
        meta = _node_meta({"mac": mac, "ip": getattr(inv, "ip", None) if inv else None}, inv)
        duration = None
        start = _connect_sessions.pop(mac, None)
        if start:
            dt_start = _parse_ts(start)
            if dt_start:
                duration = int((datetime.now() - dt_start).total_seconds())
        _persist_event("disconnect", meta, duration_seconds=duration)
        stats["disconnected"] += 1

    for mac in current_macs & previous_macs:
        node = nodes_by_mac.get(mac, {})
        inv = inventory.get(mac)
        if not inv:
            continue
        if inv.ip and node.get("ip") and inv.ip != node.get("ip"):
            meta = _node_meta(node, inv)
            _persist_event("ip_change", meta, extra={"previous_ip": inv.ip, "new_ip": node.get("ip")})
            stats["ip_changes"] += 1
        prev_host = inv.hostname
        new_host = node.get("name") or node.get("hostname")
        if prev_host and new_host and prev_host != new_host:
            meta = _node_meta(node, inv)
            _persist_event("hostname_change", meta, extra={"previous_hostname": prev_host, "new_hostname": new_host})
            stats["hostname_changes"] += 1

    _prev_scan_macs = current_macs
    return stats


def list_events(
    limit: int = 100,
    mac: Optional[str] = None,
    ip: Optional[str] = None,
    event_type: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    from database import SessionLocal, DeviceConnectionEvent

    db = SessionLocal()
    try:
        q = db.query(DeviceConnectionEvent).order_by(DeviceConnectionEvent.id.desc())
        q = _tenant_filter(q, tenant_id)
        if mac:
            q = q.filter(DeviceConnectionEvent.mac_address == mac.lower())
        if ip:
            q = q.filter(DeviceConnectionEvent.ip_address == ip)
        if event_type:
            q = q.filter(DeviceConnectionEvent.event_type == event_type)
        rows = q.limit(limit).all()
        out = []
        for r in rows:
            ev = {}
            try:
                ev = json.loads(r.evidence_json or "{}")
            except Exception:
                pass
            out.append({
                "id": r.id,
                "event_type": r.event_type,
                "timestamp": r.timestamp,
                "ip": r.ip_address,
                "mac": r.mac_address,
                "hostname": r.hostname,
                "vendor": r.vendor,
                "device_type": r.device_type,
                "asset_status": r.asset_status,
                "trust_score": r.trust_score,
                "risk_level": r.risk_level,
                "duration_seconds": r.duration_seconds,
                "evidence": ev,
            })
        return out
    finally:
        db.close()


def get_device_history(mac: Optional[str] = None, ip: Optional[str] = None) -> Dict[str, Any]:
    from database import SessionLocal, NetworkDeviceInventory, DeviceConnectionEvent

    db = SessionLocal()
    try:
        inv = None
        if mac:
            inv = db.query(NetworkDeviceInventory).filter(NetworkDeviceInventory.mac == mac.lower()).first()
        elif ip:
            inv = db.query(NetworkDeviceInventory).filter(NetworkDeviceInventory.ip == ip).first()

        filter_mac = (inv.mac if inv else mac or "").lower() if (inv or mac) else None
        filter_ip = inv.ip if inv else ip

        q = db.query(DeviceConnectionEvent)
        if filter_mac:
            q = q.filter(DeviceConnectionEvent.mac_address == filter_mac)
        elif filter_ip:
            q = q.filter(DeviceConnectionEvent.ip_address == filter_ip)
        events = q.order_by(DeviceConnectionEvent.timestamp.desc()).limit(500).all()

        connects = sum(1 for e in events if e.event_type == "connect")
        disconnects = sum(1 for e in events if e.event_type == "disconnect")
        total_seconds = sum(e.duration_seconds or 0 for e in events if e.event_type == "disconnect")

        timeline = []
        for e in reversed(events[-100:]):
            timeline.append({
                "timestamp": e.timestamp,
                "event_type": e.event_type,
                "ip": e.ip_address,
                "duration_seconds": e.duration_seconds,
                "trust_score": e.trust_score,
                "risk_level": e.risk_level,
            })

        return {
            "device": {
                "mac": inv.mac if inv else filter_mac,
                "ip": inv.ip if inv else filter_ip,
                "hostname": inv.hostname if inv else None,
                "vendor": inv.vendor if inv else None,
                "device_type": inv.device_type if inv else None,
                "first_seen": inv.first_seen if inv else None,
                "last_seen": inv.last_seen if inv else None,
                "asset_status": inv.asset_status if inv else None,
                "trust_score": inv.trust_score if inv else None,
                "risk_level": inv.risk_level if inv else None,
            },
            "connect_count": connects,
            "disconnect_count": disconnects,
            "total_connected_seconds": total_seconds,
            "timeline": timeline,
        }
    finally:
        db.close()


def search_devices(
    query: Optional[str] = None,
    limit: int = 100,
    tenant_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    from database import SessionLocal, NetworkDeviceInventory
    from services.tenant_scope_service import get_platform_tenant_id

    if not tenant_id or tenant_id != get_platform_tenant_id():
        return []

    db = SessionLocal()
    try:
        rows = (
            db.query(NetworkDeviceInventory)
            .filter(NetworkDeviceInventory.tenant_id == tenant_id)
            .order_by(NetworkDeviceInventory.last_seen.desc())
            .limit(limit * 3)
            .all()
        )
        q = (query or "").lower().strip()
        results = []
        for r in rows:
            hay = " ".join(
                str(x or "") for x in (r.ip, r.mac, r.hostname, r.vendor, r.device_type)
            ).lower()
            if q and q not in hay:
                continue
            hist = get_device_history(mac=r.mac)
            results.append({
                **hist["device"],
                "connect_count": hist["connect_count"],
                "disconnect_count": hist["disconnect_count"],
                "total_connected_seconds": hist["total_connected_seconds"],
            })
            if len(results) >= limit:
                break
        return results
    finally:
        db.close()


def get_recent_connection_summary(limit: int = 20) -> List[Dict[str, Any]]:
    return list_events(limit=limit)
