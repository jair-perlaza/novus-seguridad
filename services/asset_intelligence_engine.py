"""
Asset Intelligence Engine (AIE) — identificación, inventario, clasificación y aprendizaje
de dispositivos de red basado en evidencia real (ARP, puertos, inventario, telemetría).

No clasifica como "desconocido" sin evidencia. Estado inicial: Pendiente de aprobación.
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import logger

# Estados canónicos AIE (sin "desconocido" genérico)
STATUS_PENDIENTE = "pendiente_aprobacion"
STATUS_AUTORIZADO = "autorizado"
STATUS_NUEVO = "nuevo_dispositivo"
STATUS_NO_AUTORIZADO = "no_autorizado"
STATUS_SOSPECHOSO = "sospechoso"
STATUS_COMPROMETIDO = "comprometido"
STATUS_AISLADO = "aislado"

STATUS_LABELS = {
    STATUS_PENDIENTE: "Pendiente de aprobación",
    STATUS_AUTORIZADO: "Autorizado",
    STATUS_NUEVO: "Nuevo dispositivo",
    STATUS_NO_AUTORIZADO: "No autorizado",
    STATUS_SOSPECHOSO: "Sospechoso",
    STATUS_COMPROMETIDO: "Comprometido",
    STATUS_AISLADO: "Aislado",
}

ADMIN_ACTIONS = frozenset({
    "approve", "reject", "ignore", "corporate", "temporary", "block", "isolate",
})


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _parse_json(text: Optional[str], default=None):
    if default is None:
        default = {}
    if not text:
        return default
    try:
        return json.loads(text)
    except Exception:
        return default


def _network_segment(ip: Optional[str], meta: Optional[dict] = None) -> Optional[str]:
    if not ip:
        return None
    net_range = (meta or {}).get("network_range")
    if net_range:
        return str(net_range)
    parts = str(ip).split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return None


def _os_from_node(node: dict) -> Optional[str]:
    try:
        from services.network_ndr_service import estimate_os
        info = estimate_os(node)
        display = info.get("display") if isinstance(info, dict) else str(info)
        if display and display not in ("No identificable", "Sin datos disponibles"):
            return display
    except Exception:
        pass
    return None


def _active_alerts_for_ip(ip: str) -> List[dict]:
    """Alertas activas en SQLite para IP — evita recursión vía get_canonical_alerts/NDR."""
    try:
        from database import SessionLocal, Alerta
        db = SessionLocal()
        try:
            rows = (
                db.query(Alerta)
                .filter(Alerta.ip_afectada == ip)
                .order_by(Alerta.id.desc())
                .limit(20)
                .all()
            )
            out = []
            for row in rows:
                estado = (getattr(row, "estado", None) or "activo").lower()
                if estado in ("resuelto", "resolved", "cerrado", "closed"):
                    continue
                out.append({"id": row.id, "origin_ip": ip, "nivel": getattr(row, "nivel", None)})
            return out
        finally:
            db.close()
    except Exception:
        return []


def _auth_failures_for_ip(ip: str) -> int:
    try:
        from database import SessionLocal, Log
        db = SessionLocal()
        try:
            count = 0
            for row in db.query(Log).filter(Log.evento == "LOGIN_FAILED").limit(200).all():
                if ip in (row.detalle or ""):
                    count += 1
            return count
        finally:
            db.close()
    except Exception:
        return 0


def compute_trust_score(record, node: dict, meta: Optional[dict] = None) -> Tuple[int, List[str]]:
    """
    Trust Score 0–100 basado únicamente en señales disponibles.
    Retorna (score, factores).
    """
    factors: List[str] = []
    score = 40  # base por estar en inventario ARP

    status = getattr(record, "asset_status", None) or STATUS_PENDIENTE
    if status == STATUS_AUTORIZADO:
        score += 35
        factors.append("Aprobado por administrador (+35)")
    elif status == STATUS_PENDIENTE:
        score += 5
        factors.append("Pendiente de aprobación (+5)")
    elif status == STATUS_NUEVO:
        score += 0
        factors.append("Dispositivo nuevo en inventario")
    elif status == STATUS_NO_AUTORIZADO:
        score = min(score, 15)
        factors.append("Marcado como no autorizado")
    elif status == STATUS_SOSPECHOSO:
        score = min(score, 30)
        factors.append("Clasificado como sospechoso por evidencia")
    elif status == STATUS_COMPROMETIDO:
        score = min(score, 10)
        factors.append("Evidencia de compromiso activa")
    elif status == STATUS_AISLADO:
        score = 0
        factors.append("Dispositivo aislado")

    times_seen = getattr(record, "times_seen", None) or 0
    if times_seen >= 10:
        score += 15
        factors.append(f"Historial estable ({times_seen} escaneos, +15)")
    elif times_seen >= 3:
        score += 8
        factors.append(f"Presencia recurrente ({times_seen} escaneos, +8)")

    learning = _parse_json(getattr(record, "learning_json", None), {})
    freq = learning.get("connection_frequency_score")
    if isinstance(freq, (int, float)) and freq > 0:
        bonus = min(10, int(freq * 10))
        score += bonus
        factors.append(f"Frecuencia de conexión habitual (+{bonus})")

    behavior_changes = len(learning.get("behavior_changes") or [])
    if behavior_changes:
        penalty = min(20, behavior_changes * 5)
        score -= penalty
        factors.append(f"Cambios de comportamiento detectados (-{penalty})")

    open_ports = node.get("open_ports") or []
    if len(open_ports) >= 5:
        score -= 12
        factors.append("Superficie de puertos elevada (-12)")
    elif len(open_ports) >= 3:
        score -= 5
        factors.append("Varios puertos expuestos (-5)")

    ip = node.get("ip")
    if ip:
        auth_fails = _auth_failures_for_ip(ip)
        if auth_fails >= 3:
            penalty = min(25, auth_fails * 3)
            score -= penalty
            factors.append(f"Intentos de autenticación fallidos desde IP (-{penalty})")

        alerts = _active_alerts_for_ip(ip)
        if alerts:
            penalty = min(30, len(alerts) * 10)
            score -= penalty
            factors.append(f"Alertas activas asociadas (-{penalty})")

    admin_tag = getattr(record, "admin_tag", None)
    if admin_tag == "corporativo":
        score += 10
        factors.append("Equipo corporativo (+10)")
    elif admin_tag == "temporal":
        score -= 5
        factors.append("Dispositivo temporal (-5)")

    score = max(0, min(100, int(score)))
    return score, factors


def _detect_behavior_changes(record, node: dict, learning: dict) -> List[dict]:
    changes: List[dict] = []
    hist = _parse_json(getattr(record, "history_json", None), [])
    if len(hist) >= 2:
        prev, curr = hist[-2], hist[-1]
        if prev.get("ip") != curr.get("ip"):
            changes.append({
                "type": "ip_change",
                "from": prev.get("ip"),
                "to": curr.get("ip"),
                "at": _now(),
            })
        if prev.get("hostname") != curr.get("hostname") and curr.get("hostname"):
            changes.append({
                "type": "hostname_change",
                "from": prev.get("hostname"),
                "to": curr.get("hostname"),
                "at": _now(),
            })
    mac_hist = learning.get("mac_history") or []
    mac = (node.get("mac") or "").lower()
    if mac and mac_hist and mac_hist[-1] != mac:
        changes.append({"type": "mac_change", "from": mac_hist[-1], "to": mac, "at": _now()})
    return changes


def update_learning(record, node: dict) -> dict:
    """Registra patrones de conexión y cambios para reducir falsos positivos."""
    learning = _parse_json(getattr(record, "learning_json", None), {
        "connection_hours": {},
        "behavior_changes": [],
        "mac_history": [],
        "scan_count": 0,
    })
    hour = datetime.now().strftime("%H")
    hours = learning.setdefault("connection_hours", {})
    hours[hour] = hours.get(hour, 0) + 1

    mac = (node.get("mac") or "").lower()
    mac_hist = learning.setdefault("mac_history", [])
    if mac and (not mac_hist or mac_hist[-1] != mac):
        mac_hist.append(mac)
        mac_hist = mac_hist[-20:]

    learning["scan_count"] = (learning.get("scan_count") or 0) + 1
    total_hours = sum(hours.values()) or 1
    peak = max(hours.values()) if hours else 0
    learning["connection_frequency_score"] = round(peak / total_hours, 2)

    new_changes = _detect_behavior_changes(record, node, learning)
    if new_changes:
        existing = learning.get("behavior_changes") or []
        existing.extend(new_changes)
        learning["behavior_changes"] = existing[-30:]

    learning["last_updated"] = _now()
    return learning


def classify_asset(record, node: dict, meta: Optional[dict] = None) -> Tuple[str, str]:
    """
    Clasificación basada en inventario, contexto de red y evidencia.
    Retorna (asset_status, reason).
    """
    forced = getattr(record, "asset_status", None)
    admin_action = getattr(record, "admin_action", None)

    if admin_action == "block" or forced == STATUS_AISLADO:
        return STATUS_AISLADO, "Acción administrativa: bloqueo/aislamiento"
    if admin_action == "reject" or forced == STATUS_NO_AUTORIZADO:
        return STATUS_NO_AUTORIZADO, "Rechazado por administrador"
    if admin_action in ("approve", "corporate") or forced == STATUS_AUTORIZADO:
        return STATUS_AUTORIZADO, "Aprobado por administrador"
    if admin_action == "isolate":
        return STATUS_AISLADO, "Aislado por administrador"

    ip = node.get("ip")
    alerts = _active_alerts_for_ip(ip) if ip else []
    crit_alerts = [a for a in alerts if str(a.get("risk_level") or a.get("level", "")).lower() in ("critico", "critical", "riesgo", "high")]
    if crit_alerts:
        return STATUS_COMPROMETIDO, f"{len(crit_alerts)} alerta(s) crítica(s) activa(s) en el dispositivo"

    open_ports = node.get("open_ports") or []
    vendor = node.get("vendor") or getattr(record, "vendor", None)
    times_seen = getattr(record, "times_seen", None) or 1
    first_seen = getattr(record, "first_seen", "") or ""

    if times_seen <= 1 or str(first_seen).startswith(_today()):
        return STATUS_NUEVO, "Primer descubrimiento en inventario AIE"

    suspicious_evidence = []
    if len(open_ports) >= 6:
        suspicious_evidence.append("≥6 puertos abiertos")
    if _auth_failures_for_ip(ip or "") >= 5:
        suspicious_evidence.append("≥5 intentos de login fallidos")
    if not vendor or str(vendor).lower() in ("sin datos disponibles", "unknown", ""):
        if open_ports:
            suspicious_evidence.append("Vendor no identificado con puertos expuestos")

    if suspicious_evidence:
        return STATUS_SOSPECHOSO, "; ".join(suspicious_evidence)

    if admin_action == "ignore":
        return STATUS_PENDIENTE, "Ignorado temporalmente — sigue pendiente de aprobación"

    return STATUS_PENDIENTE, "En inventario ARP — pendiente de revisión del administrador"


def sync_asset_from_node(node: dict, meta: Optional[dict] = None, existing_map: Optional[dict] = None) -> None:
    """Persiste/actualiza inventario AIE desde nodo ARP real."""
    from database import SessionLocal, NetworkDeviceInventory
    from services.network_device_defense.device_classifier import classify_device_from_node
    from services.tenant_scope_service import get_platform_tenant_id

    platform_tid = get_platform_tenant_id()

    meta = meta or {}
    gateway = meta.get("gateway")
    ts = _now()
    mac = (node.get("mac") or "").lower()
    ip = node.get("ip")
    if not mac or not ip:
        return

    dtype = classify_device_from_node(node, gateway)
    node["device_type"] = dtype
    os_est = _os_from_node({**node, "device_type": dtype})
    segment = _network_segment(ip, meta)
    services = node.get("services") or [
        {"port": p.get("port"), "service": p.get("service") or f"TCP/{p.get('port')}"}
        for p in (node.get("open_ports") or []) if p.get("port")
    ]

    db = SessionLocal()
    try:
        if existing_map is None:
            existing_map = {
                (r.mac or "").lower(): r
                for r in db.query(NetworkDeviceInventory).filter(
                    (NetworkDeviceInventory.tenant_id == platform_tid)
                    | (NetworkDeviceInventory.tenant_id.is_(None))
                ).all()
            }
        record = existing_map.get(mac)
        hist_entry = {
            "time": ts,
            "ip": ip,
            "hostname": node.get("name"),
            "vendor": node.get("vendor"),
            "device_type": dtype,
            "response_ms": node.get("response_time_ms"),
        }

        if record:
            history = _parse_json(record.history_json, [])
            history.append(hist_entry)
            history = history[-50:]
            record.ip = ip
            record.hostname = node.get("name") or record.hostname
            record.vendor = node.get("vendor") or record.vendor
            record.device_type = dtype
            record.last_seen = ts
            record.times_seen = (record.times_seen or 0) + 1
            record.history_json = json.dumps(history, ensure_ascii=False)
            record.last_open_ports_json = json.dumps(node.get("open_ports") or [], ensure_ascii=False)
            if hasattr(record, "os_estimate") and os_est:
                record.os_estimate = os_est
            if hasattr(record, "network_segment") and segment:
                record.network_segment = segment
            if hasattr(record, "services_json"):
                record.services_json = json.dumps(services, ensure_ascii=False)
            learning = update_learning(record, node)
            if hasattr(record, "learning_json"):
                record.learning_json = json.dumps(learning, ensure_ascii=False)
            status, reason = classify_asset(record, node, meta)
            if hasattr(record, "asset_status"):
                if getattr(record, "admin_action", None) not in ("approve", "reject", "block", "isolate", "corporate", "temporary", "ignore"):
                    record.asset_status = status
                if hasattr(record, "classification_reason"):
                    record.classification_reason = reason
            trust, _ = compute_trust_score(record, node, meta)
            if hasattr(record, "trust_score"):
                record.trust_score = trust
            record.is_known = status == STATUS_AUTORIZADO
            if hasattr(record, "tenant_id") and not record.tenant_id:
                record.tenant_id = platform_tid
        else:
            record = NetworkDeviceInventory(
                mac=mac,
                ip=ip,
                tenant_id=platform_tid,
                hostname=node.get("name"),
                vendor=node.get("vendor"),
                device_type=dtype,
                first_seen=ts,
                last_seen=ts,
                times_seen=1,
                is_known=False,
                risk_level="observacion",
                history_json=json.dumps([hist_entry], ensure_ascii=False),
                last_open_ports_json=json.dumps(node.get("open_ports") or [], ensure_ascii=False),
            )
            if hasattr(NetworkDeviceInventory, "asset_status"):
                record.asset_status = STATUS_PENDIENTE
            if hasattr(NetworkDeviceInventory, "trust_score"):
                record.trust_score = 45
            if hasattr(NetworkDeviceInventory, "os_estimate"):
                record.os_estimate = os_est
            if hasattr(NetworkDeviceInventory, "network_segment"):
                record.network_segment = segment
            if hasattr(NetworkDeviceInventory, "services_json"):
                record.services_json = json.dumps(services, ensure_ascii=False)
            if hasattr(NetworkDeviceInventory, "learning_json"):
                record.learning_json = json.dumps(update_learning(record, node), ensure_ascii=False)
            if hasattr(NetworkDeviceInventory, "classification_reason"):
                record.classification_reason = "Primer descubrimiento — pendiente de aprobación"
            db.add(record)
            existing_map[mac] = record
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("AIE sync_asset_from_node: %s", exc)
    finally:
        db.close()


def enrich_node_with_aie(node: dict, record, meta: Optional[dict] = None) -> dict:
    """Enriquece nodo NDR con campos AIE para Network/Topology."""
    status, reason = classify_asset(record, node, meta) if record else (STATUS_NUEVO, "Sin registro en inventario")
    trust = 0
    factors: List[str] = []
    if record:
        trust, factors = compute_trust_score(record, node, meta)
        status = getattr(record, "asset_status", None) or status

    label = STATUS_LABELS.get(status, status.replace("_", " ").title())
    is_pending = status in (STATUS_PENDIENTE, STATUS_NUEVO)
    requires_attention = status in (STATUS_PENDIENTE, STATUS_NUEVO, STATUS_SOSPECHOSO, STATUS_COMPROMETIDO)

    learning = _parse_json(getattr(record, "learning_json", None) if record else None, {})
    hours = learning.get("connection_hours") or {}
    peak_hour = max(hours, key=hours.get) if hours else None
    services = node.get("services") or []
    if record and getattr(record, "services_json", None):
        try:
            services = json.loads(record.services_json) or services
        except Exception:
            pass

    return {
        **node,
        "asset_status": status,
        "asset_status_label": label,
        "status_display": label,
        "classification_reason": getattr(record, "classification_reason", None) if record else reason,
        "trust_score": trust,
        "trust_factors": factors,
        "trust_display": f"{trust}%",
        "is_pending_approval": is_pending,
        "requires_attention": requires_attention,
        "is_unknown": False,
        "is_known": status == STATUS_AUTORIZADO,
        "known_label": label,
        "admin_tag": getattr(record, "admin_tag", None) if record else None,
        "admin_action": getattr(record, "admin_action", None) if record else None,
        "first_seen": getattr(record, "first_seen", None) if record else node.get("first_seen"),
        "last_seen": getattr(record, "last_seen", None) if record else node.get("last_seen"),
        "times_seen": getattr(record, "times_seen", None) if record else node.get("times_seen"),
        "network_segment": getattr(record, "network_segment", None) if record else None,
        "os_estimate_short": getattr(record, "os_estimate", None) if record else node.get("os_estimate_short"),
        "services": services,
        "learning_summary": {
            "scan_count": learning.get("scan_count", 0),
            "behavior_changes": len(learning.get("behavior_changes") or []),
            "peak_hour": peak_hour,
        },
    }


def apply_admin_action(
    mac: str,
    action: str,
    user_email: Optional[str] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """Aplica acción del administrador sobre un activo."""
    from database import SessionLocal, NetworkDeviceInventory

    action = (action or "").lower().strip()
    if action not in ADMIN_ACTIONS:
        return {"status": "error", "message": f"Acción no válida: {action}"}

    db = SessionLocal()
    try:
        record = db.query(NetworkDeviceInventory).filter(
            NetworkDeviceInventory.mac == mac.lower()
        ).first()
        if not record:
            return {"status": "not_found", "message": "Dispositivo no encontrado en inventario AIE"}

        record.admin_action = action
        record.admin_action_by = user_email
        record.admin_action_at = _now()
        if notes and hasattr(record, "admin_notes"):
            record.admin_notes = notes

        if action == "approve":
            record.asset_status = STATUS_AUTORIZADO
            record.is_known = True
            record.admin_tag = None
        elif action == "corporate":
            record.asset_status = STATUS_AUTORIZADO
            record.is_known = True
            record.admin_tag = "corporativo"
        elif action == "temporary":
            record.asset_status = STATUS_AUTORIZADO
            record.is_known = True
            record.admin_tag = "temporal"
        elif action == "reject":
            record.asset_status = STATUS_NO_AUTORIZADO
            record.is_known = False
        elif action == "block":
            record.asset_status = STATUS_NO_AUTORIZADO
            record.is_known = False
        elif action == "isolate":
            record.asset_status = STATUS_AISLADO
            record.is_known = False
        elif action == "ignore":
            record.admin_tag = "ignorado"

        record.classification_reason = f"Acción administrativa: {action}"
        node = {
            "ip": record.ip,
            "mac": record.mac,
            "vendor": record.vendor,
            "open_ports": _parse_json(record.last_open_ports_json, []),
        }
        record.trust_score = compute_trust_score(record, node)[0]
        db.commit()

        try:
            from services.network_ndr_service import invalidate_ndr_cache
            invalidate_ndr_cache()
        except Exception:
            pass

        try:
            from services.evidence_center_service import record_evidence, infer_category
            cat = infer_category("asset_intelligence_engine", action)
            desc = f"Acción administrativa '{action}' sobre {record.mac} ({record.ip or 'sin IP'})"
            record_evidence(
                motor="asset_intelligence_engine",
                description=desc,
                categoria=cat,
                nivel_riesgo="medio" if action in ("approve", "corporate", "temporary") else "alto",
                nivel_confianza="Alta",
                estado="success",
                accion_ejecutada=action,
                resultado=record.asset_status,
                evidence={
                    "mac": record.mac,
                    "ip": record.ip,
                    "trust_score": record.trust_score,
                    "admin_by": user_email,
                    "notes": notes,
                },
            )
        except Exception as ev_exc:
            logger.debug("AIE evidence record: %s", ev_exc)

        try:
            from services.ai_kernel_event_engine.knowledge_adapter import get_knowledge_adapter

            admin_map = {
                "approve": "OVERRIDE_UNBLOCK",
                "corporate": "OVERRIDE_UNBLOCK",
                "temporary": "OVERRIDE_UNBLOCK",
                "isolate": "CONFIRM_ATTACK",
                "block": "CONFIRM_ATTACK",
                "reject": "CONFIRM_ATTACK",
            }
            if action in admin_map:
                get_knowledge_adapter().learn_from_feedback(
                    record.mac,
                    original_verdict=record.asset_status or "unknown",
                    admin_action=admin_map[action],
                    reason=notes or f"Acción administrativa AIE: {action}",
                )
        except Exception as learn_exc:
            logger.debug("AI kernel feedback: %s", learn_exc)

        return {
            "status": "success",
            "mac": record.mac,
            "asset_status": record.asset_status,
            "asset_status_label": STATUS_LABELS.get(record.asset_status, record.asset_status),
            "trust_score": record.trust_score,
        }
    except Exception as exc:
        db.rollback()
        logger.error("AIE apply_admin_action: %s", exc)
        return {"status": "error", "message": str(exc)}
    finally:
        db.close()


def list_inventory(limit: int = 200, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Lista inventario AIE para UI administrativa."""
    from database import SessionLocal, NetworkDeviceInventory
    from services.tenant_scope_service import get_platform_tenant_id

    platform_tid = get_platform_tenant_id()
    if tenant_id and tenant_id != platform_tid:
        return []

    db = SessionLocal()
    try:
        query = db.query(NetworkDeviceInventory).order_by(
            NetworkDeviceInventory.last_seen.desc()
        )
        query = query.filter(
            (NetworkDeviceInventory.tenant_id == platform_tid)
            | (NetworkDeviceInventory.tenant_id.is_(None))
        )
        rows = query.limit(limit).all()
        items = []
        for r in rows:
            node = {
                "ip": r.ip,
                "mac": r.mac,
                "vendor": r.vendor,
                "open_ports": _parse_json(r.last_open_ports_json, []),
            }
            status = getattr(r, "asset_status", None) or STATUS_PENDIENTE
            trust = getattr(r, "trust_score", None)
            if trust is None:
                trust = compute_trust_score(r, node)[0]
            items.append({
                "id": r.id,
                "mac": r.mac,
                "ip": r.ip,
                "hostname": r.hostname or "Sin datos disponibles",
                "vendor": r.vendor or "Sin datos disponibles",
                "device_type": r.device_type or "Otro",
                "os_estimate": getattr(r, "os_estimate", None) or "No identificable",
                "asset_status": status,
                "asset_status_label": STATUS_LABELS.get(status, status),
                "trust_score": trust,
                "risk_level": r.risk_level or "observacion",
                "first_seen": r.first_seen,
                "last_seen": r.last_seen,
                "times_seen": r.times_seen or 0,
                "network_segment": getattr(r, "network_segment", None),
                "classification_reason": getattr(r, "classification_reason", None),
                "admin_tag": getattr(r, "admin_tag", None),
                "admin_action": getattr(r, "admin_action", None),
                "open_ports_count": len(_parse_json(r.last_open_ports_json, [])),
                "services": _parse_json(getattr(r, "services_json", None), []),
            })
        return items
    finally:
        db.close()


def get_inventory_summary() -> Dict[str, Any]:
    items = list_inventory(limit=500)
    by_status: Dict[str, int] = defaultdict(int)
    for it in items:
        by_status[it.get("asset_status", STATUS_PENDIENTE)] += 1
    return {
        "total": len(items),
        "by_status": dict(by_status),
        "pending_approval": by_status.get(STATUS_PENDIENTE, 0) + by_status.get(STATUS_NUEVO, 0),
        "authorized": by_status.get(STATUS_AUTORIZADO, 0),
        "avg_trust": round(sum(i.get("trust_score", 0) for i in items) / max(len(items), 1), 1),
    }
