"""
Bus canónico de alertas NOVUS — única fuente para Dashboard, Incidentes y API.
Solo expone alertas con evidencia verificable del motor; nunca datos simulados.
"""
from __future__ import annotations

import ast
import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from utils.host_data import format_ip_or_unavailable, get_local_ip
from utils.ip_validation import extract_ips_from_text, is_documentation_ip, text_contains_documentation_ip
from utils.logger import logger
from utils.verifiable_evidence import passes_evidence_gate

RESOLVED_STATES = frozenset({
    "resuelto",
    "resuelto-falsopositivo",
    "Resuelto-FalsoPositivo",
    "cerrado",
    "resolved",
})
TEST_SOURCES = frozenset({
    "test_harness",
    "test",
    "lab",
    "demo",
    "simulated",
    "placeholder",
    "csv_bas",
    "csv_bas_validation",
})


def _parse_maybe_dict(value: Any) -> dict:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    text = str(value).strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {"raw": parsed}
    except Exception:
        pass
    try:
        parsed = ast.literal_eval(text)
        return parsed if isinstance(parsed, dict) else {"raw": parsed}
    except Exception:
        return {"summary": text}


def _split_datetime(ts: Optional[str]) -> Tuple[str, str]:
    # Do not invent "now" when the source omitted a timestamp.
    if not ts:
        return "NOT_AVAILABLE", "NOT_AVAILABLE"
    text = str(ts).strip()
    if not text or text.upper() in ("NOT_AVAILABLE", "UNKNOWN", "N/A", "—", "-"):
        return "NOT_AVAILABLE", "NOT_AVAILABLE"
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%d/%m/%Y %H:%M:%S"):
        try:
            dt = datetime.strptime(text[:19], fmt)
            return dt.strftime("%Y-%m-%d"), dt.strftime("%H:%M:%S")
        except ValueError:
            continue
    if re.match(r"^\d{2}:\d{2}:\d{2}$", text):
        # Time-only without a verifiable date — do not invent today's date.
        return "NOT_AVAILABLE", text
    if len(text) >= 10 and re.match(r"^\d{4}-\d{2}-\d{2}", text):
        return text[:10], (text[11:19] if len(text) >= 19 else "NOT_AVAILABLE")
    return "NOT_AVAILABLE", "NOT_AVAILABLE"


def _normalize_risk(severity: Optional[str]) -> str:
    try:
        from services.platform_event_contract import normalize_severity_label

        return normalize_severity_label(severity)
    except Exception:
        if severity is None or str(severity).strip() == "":
            return "NOT_AVAILABLE"
        s = str(severity).upper()
        if any(x in s for x in ("CRIT", "CRÍT")):
            return "CRITICAL"
        if "HIGH" in s or "ALTA" in s:
            return "HIGH"
        if "MED" in s or "WARN" in s:
            return "MEDIUM"
        if "LOW" in s or "INFO" in s or "OBSERV" in s:
            return "LOW"
        return "NOT_AVAILABLE"


def _normalize_confidence(raw: Any, severity: Optional[str] = None) -> Optional[str]:
    # Confidence ≠ severity: do not invent "Alta" from HIGH severity alone.
    if raw is None:
        return None
    try:
        from services.platform_event_contract import normalize_confidence_label

        c = normalize_confidence_label(raw)
        if c == "NOT_AVAILABLE":
            return None
        return {"HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja"}.get(c, c)
    except Exception:
        if isinstance(raw, (int, float)):
            pct = int(float(raw) * 100) if float(raw) <= 1 else int(float(raw))
            return f"{pct}%"
        text = str(raw).strip()
        return text or None


def humanize_evidence_for_client(evidence: Any = None, details: Optional[dict] = None) -> Dict[str, Any]:
    """Vista legible para UI — nunca expone dict/JSON crudo al cliente."""
    items = _humanize_evidence(evidence, details)
    return {
        "evidence_items": items,
        "evidence_summary": _evidence_summary(items),
    }


def _humanize_evidence(evidence: Any, details: Optional[dict] = None) -> List[Dict[str, str]]:
    items: List[Dict[str, str]] = []
    data = details or {}
    if isinstance(evidence, dict):
        data = {**data, **evidence}
    elif evidence and not data.get("summary"):
        data["summary"] = str(evidence)

    label_map = {
        "evidence": "Evidencia",
        "verified": "Verificado",
        "ip": "Dirección IP",
        "attempts": "Intentos",
        "source": "Fuente de telemetría",
        "process": "Proceso",
        "process_name": "Proceso",
        "file": "Archivo",
        "path": "Ruta",
        "port": "Puerto",
        "message": "Mensaje",
        "command_line": "Línea de comando",
        "description": "Descripción",
        "connections": "Conexiones",
    }
    for key, label in label_map.items():
        val = data.get(key)
        if val is None or val == "":
            continue
        if key == "verified":
            val = "Sí" if val else "No"
        items.append({"label": label, "value": str(val)})

    if not items and data.get("summary"):
        items.append({"label": "Resumen", "value": str(data["summary"])[:500]})
    return items


def _evidence_summary(items: List[Dict[str, str]]) -> str:
    if not items:
        return "Sin evidencia estructurada disponible."
    parts = []
    for item in items[:4]:
        parts.append(f"{item['label']}: {item['value']}")
    return " · ".join(parts)


def _alert_fingerprint(alert: dict) -> str:
    # Prefer event_id when present (canonical contract) — avoids merging distinct events
    eid = alert.get("event_id") or (alert.get("technical_detail") or {}).get("event_id")
    if eid:
        return f"eid|{eid}"
    parts = [
        alert.get("source_channel", ""),
        alert.get("motor", ""),
        alert.get("threat_type", ""),
        alert.get("origin_ip", ""),
        alert.get("scope", ""),
        alert.get("evidence_summary", "")[:120],
    ]
    return "|".join(str(p).lower() for p in parts)


def _is_test_or_fake(alert: dict) -> bool:
    src = str(alert.get("motor") or alert.get("fuente") or "").lower()
    if any(t in src for t in TEST_SOURCES):
        return True
    if text_contains_documentation_ip(alert.get("origin_ip")):
        return True
    if text_contains_documentation_ip(alert.get("evidence_summary")):
        return True
    for item in alert.get("evidence_items") or []:
        if text_contains_documentation_ip(item.get("value")):
            return True
    return False


def _has_real_evidence(alert: dict) -> bool:
    ok, _ = passes_evidence_gate(alert)
    return ok


def _from_sqlite_alerta(row) -> Optional[dict]:
    from services.alert_reconciliation_service import RESOLVED_LEVEL

    if row.nivel == RESOLVED_LEVEL or (getattr(row, "activa", True) is False):
        return None
    estado = getattr(row, "estado", None) or "activo"
    if str(estado).lower() in RESOLVED_STATES:
        return None

    details = _parse_maybe_dict(getattr(row, "evidencia_json", None) or row.descripcion)
    ip = row.ip_afectada or details.get("ip")
    if is_documentation_ip(ip):
        return None
    if text_contains_documentation_ip(row.descripcion):
        return None

    titulo = row.titulo or "Alerta de seguridad"
    if titulo.startswith("Evento RUNTIME_") and not details.get("verified") and not details.get("evidence"):
        return None

    threat_type = details.get("threat_type") or details.get("type")
    if not threat_type:
        m = re.search(r"([A-Z_]+)\s+Threat", titulo, re.I)
        threat_type = m.group(1) if m else titulo.replace("Evento ", "")

    # Do not promote trust-store / SSL-stripping false MITM as canonical LIVE threats
    tt_l = str(threat_type or "").lower()
    evid_blob = json.dumps(details, ensure_ascii=False, default=str).lower()
    if "mitm" in tt_l or "mitm" in (titulo or "").lower():
        if (
            details.get("status") == "NOT_VERIFIABLE"
            or details.get("data_state") == "NOT_VERIFIABLE"
            or "not_verifiable" in evid_blob
            or "trust store" in evid_blob
            or (
                "ssl stripping" in evid_blob
                and "certificado desconocido" not in evid_blob
                and details.get("confidence") in (None, "", "NOT_AVAILABLE")
            )
        ):
            return None

    date_part, time_part = _split_datetime(row.fecha)
    evidence_items = _humanize_evidence(details.get("evidence") or details, details)
    motor = getattr(row, "motor", None) or details.get("source") or details.get("motor") or "security_engine"
    confidence = _normalize_confidence(
        getattr(row, "confianza", None) or details.get("confianza") or details.get("confidence"),
        row.nivel,
    )

    acciones = []
    raw_actions = getattr(row, "acciones_json", None)
    if raw_actions:
        try:
            acciones = json.loads(raw_actions) if isinstance(raw_actions, str) else list(raw_actions)
        except Exception:
            pass

    return {
        "id": f"ALT-DB-{row.id:05d}",
        "db_id": row.id,
        "event_id": details.get("event_id"),
        "correlation_id": details.get("correlation_id"),
        "detection_type": details.get("detection_type") or threat_type,
        "scope": details.get("scope") or "UNKNOWN",
        "tenant_id": getattr(row, "tenant_id", None) or details.get("tenant_id"),
        "threat_type": str(threat_type).replace("_", " ").title(),
        "status": estado if estado else "activo",
        "risk_level": _normalize_risk(row.nivel),
        "confidence": confidence,
        "origin": ip or format_ip_or_unavailable(get_local_ip()),
        "origin_ip": ip,
        "date": date_part,
        "time": time_part,
        "timestamp": row.fecha,
        "motor": motor,
        "fuente": getattr(row, "fuente", None) or "sqlite_alerta",
        "source_channel": "sqlite_alerta",
        "evidence_items": evidence_items,
        "evidence_summary": _evidence_summary(evidence_items),
        "remediation_status": getattr(row, "estado_remediacion", None) or "Pendiente",
        "auto_actions": acciones,
        "playbook_id": details.get("playbook_id"),
        "verified": bool(details.get("verified") or details.get("evidence") or evidence_items),
        "timeline": [],
        "technical_detail": details,
    }


def _from_threat_registry(entry: dict, index: int) -> Optional[dict]:
    if not entry.get("verified") and not entry.get("evidence"):
        details = entry.get("details") or {}
        if isinstance(details, dict) and not (details.get("verified") or details.get("evidence")):
            return None

    details = entry.get("details") if isinstance(entry.get("details"), dict) else {}
    evidence = entry.get("evidence") or details.get("evidence") or details
    ip = details.get("ip") if isinstance(details, dict) else None
    if is_documentation_ip(ip) or text_contains_documentation_ip(str(evidence)):
        return None
    source = str(entry.get("source") or "").lower()
    if source in TEST_SOURCES:
        return None

    ts = entry.get("time") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_part, time_part = _split_datetime(ts)
    evidence_items = _humanize_evidence(evidence, details if isinstance(details, dict) else {})
    finding_id = entry.get("finding_id") or f"RT-{entry.get('threat_type', 'TH')}-{index}"

    return {
        "id": f"ALT-RT-{finding_id}",
        "threat_type": str(entry.get("threat_type") or "Amenaza runtime").replace("_", " ").title(),
        "status": "activo",
        "risk_level": _normalize_risk(entry.get("severity")),
        "confidence": _normalize_confidence(details.get("confidence") if isinstance(details, dict) else None, entry.get("severity")),
        "origin": ip or format_ip_or_unavailable(get_local_ip()),
        "origin_ip": ip,
        "date": date_part,
        "time": time_part,
        "timestamp": ts,
        "motor": entry.get("source") or "security_engine",
        "fuente": "threat_registry",
        "source_channel": "threat_registry",
        "evidence_items": evidence_items,
        "evidence_summary": _evidence_summary(evidence_items),
        "remediation_status": "En evaluación",
        "auto_actions": [],
        "playbook_id": None,
        "verified": bool(
            entry.get("verified")
            or (isinstance(details, dict) and details.get("verified") is True)
        ),
        "timeline": [],
        "technical_detail": details if isinstance(details, dict) else {"raw": details},
    }


def _from_ndr_alert(alert: dict) -> Optional[dict]:
    ip = alert.get("ip")
    if is_documentation_ip(ip):
        return None
    evidence_text = alert.get("evidence") or alert.get("plain_explanation") or alert.get("title")
    if text_contains_documentation_ip(evidence_text):
        return None

    ts = alert.get("time") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_part, time_part = _split_datetime(ts)
    evidence_items = _humanize_evidence(evidence_text, alert)

    return {
        "id": f"ALT-{alert.get('id', 'NDR-UNK')}",
        "threat_type": alert.get("title") or "Anomalía de red",
        "status": "activo",
        "risk_level": _normalize_risk(alert.get("level")),
        "confidence": _normalize_confidence(alert.get("confidence"), alert.get("level")),
        "origin": ip or "Red local",
        "origin_ip": ip,
        "date": date_part,
        "time": time_part,
        "timestamp": ts,
        "motor": alert.get("motor") or "network_ndr_service",
        "fuente": "ndr",
        "source_channel": "ndr",
        "evidence_items": evidence_items,
        "evidence_summary": _evidence_summary(evidence_items),
        "remediation_status": "Monitoreo NDR",
        "auto_actions": [],
        "playbook_id": None,
        "verified": True,
        "timeline": [],
        "technical_detail": alert,
    }


def _from_active_defense(entry: dict) -> Optional[dict]:
    if entry.get("status") != "active":
        return None
    tt = str(entry.get("threat_type") or entry.get("category") or "").lower()
    if "brute" in tt or tt in ("auth_credentials", "auth_anomaly"):
        from services.auth_anomaly_evidence_service import auth_details_pass_gate

        raw = entry.get("evidence") or entry.get("details") or {}
        if not isinstance(raw, dict):
            return None
        ok, _ = auth_details_pass_gate(
            {**raw, "verified": True, "event_type": "brute_force", "source": raw.get("source") or "auth_access_audit"}
        )
        if not ok:
            return None
    ts = entry.get("last_seen_at") or entry.get("started_at")
    date_part, time_part = _split_datetime(ts)
    threat = str(entry.get("threat_type") or entry.get("category") or "Amenaza").replace("_", " ").title()

    evidence_items = [
        {"label": "Verificaciones", "value": str(entry.get("check_count", 1))},
        {"label": "Categoría", "value": str(entry.get("category") or "—")},
    ]

    return {
        "id": f"ALT-AD-{entry.get('finding_id', 'UNK')}",
        "threat_type": threat,
        "status": "activo",
        "risk_level": _normalize_risk(entry.get("severity")),
        "confidence": _normalize_confidence(
            entry.get("confidence") or entry.get("confianza"),
            entry.get("severity"),
        ),
        "origin": format_ip_or_unavailable(get_local_ip()),
        "origin_ip": None,
        "date": date_part,
        "time": time_part,
        "timestamp": ts if ts else "NOT_AVAILABLE",
        "motor": "active_defense_orchestrator",
        "fuente": "defensa_activa",
        "source_channel": "active_defense",
        "evidence_items": evidence_items,
        "evidence_summary": _evidence_summary(evidence_items),
        "remediation_status": "Defensa activa en curso",
        "auto_actions": entry.get("actions") or [],
        "playbook_id": None,
        "verified": True,
        "timeline": [],
        "technical_detail": entry,
        "finding_id": entry.get("finding_id"),
    }


def _merge_defense_timeline(alerts: List[dict]) -> None:
    try:
        from services.defense_evidence_registry import list_recent_events

        events = list_recent_events(limit=200)
    except Exception:
        return

    by_finding: Dict[str, List[dict]] = {}
    for ev in events:
        fid = ev.get("finding_id")
        if not fid:
            continue
        by_finding.setdefault(fid, []).append({
            "time": ev.get("timestamp"),
            "phase": ev.get("phase"),
            "action": ev.get("action"),
            "outcome": ev.get("outcome"),
            "detail": ev.get("detail"),
        })

    for alert in alerts:
        fid = alert.get("finding_id") or alert.get("id", "").replace("ALT-AD-", "")
        timeline = by_finding.get(fid) or []
        if timeline:
            alert["timeline"] = timeline[:20]


def get_canonical_alerts(
    include_resolved: bool = False,
    limit: int = 100,
    tenant_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Lista unificada de alertas verificables — fuente canónica del módulo."""
    from services.tenant_scope_service import get_platform_tenant_id

    platform_tid = get_platform_tenant_id()
    if not tenant_id:
        return []
    if tenant_id != platform_tid:
        return []

    from database import SessionLocal, Alerta
    from services.novus_security_integration import novus_security

    collected: List[dict] = []

    db = SessionLocal()
    try:
        query = db.query(Alerta).order_by(Alerta.id.desc())
        query = query.filter(Alerta.tenant_id == tenant_id)
        rows = query.limit(limit * 2).all()
        for row in rows:
            parsed = _from_sqlite_alerta(row)
            if parsed:
                collected.append(parsed)
    finally:
        db.close()

    registry = novus_security.security_engine.threat_registry or []
    for idx, entry in enumerate(reversed(registry[-50:]), start=1):
        parsed = _from_threat_registry(entry, idx)
        if parsed:
            collected.append(parsed)

    try:
        from services.network_ndr_service import build_ndr_payload_from_cache

        ndr = build_ndr_payload_from_cache()
        for alert in ndr.get("alerts") or []:
            parsed = _from_ndr_alert(alert)
            if parsed:
                collected.append(parsed)
    except Exception as exc:
        logger.debug("canonical alerts NDR: %s", exc)

    try:
        from services.active_defense_orchestrator import _load_state

        state = _load_state()
        for entry in state.get("active") or []:
            parsed = _from_active_defense(entry)
            if parsed:
                collected.append(parsed)
    except Exception as exc:
        logger.debug("canonical alerts AD: %s", exc)

    if not include_resolved:
        collected = [a for a in collected if str(a.get("status", "")).lower() not in RESOLVED_STATES]

    filtered = []
    seen = set()
    for alert in collected:
        if _is_test_or_fake(alert):
            continue
        if not _has_real_evidence(alert):
            continue
        fp = _alert_fingerprint(alert)
        if fp in seen:
            continue
        seen.add(fp)
        filtered.append(_public_alert_view(alert))

    filtered.sort(key=lambda a: a.get("timestamp") or "", reverse=True)
    _merge_defense_timeline(filtered)
    return filtered[:limit]


def _public_alert_view(alert: dict) -> dict:
    """Vista para cliente — sin JSON crudo en campos principales."""
    out = dict(alert)
    out.pop("technical_detail", None)
    out.pop("db_id", None)
    return out


def get_canonical_alert_by_id(alert_id: str) -> Optional[Dict[str, Any]]:
    internal = _get_alert_with_technical(alert_id)
    if not internal:
        return None
    if _is_test_or_fake(internal) and not _has_real_evidence(internal):
        return None
    if _is_test_or_fake(internal):
        return None
    out = _public_alert_view(internal)
    out["technical_detail"] = internal.get("technical_detail")
    out["timeline"] = internal.get("timeline") or []
    _merge_defense_timeline([out])
    return out


def _get_alert_with_technical(alert_id: str) -> Optional[dict]:
    """Busca alerta incluyendo technical_detail (uso interno API detalle)."""
    from database import SessionLocal, Alerta
    from services.novus_security_integration import novus_security

    if alert_id.startswith("ALT-DB-"):
        try:
            db_id = int(alert_id.replace("ALT-DB-", ""))
        except ValueError:
            db_id = None
        if db_id:
            db = SessionLocal()
            try:
                row = db.query(Alerta).filter(Alerta.id == db_id).first()
                if row:
                    parsed = _from_sqlite_alerta(row)
                    if parsed:
                        return parsed
            finally:
                db.close()

    for idx, entry in enumerate(reversed((novus_security.security_engine.threat_registry or [])[-50:]), start=1):
        parsed = _from_threat_registry(entry, idx)
        if parsed and parsed.get("id") == alert_id:
            return parsed

    try:
        from services.network_ndr_service import build_ndr_payload

        for alert in (build_ndr_payload(force_refresh=False).get("alerts") or []):
            parsed = _from_ndr_alert(alert)
            if parsed and parsed.get("id") == alert_id:
                return parsed
    except Exception:
        pass

    try:
        from services.active_defense_orchestrator import _load_state

        for entry in (_load_state().get("active") or []):
            parsed = _from_active_defense(entry)
            if parsed and parsed.get("id") == alert_id:
                return parsed
    except Exception:
        pass
    return None


def get_active_alerts_count(tenant_id: Optional[str] = None) -> int:
    return len(get_canonical_alerts(include_resolved=False, tenant_id=tenant_id))


def mark_alert_resolved(alert_id: str, reason: str = "evidence_cleared") -> bool:
    """Marca alerta como resuelta en origen (SQLite) — oculta del dashboard."""
    from database import SessionLocal, Alerta
    from services.alert_reconciliation_service import RESOLVED_LEVEL

    db_id = None
    if alert_id.startswith("ALT-DB-"):
        try:
            db_id = int(alert_id.replace("ALT-DB-", ""))
        except ValueError:
            pass

    db = SessionLocal()
    try:
        updated = False
        if db_id:
            row = db.query(Alerta).filter(Alerta.id == db_id).first()
            if row:
                row.nivel = RESOLVED_LEVEL
                row.estado = "resuelto"
                if hasattr(row, "activa"):
                    row.activa = False
                if hasattr(row, "estado_remediacion"):
                    row.estado_remediacion = f"Resuelto — {reason}"
                note = f"[RESUELTO: {reason}]"
                row.descripcion = f"{row.descripcion or ''}\n{note}".strip()
                updated = True
        db.commit()
        return updated
    except Exception as exc:
        logger.error("mark_alert_resolved: %s", exc)
        db.rollback()
        return False
    finally:
        db.close()


def resolve_alerts_for_finding(finding_id: str, reason: str = "defensa_activa") -> int:
    """Resuelve alertas vinculadas a un finding de defensa activa."""
    count = 0
    if mark_alert_resolved(f"ALT-AD-{finding_id}", reason):
        count += 1
    from database import SessionLocal, Alerta
    from services.alert_reconciliation_service import RESOLVED_LEVEL

    db = SessionLocal()
    try:
        for row in db.query(Alerta).order_by(Alerta.id.desc()).limit(100).all():
            if finding_id in (row.descripcion or "") or finding_id in (row.titulo or ""):
                if row.nivel != RESOLVED_LEVEL:
                    row.nivel = RESOLVED_LEVEL
                    if hasattr(row, "estado"):
                        row.estado = "resuelto"
                    if hasattr(row, "activa"):
                        row.activa = False
                    count += 1
        db.commit()
    finally:
        db.close()
    return count
