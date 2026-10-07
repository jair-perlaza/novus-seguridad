"""
Centro de Evidencias NOVUS — persistencia unificada de detecciones y acciones reales.
Toda evidencia proviene de motores operativos; no se generan datos simulados.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger

EVIDENCE_CATEGORIES = (
    "amenaza_detectada",
    "ip_bloqueada",
    "vulnerabilidad_detectada",
    "remediacion_ejecutada",
    "dispositivo_autorizado",
    "dispositivo_bloqueado",
    "comportamiento_anomalo",
    "incidente_generado",
    "defensa_activa",
    "auditoria",
)

CATEGORY_LABELS = {
    "amenaza_detectada": "Amenaza detectada",
    "ip_bloqueada": "IP bloqueada",
    "vulnerabilidad_detectada": "Vulnerabilidad detectada",
    "remediacion_ejecutada": "Remediación ejecutada",
    "dispositivo_autorizado": "Dispositivo autorizado",
    "dispositivo_bloqueado": "Dispositivo bloqueado",
    "comportamiento_anomalo": "Comportamiento anómalo",
    "incidente_generado": "Incidente generado",
    "defensa_activa": "Defensa activa",
    "auditoria": "Auditoría",
}


def _now_parts() -> tuple[str, str, str]:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fecha, hora = ts[:10], ts[11:]
    return ts, fecha, hora


def _normalize_risk(value: Optional[str]) -> str:
    raw = (value or "medio").lower().strip()
    mapping = {
        "critico": "critico", "crítico": "critico", "critical": "critico",
        "alto": "alto", "high": "alto",
        "medio": "medio", "medium": "medio",
        "bajo": "bajo", "low": "bajo",
        "info": "bajo", "informativo": "bajo",
    }
    return mapping.get(raw, raw if raw in ("critico", "alto", "medio", "bajo") else "medio")


def infer_category(
    motor: str,
    action: str,
    *,
    phase: Optional[str] = None,
    threat_type: Optional[str] = None,
    outcome: Optional[str] = None,
) -> str:
    """Clasifica una evidencia según motor/acción — sin inventar categorías."""
    act = (action or "").lower()
    mot = (motor or "").lower()
    ph = (phase or "").lower()
    tt = (threat_type or "").lower()

    if "block" in act or "bloq" in act or mot == "auth_protection_service":
        if "ip" in act or "origin" in act or "firewall" in act or outcome == "blocked":
            return "ip_bloqueada"
    if act in ("approve", "corporate", "temporary") or "autoriz" in act:
        return "dispositivo_autorizado"
    if act in ("block", "reject", "isolate") and ("asset" in mot or mot == "asset_intelligence_engine"):
        return "dispositivo_bloqueado"
    if "remediat" in act or "remediacion" in act or mot == "remediation_orchestrator":
        return "remediacion_ejecutada"
    if "vulnerabil" in act or "vuln" in tt or mot == "vulnerability_analyst":
        return "vulnerabilidad_detectada"
    if "incident" in act or ph == "respond" or "incidente" in act:
        return "incidente_generado"
    if event_type := _behavior_event_type(act):
        return event_type
    if tt or "threat" in act or "amenaza" in act or ph == "detect":
        return "amenaza_detectada"
    if ph == "audit":
        return "auditoria"
    return "defensa_activa"


def _behavior_event_type(action: str) -> Optional[str]:
    anomalies = (
        "behavior_change", "traffic_change", "port_change",
        "ip_change", "hostname_change", "anomal",
    )
    if any(k in action for k in anomalies):
        return "comportamiento_anomalo"
    return None


def record_evidence(
    motor: str,
    description: str,
    *,
    categoria: Optional[str] = None,
    nivel_riesgo: str = "medio",
    nivel_confianza: Optional[str] = None,
    estado: str = "registrado",
    accion_ejecutada: Optional[str] = None,
    resultado: Optional[str] = None,
    source_event_id: Optional[str] = None,
    evidence: Optional[dict] = None,
    dedupe_key: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Persiste una evidencia en SQLite. Retorna el registro creado o existente (dedupe)."""
    from database import PlatformEvidence, SessionLocal
    from utils.verifiable_evidence import passes_defense_event_gate
    from services.tenant_scope_service import get_platform_tenant_id

    if not tenant_id:
        tenant_id = get_platform_tenant_id()

    ok, skip_reason = passes_defense_event_gate(evidence)
    if not ok:
        logger.debug("Evidence center omitido: %s — %s", motor, skip_reason)
        return {"status": "skipped", "reason": skip_reason}

    ts, fecha, hora = _now_parts()
    cat = categoria or "defensa_activa"
    if cat not in EVIDENCE_CATEGORIES:
        cat = "defensa_activa"

    entry_id = source_event_id or f"EVD-{uuid.uuid4().hex[:12]}"
    risk = _normalize_risk(nivel_riesgo)

    db = SessionLocal()
    try:
        if dedupe_key:
            existing = (
                db.query(PlatformEvidence)
                .filter(PlatformEvidence.source_event_id == dedupe_key)
                .first()
            )
            if existing:
                return _row_to_dict(existing)

        if source_event_id:
            dup = db.query(PlatformEvidence).filter(PlatformEvidence.id == source_event_id).first()
            if dup:
                return _row_to_dict(dup)

        row = PlatformEvidence(
            id=entry_id,
            tenant_id=tenant_id,
            fecha=fecha,
            hora=hora,
            timestamp=ts,
            motor=motor,
            categoria=cat,
            descripcion=(description or "")[:1000],
            nivel_riesgo=risk,
            nivel_confianza=nivel_confianza,
            estado=estado or "registrado",
            accion_ejecutada=accion_ejecutada,
            resultado=resultado,
            source_event_id=dedupe_key or source_event_id,
            evidence_json=json.dumps(evidence or {}, ensure_ascii=False),
            created_at=ts,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        out = _row_to_dict(row)
        try:
            from services.enterprise_data_service import record_evidence_domain
            from services.tenant_scope_service import get_platform_tenant_id

            record_evidence_domain(
                evidence_id=entry_id,
                tenant_id=tenant_id,
                evidence_type=cat,
                motor=motor,
                metadata=evidence or {},
                related_event_id=dedupe_key or source_event_id,
            )
            from services.enterprise_data_service import record_security_event_domain

            record_security_event_domain(
                event_type=cat,
                tenant_id=tenant_id,
                severity=risk,
                motor=motor,
                evidence=evidence,
                action_taken=accion_ejecutada,
                legacy_ref=entry_id,
                event_id=entry_id,
            )
        except Exception as exc:
            logger.debug("enterprise dual-write evidence: %s", exc)
        try:
            from services.forensic_evidence_integrity_service import hook_seal_platform_evidence
            hook_seal_platform_evidence(out, evidence)
        except Exception as exc:
            logger.debug("forensic seal platform: %s", exc)
        return out
    except Exception as exc:
        db.rollback()
        logger.error("evidence_center record: %s", exc)
        return {"status": "error", "error": str(exc)}
    finally:
        db.close()


def record_from_defense_event(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Puente desde defense_evidence_registry — enriquece y persiste."""
    if not entry or not entry.get("motor"):
        return None

    cat = infer_category(
        entry.get("motor", ""),
        entry.get("action", ""),
        phase=entry.get("phase"),
        threat_type=entry.get("threat_type"),
        outcome=entry.get("outcome"),
    )
    desc = entry.get("detail") or entry.get("action") or cat
    if entry.get("threat_type"):
        desc = f"{desc} [{entry['threat_type']}]"

    risk = "medio"
    tt = (entry.get("threat_type") or "").lower()
    if "crit" in tt or entry.get("outcome") == "failed":
        risk = "critico" if "crit" in tt else "alto"

    return record_evidence(
        motor=entry.get("motor", "unknown"),
        description=desc,
        categoria=cat,
        nivel_riesgo=risk,
        nivel_confianza=entry.get("confidence"),
        estado=entry.get("outcome") or "registrado",
        accion_ejecutada=entry.get("action"),
        resultado=entry.get("outcome"),
        source_event_id=entry.get("id"),
        evidence={
            "phase": entry.get("phase"),
            "finding_id": entry.get("finding_id"),
            "threat_type": entry.get("threat_type"),
            "user_email": entry.get("user_email"),
            "evidence": entry.get("evidence") or {},
        },
        dedupe_key=entry.get("id"),
    )


def list_evidence(
    limit: int = 50,
    *,
    categoria: Optional[str] = None,
    motor: Optional[str] = None,
    since: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    from database import PlatformEvidence, SessionLocal
    from services.tenant_isolation_service import sql_tenant_filter

    if not tenant_id:
        return []

    db = SessionLocal()
    try:
        q = db.query(PlatformEvidence).order_by(PlatformEvidence.timestamp.desc())
        q = sql_tenant_filter(q, PlatformEvidence, tenant_id)
        if categoria:
            q = q.filter(PlatformEvidence.categoria == categoria)
        if motor:
            q = q.filter(PlatformEvidence.motor == motor)
        if since:
            q = q.filter(PlatformEvidence.timestamp >= since)
        rows = q.limit(min(limit, 500)).all()
        from utils.verifiable_evidence import passes_defense_event_gate
        from utils.ip_validation import text_contains_documentation_ip

        out = []
        for r in rows:
            d = _row_to_dict(r)
            ev = {}
            try:
                ev = json.loads(r.evidence_json) if r.evidence_json else {}
            except Exception:
                ev = {}
            ok, _ = passes_defense_event_gate(ev.get("evidence") if isinstance(ev.get("evidence"), dict) else ev)
            if not ok or text_contains_documentation_ip(d.get("descripcion")):
                continue
            try:
                from services.v1_runtime_surface import blob_contains_lab_marker

                if blob_contains_lab_marker(d) or blob_contains_lab_marker(ev):
                    continue
            except Exception:
                pass
            out.append(_sanitize_client_row(d))
        return out
    finally:
        db.close()


def get_evidence_by_id(evidence_id: str, *, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    from database import PlatformEvidence, SessionLocal
    from services.tenant_isolation_service import tenant_ids_match

    if not tenant_id or not evidence_id:
        return None
    db = SessionLocal()
    try:
        row = db.query(PlatformEvidence).filter(PlatformEvidence.id == evidence_id).first()
        if not row or not tenant_ids_match(row.tenant_id, tenant_id):
            return None
        return _sanitize_client_row(_row_to_dict(row))
    finally:
        db.close()


def get_evidence_summary(*, tenant_id: Optional[str] = None) -> Dict[str, Any]:
    from database import PlatformEvidence, SessionLocal
    from sqlalchemy import func

    if not tenant_id:
        return {"total": 0, "by_category": {}, "by_motor": {}, "recent": []}

    db = SessionLocal()
    try:
        total = (
            db.query(func.count(PlatformEvidence.id))
            .filter(PlatformEvidence.tenant_id == tenant_id)
            .scalar()
            or 0
        )
        by_category: Dict[str, int] = {}
        by_motor: Dict[str, int] = {}
        for cat, cnt in (
            db.query(PlatformEvidence.categoria, func.count(PlatformEvidence.id))
            .filter(PlatformEvidence.tenant_id == tenant_id)
            .group_by(PlatformEvidence.categoria)
            .all()
        ):
            by_category[cat or "unknown"] = cnt
        for mot, cnt in (
            db.query(PlatformEvidence.motor, func.count(PlatformEvidence.id))
            .filter(PlatformEvidence.tenant_id == tenant_id)
            .group_by(PlatformEvidence.motor)
            .limit(20)
            .all()
        ):
            by_motor[mot or "unknown"] = cnt
        recent = list_evidence(limit=5, tenant_id=tenant_id)
        return {
            "total": total,
            "by_category": by_category,
            "by_motor": by_motor,
            "recent": recent,
        }
    finally:
        db.close()


def backfill_from_defense_registry(limit: int = 500) -> Dict[str, Any]:
    """Importa eventos históricos del registro JSONL al centro (sin duplicar)."""
    from services.defense_evidence_registry import list_recent_events
    from database import PlatformEvidence, SessionLocal

    db = SessionLocal()
    try:
        existing_ids = {
            row[0]
            for row in db.query(PlatformEvidence.id).all()
        }
        existing_sources = {
            row[0]
            for row in db.query(PlatformEvidence.source_event_id).filter(
                PlatformEvidence.source_event_id.isnot(None)
            ).all()
        }
    finally:
        db.close()

    imported = 0
    skipped = 0
    for row in list_recent_events(limit=limit):
        eid = row.get("id")
        if eid in existing_ids or eid in existing_sources:
            skipped += 1
            continue
        result = record_from_defense_event(row)
        if result and result.get("status") != "error":
            imported += 1
            if eid:
                existing_ids.add(eid)
        else:
            skipped += 1
    return {"imported": imported, "skipped": skipped}


def _sanitize_evidence_blob(obj: Any) -> Any:
    """Elimina campos técnicos internos antes de exponer al cliente."""
    sensitive = frozenset({
        "stack_trace", "traceback", "raw_excerpt", "stderr", "stdout",
        "exc_info", "tb", "file_path", "python_trace",
    })
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if k in sensitive:
                continue
            out[k] = _sanitize_evidence_blob(v)
        return out
    if isinstance(obj, list):
        return [_sanitize_evidence_blob(x) for x in obj]
    if isinstance(obj, str):
        low = obj.lower()
        if "traceback" in low or "exception:" in low or 'file "c:\\novus' in low:
            return "Detalle técnico omitido"
    return obj


def _sanitize_client_row(row: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(row)
    out["evidence"] = _sanitize_evidence_blob(out.get("evidence") or {})
    desc = out.get("descripcion") or ""
    if isinstance(desc, str) and ("exception:" in desc.lower() or "traceback" in desc.lower()):
        out["descripcion"] = "Evento registrado por motor de defensa"
    return out


def _row_to_dict(row) -> Dict[str, Any]:
    ev = {}
    if row.evidence_json:
        try:
            ev = json.loads(row.evidence_json)
        except Exception:
            ev = {}
    return {
        "id": row.id,
        "fecha": row.fecha,
        "hora": row.hora,
        "timestamp": row.timestamp,
        "motor": row.motor,
        "categoria": row.categoria,
        "categoria_label": CATEGORY_LABELS.get(row.categoria, row.categoria),
        "descripcion": row.descripcion,
        "nivel_riesgo": row.nivel_riesgo,
        "nivel_confianza": row.nivel_confianza,
        "estado": row.estado,
        "accion_ejecutada": row.accion_ejecutada,
        "resultado": row.resultado,
        "source_event_id": row.source_event_id,
        "evidence": ev,
        "created_at": row.created_at,
    }
