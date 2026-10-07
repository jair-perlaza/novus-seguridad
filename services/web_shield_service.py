"""Persistencia, estadísticas y cuarentena — NOVUS Web Shield."""
from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import shutil
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUARANTINE_DIR = os.path.join(_PROJECT_ROOT, "data", "quarantine", "web_shield")

HIGH_RISK_EXTENSIONS = frozenset({
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".msp",
    ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".psm1",
    ".dll", ".hta", ".cpl", ".jar", ".apk",
})


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _platform_tenant() -> str:
    from services.tenant_scope_service import get_platform_tenant_id
    return get_platform_tenant_id()


def record_event(
    event_type: str,
    *,
    severity: str = "info",
    action_taken: Optional[str] = None,
    domain: Optional[str] = None,
    url: Optional[str] = None,
    risk_score: Optional[int] = None,
    evidence: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    from database import SessionLocal, WebShieldEvent

    ev = dict(evidence or {})
    ev.setdefault("source", "novus_web_shield")
    ev.setdefault("timestamp", _now())
    ev["verified"] = True

    db = SessionLocal()
    try:
        row = WebShieldEvent(
            tenant_id=_platform_tenant(),
            event_type=event_type,
            severity=severity,
            action_taken=action_taken,
            domain=domain,
            url=(url or "")[:2000] if url else None,
            risk_score=risk_score,
            timestamp=_now(),
            evidence_json=json.dumps(ev, ensure_ascii=False),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        out = _row_to_dict(row)
        event_id = row.id
    except Exception as exc:
        db.rollback()
        logger.error("web_shield record_event: %s", exc)
        return None
    finally:
        db.close()

    try:
        from services.evidence_center_service import record_evidence

        if severity in ("alto", "critico", "critical", "high") or (risk_score or 0) >= 50:
            record_evidence(
                motor="novus_web_shield",
                description=f"Web Shield: {event_type} — {domain or url or 'host'}",
                categoria="amenaza_detectada" if "phish" in event_type or "block" in event_type else "comportamiento_anomalo",
                nivel_riesgo=severity,
                accion_ejecutada=action_taken,
                source_event_id=f"WS-{event_id}",
                evidence=ev,
                dedupe_key=f"web_shield:{event_type}:{domain}:{url}:{ev.get('sha256', '')}"[:200],
            )
    except Exception as exc:
        logger.debug("web_shield evidence: %s", exc)

    return out


def _row_to_dict(row) -> Dict[str, Any]:
    ev = {}
    try:
        ev = json.loads(row.evidence_json or "{}")
    except Exception:
        pass
    return {
        "id": row.id,
        "event_type": row.event_type,
        "severity": row.severity,
        "action_taken": row.action_taken,
        "domain": row.domain,
        "url": row.url,
        "risk_score": row.risk_score,
        "timestamp": row.timestamp,
        "evidence": ev,
    }


def list_events(limit: int = 50, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
    from database import SessionLocal, WebShieldEvent

    tid = _platform_tenant()
    db = SessionLocal()
    try:
        q = db.query(WebShieldEvent).filter(WebShieldEvent.tenant_id == tid)
        if event_type:
            q = q.filter(WebShieldEvent.event_type == event_type)
        rows = q.order_by(WebShieldEvent.id.desc()).limit(limit).all()
        return [_row_to_dict(r) for r in rows]
    finally:
        db.close()


def get_stats() -> Dict[str, Any]:
    from database import SessionLocal, WebShieldEvent
    from sqlalchemy import func

    tid = _platform_tenant()
    db = SessionLocal()
    try:
        base = db.query(WebShieldEvent).filter(WebShieldEvent.tenant_id == tid)
        total = base.count()
        blocked = base.filter(WebShieldEvent.event_type.in_(
            ("url_blocked", "download_blocked", "download_quarantined")
        )).count()
        urls = base.filter(WebShieldEvent.event_type.in_(("url_analyzed", "url_blocked", "url_warned"))).count()
        downloads = base.filter(WebShieldEvent.event_type.like("download_%")).count()
        phishing = base.filter(WebShieldEvent.event_type.like("%phish%")).count()
        quarantine = base.filter(WebShieldEvent.event_type == "download_quarantined").count()
        last = db.query(func.max(WebShieldEvent.timestamp)).filter(WebShieldEvent.tenant_id == tid).scalar()
        return {
            "sites_analyzed": urls,
            "sites_blocked": base.filter(WebShieldEvent.event_type == "url_blocked").count(),
            "downloads_inspected": downloads,
            "downloads_blocked": base.filter(WebShieldEvent.event_type.in_(("download_blocked", "download_quarantined"))).count(),
            "phishing_detected": phishing,
            "files_quarantined": quarantine,
            "events_total": total,
            "last_event_at": last or "Sin datos disponibles",
        }
    finally:
        db.close()


def sha256_file(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as exc:
        logger.debug("sha256_file: %s", exc)
        return None


def inspect_download_file(path: str) -> Dict[str, Any]:
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    size = os.path.getsize(path) if os.path.isfile(path) else None
    mime, _ = mimetypes.guess_type(path)
    digest = sha256_file(path) if os.path.isfile(path) else None
    risk = 0
    reasons: List[str] = []
    if ext in HIGH_RISK_EXTENSIONS:
        risk += 55
        reasons.append(f"Extensión de alto riesgo: {ext}")
    if size is not None and size < 512 and ext in (".exe", ".dll"):
        risk += 15
        reasons.append("Archivo ejecutable muy pequeño")
    if name.count(".") > 2:
        risk += 20
        reasons.append("Doble extensión u ofuscación en nombre")
    return {
        "path": path,
        "filename": name,
        "extension": ext,
        "mime": mime or "application/octet-stream",
        "size_bytes": size,
        "sha256": digest,
        "risk_score": min(100, risk),
        "reasons": reasons,
        "inspected_at": _now(),
    }


def quarantine_file(path: str, evidence: Dict[str, Any]) -> Optional[str]:
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    if not os.path.isfile(path):
        return None
    base = os.path.basename(path)
    safe = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{base}.novus_quarantine"
    dest = os.path.join(QUARANTINE_DIR, safe)
    try:
        shutil.move(path, dest)
        meta_path = dest + ".meta.json"
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(evidence, fh, indent=2, ensure_ascii=False)
        return dest
    except Exception as exc:
        logger.error("quarantine_file: %s", exc)
        return None


def explain_incident_for_kernel(event_id: int) -> Optional[Dict[str, Any]]:
    from database import SessionLocal, WebShieldEvent

    db = SessionLocal()
    try:
        row = db.query(WebShieldEvent).filter(WebShieldEvent.id == event_id).first()
        if not row:
            return None
        ev = json.loads(row.evidence_json or "{}")
        return {
            "what": row.event_type,
            "site": row.url or row.domain,
            "evidence": ev,
            "protections": row.action_taken,
            "risk_score": row.risk_score,
            "severity": row.severity,
            "timestamp": row.timestamp,
            "recommendations": ev.get("recommendations") or [
                "Revise el Centro de Evidencias para trazabilidad completa.",
                "Mantenga listas blanca/negra actualizadas en Web Shield.",
            ],
        }
    finally:
        db.close()
