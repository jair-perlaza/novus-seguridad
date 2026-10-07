"""Cuarentena de archivos del endpoint local — sin borrado automático."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from utils.logger import logger

QUARANTINE_ROOT = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "endpoint_quarantine", "vault"
)


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _sha256(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def quarantine_file(original_path: str, requested_by: Optional[str] = None) -> Dict[str, Any]:
    if not original_path or not os.path.isfile(original_path):
        return {"status": "error", "message": "Ruta de archivo no válida o inaccesible"}
    os.makedirs(QUARANTINE_ROOT, exist_ok=True)
    digest = _sha256(original_path)
    qid = f"EQ-{uuid.uuid4().hex[:12].upper()}"
    base = os.path.basename(original_path)
    dest = os.path.join(QUARANTINE_ROOT, f"{qid}_{base}")
    try:
        shutil.move(original_path, dest)
    except Exception as exc:
        logger.error("endpoint quarantine move: %s", exc)
        return {"status": "error", "message": str(exc)}
    record = {
        "id": qid,
        "original_path": original_path,
        "quarantine_path": dest,
        "sha256": digest,
        "action": "quarantine",
        "status": "quarantined",
        "requested_by": requested_by,
        "created_at": _now(),
        "evidence": {"verified": True, "operation": "move", "host": os.environ.get("COMPUTERNAME", "")},
    }
    _persist(record)
    return {"status": "success", "record": record}


def delete_file_confirmed(original_path: str, requested_by: Optional[str] = None, confirm: bool = False) -> Dict[str, Any]:
    if not confirm:
        return {"status": "error", "message": "Eliminación requiere confirm=true del administrador"}
    if not original_path or not os.path.isfile(original_path):
        return {"status": "error", "message": "Archivo no encontrado"}
    digest = _sha256(original_path)
    try:
        os.remove(original_path)
    except Exception as exc:
        return {"status": "error", "message": str(exc)}
    qid = f"ED-{uuid.uuid4().hex[:12].upper()}"
    record = {
        "id": qid,
        "original_path": original_path,
        "quarantine_path": None,
        "sha256": digest,
        "action": "delete",
        "status": "deleted",
        "requested_by": requested_by,
        "created_at": _now(),
        "evidence": {"verified": True, "operation": "remove", "admin_confirmed": True},
    }
    _persist(record)
    return {"status": "success", "record": record}


def ignore_finding(finding_ref: str, requested_by: Optional[str] = None) -> Dict[str, Any]:
    record = {
        "id": f"EI-{uuid.uuid4().hex[:10].upper()}",
        "original_path": finding_ref,
        "quarantine_path": None,
        "sha256": None,
        "action": "ignore",
        "status": "ignored",
        "requested_by": requested_by,
        "created_at": _now(),
        "evidence": {"verified": True, "finding_ref": finding_ref},
    }
    _persist(record)
    return {"status": "success", "record": record}


def _persist(record: dict) -> None:
    from database import SessionLocal, EndpointQuarantineRecord

    db = SessionLocal()
    try:
        db.add(
            EndpointQuarantineRecord(
                id=record["id"],
                original_path=record.get("original_path"),
                quarantine_path=record.get("quarantine_path"),
                sha256=record.get("sha256"),
                action=record.get("action"),
                status=record.get("status"),
                requested_by=record.get("requested_by"),
                created_at=record.get("created_at"),
                evidence_json=json.dumps(record.get("evidence") or {}, ensure_ascii=False),
            )
        )
        db.commit()
    finally:
        db.close()


def list_quarantine(limit: int = 50) -> list:
    from database import SessionLocal, EndpointQuarantineRecord

    db = SessionLocal()
    try:
        rows = db.query(EndpointQuarantineRecord).order_by(EndpointQuarantineRecord.id.desc()).limit(limit).all()
        out = []
        for r in rows:
            out.append(
                {
                    "id": r.id,
                    "original_path": r.original_path,
                    "quarantine_path": r.quarantine_path,
                    "sha256": r.sha256,
                    "action": r.action,
                    "status": r.status,
                    "requested_by": r.requested_by,
                    "created_at": r.created_at,
                }
            )
        return out
    finally:
        db.close()
