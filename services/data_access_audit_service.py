"""
Auditoría de acceso a datos sensibles — integrado con ledger forense.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from utils.logger import logger

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT_DIR = os.path.join(ROOT, "data", "data_access_audit")
AUDIT_FILE = os.path.join(AUDIT_DIR, "access.jsonl")


def _now_parts():
    now = datetime.now()
    return (
        now.strftime("%Y-%m-%d %H:%M:%S"),
        now.strftime("%Y-%m-%d"),
        now.strftime("%H:%M:%S"),
    )


def log_data_access(
    *,
    resource: str,
    operation: str,
    result: str = "success",
    user_email: Optional[str] = None,
    ip: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Registra acceso: usuario, fecha, hora, IP, recurso, operación, resultado.
    Sella evidencia forense (best-effort).
    """
    os.makedirs(AUDIT_DIR, exist_ok=True)
    ts, fecha, hora = _now_parts()
    event_id = f"DAA-{uuid.uuid4().hex[:12]}"
    row = {
        "event_id": event_id,
        "timestamp": ts,
        "event_date": fecha,
        "event_time": hora,
        "user_email": user_email,
        "ip": ip,
        "resource": resource,
        "operation": operation,
        "result": result,
        "detail": detail or {},
    }
    try:
        with open(AUDIT_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.error("data_access_audit write: %s", exc)
        return {"ok": False, "error": str(exc)[:200]}

    try:
        from services.forensic_evidence_integrity_service import seal_evidence

        seal_evidence(
            source_id=event_id,
            source_type="data_access_audit",
            motor="data_access_audit",
            evidence_type="data_access",
            payload={
                "resource": resource,
                "operation": operation,
                "result": result,
                "ip": ip,
                "detail": detail or {},
            },
            user_email=user_email,
        )
    except Exception as exc:
        logger.debug("data_access_audit forensic seal: %s", exc)

    return {"ok": True, "event_id": event_id}


def list_recent(limit: int = 50) -> list:
    if not os.path.isfile(AUDIT_FILE):
        return []
    rows = []
    try:
        with open(AUDIT_FILE, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    except Exception:
        return []
    return rows[-limit:]
