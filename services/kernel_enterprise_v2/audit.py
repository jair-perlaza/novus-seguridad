"""
Auditoría de acciones Kernel Enterprise V2 — append-only + defense_registry.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from utils.logger import logger

_LOCK = threading.Lock()
_AUDIT_DIR = os.path.join("data", "kernel_enterprise_v2")
_AUDIT_PATH = os.path.join(_AUDIT_DIR, "action_audit.jsonl")


def _ensure_dir() -> None:
    os.makedirs(_AUDIT_DIR, exist_ok=True)


def record_action_audit(
    *,
    action_id: str,
    user_email: Optional[str],
    user_role: Optional[str],
    reason: str,
    status: str,
    result_message: str,
    params: Optional[dict] = None,
    evidence: Optional[dict] = None,
) -> str:
    """Persiste auditoría local y notifica defense_evidence_registry cuando aplica."""
    audit_id = f"KEV2-{uuid.uuid4().hex[:12]}"
    entry = {
        "audit_id": audit_id,
        "action_id": action_id,
        "user_email": user_email or "",
        "user_role": user_role or "",
        "reason": reason or "",
        "status": status,
        "result_message": result_message,
        "params": params or {},
        "evidence": evidence or {},
        "ts": datetime.now(timezone.utc).isoformat(),
        "integrity": "append_only_jsonl",
    }
    try:
        _ensure_dir()
        with _LOCK:
            with open(_AUDIT_PATH, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.warning("KE-V2 audit write failed: %s", exc)

    try:
        from services.defense_coordinator import record_detection

        record_detection(
            motor="kernel_enterprise_v2",
            action=f"action.{action_id}",
            evidence={
                "verified": True,
                "audit_id": audit_id,
                "status": status,
                "params_keys": list((params or {}).keys()),
            },
            phase="audit",
            outcome=status,
            detail=result_message[:500],
            user_email=user_email,
            confidence="high",
        )
    except Exception as exc:
        logger.debug("KE-V2 defense audit bridge: %s", exc)

    try:
        from services.kernel_memory import kernel_memory

        kernel_memory.log_operation(
            {
                "type": "kernel_enterprise_v2_action",
                "audit_id": audit_id,
                "action_id": action_id,
                "status": status,
                "user_email": user_email,
            }
        )
    except Exception:
        pass

    return audit_id


def recent_audits(limit: int = 50) -> list:
    if not os.path.isfile(_AUDIT_PATH):
        return []
    rows = []
    try:
        with open(_AUDIT_PATH, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception as exc:
        logger.debug("KE-V2 audit read: %s", exc)
        return []
    return rows[-limit:]
