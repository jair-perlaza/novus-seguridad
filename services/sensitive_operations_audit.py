"""Auditoría append-only de operaciones sensibles (crypto, claves, admin)."""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, Optional

from utils.logger import logger

AUDIT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "sensitive_ops_audit")
AUDIT_FILE = os.path.join(AUDIT_DIR, "operations.jsonl")


def _ensure() -> None:
    os.makedirs(AUDIT_DIR, exist_ok=True)


def log_sensitive_operation(
    operation: str,
    *,
    actor: Optional[str] = None,
    outcome: str = "success",
    detail: Optional[Dict[str, Any]] = None,
    ip: Optional[str] = None,
) -> None:
    _ensure()
    row = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "operation": operation,
        "actor": actor or "system",
        "outcome": outcome,
        "ip": ip,
        "detail": detail or {},
    }
    try:
        with open(AUDIT_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.error("sensitive_ops_audit write failed: %s", exc)


def list_recent(limit: int = 50) -> list:
    _ensure()
    if not os.path.isfile(AUDIT_FILE):
        return []
    lines: list = []
    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    lines.append(json.loads(line))
    except Exception:
        return []
    return lines[-limit:]
