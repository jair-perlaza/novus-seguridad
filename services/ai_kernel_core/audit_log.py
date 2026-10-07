"""Bitácora de auditoría del Kernel Core."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

_AUDIT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data",
    "ai_kernel_core",
)
_AUDIT_FILE = os.path.join(_AUDIT_DIR, "audit.jsonl")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log_audit(action: str, details: Dict[str, Any]) -> Dict[str, Any]:
    os.makedirs(_AUDIT_DIR, exist_ok=True)
    entry = {
        "timestamp": _utc(),
        "action": action,
        "details": details,
        "executes_actions": details.get("executes_actions", False),
        "verified": details.get("verified", True),
        "invented": False,
    }
    try:
        with open(_AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass
    return entry


def list_audit(limit: int = 50) -> List[Dict[str, Any]]:
    if not os.path.exists(_AUDIT_FILE):
        return []
    rows: List[Dict[str, Any]] = []
    try:
        with open(_AUDIT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return []
    return rows[-limit:]
