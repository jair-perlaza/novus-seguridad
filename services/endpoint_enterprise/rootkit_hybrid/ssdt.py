"""
T6 — SSDT: explícitamente NO implementado.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from services.endpoint_enterprise.rootkit_hybrid.limitations import LIMITATIONS


def check_ssdt_capability() -> Dict[str, Any]:
    """Nunca afirma comprobación SSDT. No marcar en auditoría como implementado."""
    ssdt_lim = next((x for x in LIMITATIONS if "SSDT" in x.get("capability", "")), None)
    return {
        "implemented": False,
        "audit_status": "NO IMPLEMENTADO",
        "checked": False,
        "reason": (ssdt_lim or {}).get("reason"),
        "enterprise_alternative": (ssdt_lim or {}).get("enterprise_alternative"),
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ring0_required": True,
    }
