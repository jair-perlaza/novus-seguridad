"""Aislamiento de host vía Asset Intelligence (inventario real por IP/MAC)."""
from __future__ import annotations

from typing import Any, Dict, Optional


def isolate_host_by_ip(
    ip: str,
    *,
    actor: str = "swarm_defense_engine",
    reason: str = "",
) -> Dict[str, Any]:
    """Marca dispositivo del inventario AIE como aislado (STATUS_AISLADO)."""
    ip = (ip or "").strip()
    if not ip:
        return {"ok": False, "status": "insufficient_evidence", "message": "Falta IP"}
    try:
        from database import SessionLocal, NetworkDeviceInventory
        from services.asset_intelligence_engine import apply_admin_action
    except Exception as exc:
        return {"ok": False, "status": "error", "message": str(exc)[:200]}

    db = SessionLocal()
    try:
        record = (
            db.query(NetworkDeviceInventory)
            .filter(NetworkDeviceInventory.ip == ip)
            .order_by(NetworkDeviceInventory.id.desc())
            .first()
        )
        if not record or not record.mac:
            return {
                "ok": False,
                "status": "not_found",
                "message": f"IP {ip} no está en inventario AIE — no se simula aislamiento",
                "ip": ip,
            }
        mac = record.mac
    finally:
        db.close()

    result = apply_admin_action(
        mac,
        "isolate",
        user_email=actor,
        notes=reason or "Swarm Defense coordinated isolate_host",
    )
    ok = (result or {}).get("status") not in ("error", "not_found")
    return {
        "ok": bool(ok),
        "status": "executed" if ok else (result or {}).get("status") or "error",
        "ip": ip,
        "mac": mac,
        "motor": "asset_intelligence_engine",
        "details": result,
    }
