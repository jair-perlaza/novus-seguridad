#!/usr/bin/env python3
"""Sellado forense de transferencias Mesh (origen/destino/integridad)."""
from __future__ import annotations

from typing import Any, Dict, Optional

from utils.logger import logger


def seal_mesh_transfer(
    *,
    direction: str,
    peer_id: str,
    msg_id: Optional[str],
    ok: bool,
    detail: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    try:
        from services.forensic_custody_phase1 import seal_swarm_evidence, log_custody_event
        from services.swarm_defense.mesh.node_identity import resolve_node_id

        local = resolve_node_id()
        result = seal_swarm_evidence(
            node_id=local,
            action_id=f"mesh.{direction}",
            risk_level="info" if ok else "high",
            response={"ok": ok, "peer_id": peer_id, "msg_id": msg_id, **(detail or {})},
            correlation={"msg_id": msg_id, "peer_id": peer_id, "ok": ok},
            origin_event={"mesh": True, "direction": direction, "finding_id": msg_id},
            user_email="swarm_mesh",
        )
        log_custody_event(
            action=f"mesh_{direction}",
            source_id=msg_id,
            motor="swarm_mesh",
            equipment=local,
            reason=f"peer={peer_id}",
            detail={"ok": ok, **(detail or {})},
            outcome="ok" if ok else "rejected",
        )
        return {"ok": True, "seal": result}
    except Exception as exc:
        logger.debug("mesh forensic seal: %s", exc)
        try:
            from services.forensic_evidence_integrity_service import seal_evidence
            from services.swarm_defense.mesh.node_identity import resolve_node_id

            seal_evidence(
                source_id=msg_id or f"mesh-{direction}",
                source_type="swarm_mesh",
                motor="swarm_mesh",
                evidence_type=f"mesh.{direction}",
                payload={"peer_id": peer_id, "ok": ok, "local": resolve_node_id(), **(detail or {})},
                user_email="swarm_mesh",
            )
            return {"ok": True, "fallback": True}
        except Exception as exc2:
            return {"ok": False, "error": str(exc2)[:160]}
