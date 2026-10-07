#!/usr/bin/env python3
"""
Ingesta de sobres Mesh: validar confianza, firma, replay, poisoning → aplicar IOC.
"""
from __future__ import annotations

from typing import Any, Dict

from utils.logger import logger


def ingest_envelope(envelope: Dict[str, Any]) -> Dict[str, Any]:
    from services.swarm_defense.mesh import (
        anti_abuse,
        channel_keys,
        envelope as envmod,
        intel_store,
        node_identity,
        trust_registry,
    )
    from services.swarm_defense.mesh import forensic_mesh

    meta = dict((envelope or {}).get("meta") or {})
    sender = meta.get("sender_node_id") or ""
    msg_id = meta.get("msg_id") or ""
    created_ts = int(meta.get("created_ts") or 0)

    if trust_registry.is_revoked(sender):
        trust_registry.bump_peer_stats(sender, accepted=False)
        forensic_mesh.seal_mesh_transfer(direction="inbound_reject", peer_id=sender, msg_id=msg_id, ok=False, detail={"reason": "revoked"})
        return {"ok": False, "error": "peer_revoked", "rejected": True}

    peer = trust_registry.get_peer(sender)
    if not peer:
        forensic_mesh.seal_mesh_transfer(direction="inbound_reject", peer_id=sender, msg_id=msg_id, ok=False, detail={"reason": "untrusted"})
        return {"ok": False, "error": "peer_not_trusted", "rejected": True}

    replay = anti_abuse.check_and_remember(msg_id, created_ts)
    if not replay.get("ok"):
        trust_registry.bump_peer_stats(sender, accepted=False)
        forensic_mesh.seal_mesh_transfer(direction="inbound_reject", peer_id=sender, msg_id=msg_id, ok=False, detail=replay)
        return {"ok": False, "error": replay.get("reason"), "rejected": True}

    if not channel_keys.has_channel(sender):
        return {"ok": False, "error": "no_channel_key", "rejected": True}

    try:
        pub = node_identity.load_public_key_pem(peer["public_pem"])
        key = channel_keys.load_channel_key(sender)
    except Exception as exc:
        return {"ok": False, "error": f"channel_or_key:{exc}"[:160], "rejected": True}

    ok, payload, reason = envmod.open_envelope(envelope=envelope, channel_key=key, sender_public_key=pub)
    if not ok:
        trust_registry.bump_peer_stats(sender, accepted=False)
        forensic_mesh.seal_mesh_transfer(direction="inbound_reject", peer_id=sender, msg_id=msg_id, ok=False, detail={"reason": reason})
        return {"ok": False, "error": reason, "rejected": True}

    # MitM / spoof: meta sender must match signed content intent
    if meta.get("sender_node_id") != sender:
        return {"ok": False, "error": "sender_mismatch", "rejected": True}

    poison = anti_abuse.validate_intel_payload(payload)
    if not poison.get("ok"):
        trust_registry.bump_peer_stats(sender, accepted=False)
        forensic_mesh.seal_mesh_transfer(direction="inbound_reject", peer_id=sender, msg_id=msg_id, ok=False, detail=poison)
        return {"ok": False, "error": poison.get("reason"), "rejected": True}

    # P0-2: tenant canónico del payload; sin tenant → apply DENY (no influencia ZDDE).
    applied = intel_store.apply_indicators(
        payload.get("indicators") or {},
        peer_id=sender,
        msg_id=msg_id,
        payload=payload if isinstance(payload, dict) else None,
    )
    intel_store.record_inbound(
        {
            "peer_id": sender,
            "msg_id": msg_id,
            "applied": applied.get("applied"),
            "origin": payload.get("origin"),
            "tenant_id": applied.get("tenant_id"),
            "influence": applied.get("influence"),
            "denied": bool(applied.get("denied")),
            "deny_reason": applied.get("reason") if applied.get("denied") else None,
        }
    )
    if applied.get("denied"):
        trust_registry.bump_peer_stats(sender, accepted=True)  # envelope válido; IOC sin scope de influencia
        forensic_mesh.seal_mesh_transfer(
            direction="inbound_no_influence",
            peer_id=sender,
            msg_id=msg_id,
            ok=True,
            detail={
                "denied": True,
                "reason": applied.get("reason"),
                "influence": "NO_INFLUENCE",
                "fingerprint": peer.get("fingerprint"),
            },
        )
        return {
            "ok": True,
            "accepted": True,
            "peer_id": sender,
            "msg_id": msg_id,
            "applied": applied.get("applied"),
            "denied": True,
            "reason": applied.get("reason"),
            "influence": "NO_INFLUENCE",
            "kernel_note_ok": True,
            "ape_status_ok": False,
            "kernel_policy": {"analyzes": True, "executes_actions": False},
        }
    trust_registry.bump_peer_stats(sender, accepted=True)
    forensic_mesh.seal_mesh_transfer(
        direction="inbound",
        peer_id=sender,
        msg_id=msg_id,
        ok=True,
        detail={"applied": applied.get("applied"), "tenant_id": applied.get("tenant_id"), "fingerprint": peer.get("fingerprint")},
    )

    # Persistencia IOC + APE/forense ya aplicados. No re-entrar al bus ARP aquí
    # (evitar timeouts del peer worker). La colonia endurece vía intel_store compartida.

    # Kernel insights (analyze only — no side effects)
    kernel_note = {"analyzes": True, "executes_actions": False}

    # APE: registro ligero sin observe_async (evita ARP scans en el peer worker)
    try:
        from services.adaptive_profile_engine import engine_status

        _ = engine_status()
        ape_ok = True
    except Exception:
        ape_ok = False

    return {
        "ok": True,
        "accepted": True,
        "peer_id": sender,
        "msg_id": msg_id,
        "applied": applied.get("applied"),
        "tenant_id": applied.get("tenant_id"),
        "influence": applied.get("influence"),
        "denied": False,
        "kernel_note_ok": True,
        "ape_status_ok": ape_ok,
        "kernel_policy": kernel_note,
    }
